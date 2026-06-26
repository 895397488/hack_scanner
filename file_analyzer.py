#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Analyzer - 文件/代码静态安全分析器
支持多种编程语言的安全漏洞检测
"""

import os
import re
import json
import hashlib
import logging
import sys
import io
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

# Fix Windows GBK terminal emoji encoding crash
if sys.stdout.encoding and 'gbk' in sys.stdout.encoding.lower():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding and 'gbk' in sys.stderr.encoding.lower():
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import yaml
logging.getLogger().setLevel(logging.WARNING)


@dataclass
class FileFinding:
    severity: str
    category: str
    file_path: str
    line_number: int
    title: str
    description: str
    evidence: str
    recommendation: str
    cwe: str = ""
    confidence: str = "medium"

    def to_dict(self):
        return {
            'severity': self.severity,
            'category': self.category,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence[:300],
            'recommendation': self.recommendation,
            'cwe': self.cwe,
            'confidence': self.confidence,
        }


# ==================== 敏感文件/内容检测规则 ====================
SECRET_RULES = [
    # AWS
    ('AWS Access Key', r'AKIA[0-9A-Z]{16}', 'critical', 'CWE-798',
     '发现AWS访问密钥ID', '不要硬编码AWS凭证，使用IAM角色或环境变量'),
    # Private keys
    ('Private Key', r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----', 'critical', 'CWE-312',
     '发现私钥文件内容', '立即轮换密钥，不要在代码/版本控制中存储私钥'),
    # Generic API keys
    ('API Key', r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}', 'high', 'CWE-798',
     '发现API密钥配置', '使用环境变量或密钥管理服务'),
    # Generic password
    ('Password/Secret', r'(?:password|passwd|pwd|secret|token)\s*[:=]\s*["\']?[A-Za-z0-9_\-!@#$%^&*]{8,}', 'high', 'CWE-798',
     '发现密码/密钥明文配置', '使用环境变量或密钥管理服务'),
    # Database connection strings
    ('DB Connection String', r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', 'high', 'CWE-798',
     '发现数据库连接字符串（可能含凭证）', '使用环境变量存储连接信息'),
    # JWT secret
    ('JWT Secret', r'(?:jwt[_-]?secret|jsonwebtoken)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', 'high', 'CWE-798',
     '发现JWT密钥配置', '使用强随机密钥，不要硬编码'),
    # SSH key fingerprint
    ('SSH Fingerprint', r'SSH\.RSA\s+[A-Fa-f0-9]+', 'medium', 'CWE-312',
     '发现SSH公钥指纹', '检查是否泄露敏感主机信息'),
    # GitHub token
    ('GitHub Token', r'ghp_[A-Za-z0-9]{36}', 'critical', 'CWE-798',
     '发现GitHub Personal Access Token', '立即撤销该令牌，使用环境变量'),
    # Google API key
    ('Google API Key', r'AIzaSy[0-9a-zA-Z_-]{33}', 'high', 'CWE-798',
     '发现Google API密钥', '限制API密钥的使用范围和配额'),
    # Slack webhook
    ('Slack Webhook', r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', 'high', 'CWE-798',
     '发现Slack Webhook URL', '限制Webhook的使用范围'),
    # Telegram bot token
    ('Telegram Bot Token', r'[\d]+:[A-Za-z0-9_-]{35}', 'medium', 'CWE-798',
     '可能发现了Telegram Bot Token', '检查是否为合法配置，不要硬编码'),
    # Generic bearer/token
    ('Bearer Token', r'Bearer\s+[A-Za-z0-9_\-\.]+', 'medium', 'CWE-798',
     '发现Bearer Token配置', '不要在代码中存储Token，使用时动态获取'),
    # HSTS
    ('HSTS Header', r'strict[-_]transport[-_]security', 'info', 'CWE-319',
     '检测到HSTS相关配置', '检查max-age是否足够大（建议≥31536000）'),
    # Encryption keys
    ('Encryption Key', r'(?:encryption[_-]?key|encrypt[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', 'high', 'CWE-798',
     '发现加密密钥配置', '使用KMS或Vault管理密钥'),
    # OAuth credentials
    ('OAuth Client Secret', r'(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', 'high', 'CWE-798',
     '发现OAuth密钥配置', '使用环境变量存储OAuth凭证'),
]

# ==================== 危险函数/代码模式检测 ====================
DANGEROUS_PATTERNS = {
    # Python
    '.py': [
        ('Eval Execution', r'\beval\s*\(', 'critical', 'CWE-95',
         '发现eval()调用，可能执行任意代码', '避免使用eval()/exec()，改用安全的配置解析方式'),
        ('Exec Execution', r'\bexec\s*\(', 'critical', 'CWE-95',
         '发现exec()调用，可能执行任意代码', '避免使用eval()/exec()'),
        ('Pickle Deserialization', r'\bpickle\.(?:load|loads)\s*\(', 'critical', 'CWE-502',
         '发现pickle反序列化，可能导致远程代码执行', '使用json替代pickle处理不可信数据'),
        ('Subprocess with shell=True', r'subprocess\..*shell\s*=\s*True', 'high', 'CWE-78',
         'subprocess调用设置了shell=True', '避免shell拼接，使用参数列表直接调用'),
        ('os.system call', r'os\.system\s*\(', 'high', 'CWE-78',
         '发现os.system()调用', '使用subprocess.run()替代，避免shell注入'),
        ('SQL Query Concatenation', r'(?:cursor\.execute|execute)\s*\(.*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*?\+', 'high', 'CWE-89',
         '发现字符串拼接SQL查询', '使用参数化查询（prepared statements）'),
        ('Temporary file write', r'open\s*\(.*/tmp/', 'medium', 'CWE-377',
         '在/tmp中创建临时文件可能被替代攻击', '使用tempfile模块创建临时文件'),
        ('Hardcoded Port', r'(?:port|PORT)\s*[:=]\s*[0-9]{4,5}', 'low', 'CWE-215',
         '发现硬编码端口配置', '使用配置文件或环境变量管理端口'),
    ],
    # JavaScript/TypeScript
    '.js': [
        ('Eval Execution', r'\beval\s*\(', 'critical', 'CWE-95',
         '发现eval()调用', '避免使用eval()/Function()，改用安全替代方案'),
        ('InnerHTML XSS', r'\.innerHTML\s*=', 'high', 'CWE-79',
         '发现innerHTML赋值，可能存在XSS风险', '使用textContent或DOMPurify处理用户输入'),
        ('dangerouslySetInnerHTML', r'dangerouslySetInnerHTML', 'high', 'CWE-79',
         'React dangerouslySetInnerHTML可能被滥用', '检查传入的数据是否经过清理'),
        ('setTimeout with string', r'setTimeout\s*\(\s*["\']', 'medium', 'CWE-95',
         'setTimeout使用字符串而非函数引用', '传递函数引用而非字符串'),
    ],
    '.ts': [
        ('Eval Execution', r'\beval\s*\(', 'critical', 'CWE-95',
         '发现eval()调用', '避免使用eval()/Function()'),
        ('dangerouslySetInnerHTML', r'dangerouslySetInnerHTML', 'high', 'CWE-79',
         'React dangerouslySetInnerHTML可能被滥用', '检查传入的数据是否经过清理'),
    ],
    # PHP
    '.php': [
        ('Eval Execution', r'\beval\s*\(', 'critical', 'CWE-95',
         '发现eval()调用', '避免使用eval()/preg_replace/e修饰符'),
        ('System call', r'(?:system|passthru|exec|shell_exec|proc_open)\s*\(', 'high', 'CWE-78',
         '发现系统命令执行函数', '避免执行用户可控的命令输入'),
        ('SQL Injection', r'(?:mysql_query|mysqli_query|pg_query)\s*\(.*\.', 'high', 'CWE-89',
         '发现拼接SQL查询', '使用PDO预处理语句（prepared statements）'),
        ('Unserialize input', r'\bunserialize\s*\(', 'critical', 'CWE-502',
         '发现unserialize()，可能触发反序列化漏洞', '使用json_encode/decode替代'),
        ('PHPINFO disclosure', r'phpinfo\s*\(\s*\)', 'medium', 'CWE-200',
         '发现phpinfo()调用，泄露服务器配置', '生产环境移除或限制访问'),
        ('File include', r'(?:include|require)(?:_once)?\s*\(.*\$.*\)', 'high', 'CWE-97/434',
         '动态文件包含可能引入恶意代码', '使用白名单限制可包含的文件'),
    ],
    # Java
    '.java': [
        ('SQL Injection', r'(?:(?:Statement|Connection)\s*\w+\s*=.*;\s*.*\.executeQuery\s*\(\s*["\'].*\+)', 'high', 'CWE-89',
         '发现字符串拼接SQL查询', '使用PreparedStatement替代'),
        ('Deserialization', r'ObjectInputStream(?:\s*<[^>]+>)?\s*\(', 'critical', 'CWE-502',
         '发现反序列化代码，可能触发远程代码执行', '避免反序列化不可信数据，或使用白名单验证'),
        ('Command injection', r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(', 'high', 'CWE-78',
         '发现Runtime.exec()调用', '避免使用用户输入拼接系统命令'),
        ('Hardcoded Secret', r'(?:password|secret|apiKey)\s*=\s*["\'][^\"]{8,}', 'high', 'CWE-798',
         '发现硬编码凭证', '使用环境变量或配置文件管理凭证'),
    ],
    # YAML (Docker/Compose)
    '.yml': [
        ('Privileged container', r'privileged:\s*true', 'critical', 'CWE-250',
         'Docker容器使用了特权模式', '移除privileged:true，使用最小权限原则'),
        ('Host network mode', r'network_mode:\s*host', 'high', 'CWE-269',
         '容器使用了主机网络模式', '使用bridge或overlay网络隔离'),
        ('Volume mount /etc', r'volumes.*?:\s*.*["\']?(?:/etc|/root|/var)', 'high', 'CWE-732',
         '敏感目录被挂载到容器中', '避免挂载宿主机的敏感目录'),
    ],
    '.yaml': [
        ('Privileged container', r'privileged:\s*true', 'critical', 'CWE-250',
         'Docker容器使用了特权模式', '移除privileged:true，使用最小权限原则'),
        ('Host network mode', r'network_mode:\s*host', 'high', 'CWE-269',
         '容器使用了主机网络模式', '使用bridge或overlay网络隔离'),
    ],
    # Nginx config
    '.conf': [
        ('Directory listing enabled', r'autodir(?:list)?\s+on|autoindex\s+on', 'medium', 'CWE-538',
         '目录列表功能被启用，暴露文件结构', '关闭自动目录索引'),
        ('Server version exposed', r'server_tokens\s+on', 'low', 'CWE-200',
         'Nginx版本号暴露', '设置server_tokens off'),
    ],
    # .env files
    '.env': [
        ('Any value in env file', r'^[^#][^\s]*=[^\s]+', 'info', 'CWE-213',
         '.env文件中包含配置项（请检查是否含敏感信息）', '确保.env不在版本控制中，.gitignore排除'),
    ],
    # package.json / requirements.txt (known vulnerable deps)
}

# 已知易受攻击的依赖版本
KNOWN_VULN_DEPS = {
    'express': {'vulnerable_versions': ['<4.17.3'], 'cve': 'CVE-2022-24999', 'severity': 'high', 'title': 'Express原型污染漏洞'},
    'lodash': {'vulnerable_versions': ['<4.17.21'], 'cve': 'CVE-2021-23337', 'severity': 'critical', 'title': 'Lodash命令注入漏洞'},
    'django': {'vulnerable_versions': ['<3.2.20'], 'cve': 'CVE-2023-0471', 'severity': 'high', 'title': 'Django路径遍历漏洞'},
    'flask': {'vulnerable_versions': ['<2.2.5'], 'cve': 'CVE-2023-30861', 'severity': 'medium', 'title': 'Flask会话cookie安全问题'},
    'log4j': {'vulnerable_versions': ['>=2.0-beta9,<2.17.0'], 'cve': 'CVE-2021-44228', 'severity': 'critical', 'title': 'Log4Shell远程代码执行'},
}


class FileAnalyzer:
    """文件/目录安全分析器 — 支持 Shannon 上下文感知的白盒驱动扫描"""

    def __init__(self, scan_path: str):
        self.scan_path = os.path.abspath(scan_path)
        self.findings: List[FileFinding] = []
        # 类型推断 + XSS输出点收集（借鉴 Shannon ContextAwarePayloadGenerator）
        self._type_map = {}           # param_name → inferred type (int/string/path/url)
        self.output_points = []       # XSS output points for encoding bypass chains
        self.ssrf_params = []         # SSRF target parameters with context
        self.js_call_chains = {}      # JS function call chain AST analysis
        # === 新增: 从源码提取变量类型推断（Shannon 借鉴） ===
        self.type_map: Dict[str, str] = {}       # param_name → inferred type
        self.output_points: List[Dict] = []       # 前端输出点位置
        self.ssrf_targets: List[Dict] = []        # SSRF 目标参数
        self.stats = {
            'files_scanned': 0,
            'directories_scanned': 0,
            'file_types': {},
            'languages': {},
            'total_secrets': 0,
            'total_dangerous': 0,
        }

    def analyze(self) -> List[FileFinding]:
        if os.path.isfile(self.scan_path):
            self._analyze_file(self.scan_path)
        elif os.path.isdir(self.scan_path):
            for root, dirs, files in os.walk(self.scan_path):
                self.stats['directories_scanned'] += 1
                # 跳过某些目录
                skip_dirs = ['.git', 'hack_report', '.svn', 'node_modules', '__pycache__', 'venv', '.venv', 'env']
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    self._analyze_file(fpath)

        # === 新增: 分析后执行类型推断和数据流收集 ===
        self._infer_types_from_analysis()
        self._collect_output_points()

        return sorted(self.findings, key=lambda f: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(f.severity, 5),
            -f.line_number
        ))

    def _analyze_file(self, filepath: str):
        self.stats['files_scanned'] += 1

        # 统计文件类型
        ext = os.path.splitext(filepath)[1].lower()
        self.stats['file_types'][ext or '(无扩展名)'] = self.stats['file_types'].get(ext or '(无扩展名)', 0) + 1

        # 检测文件名风险
        basename = os.path.basename(filepath).lower()
        risk_files = ['.env', '.git/config', 'id_rsa', 'id_dsa', 'known_hosts',
                       'shadow', 'passwd', '.htpasswd', 'web.config']
        for rf in risk_files:
            if basename == rf or filepath.endswith(rf):
                self.findings.append(FileFinding(
                    severity='high', category='文件名风险', file_path=filepath, line_number=0,
                    title=f'发现敏感文件: {basename}',
                    description=f'{basename} 是常见的敏感配置文件/密钥文件，不应在版本控制或公开目录中',
                    evidence='', recommendation=f'将此文件加入.gitignore并从仓库历史中移除', cwe='CWE-732'
                ))

        # 检查文件权限
        try:
            mode = oct(os.stat(filepath).st_mode)[-3:]
            if filepath.endswith(('.py', '.js', '.php', '.sh', '.conf', '.env')) and mode in ('644', '755'):
                self.findings.append(FileFinding(
                    severity='medium', category='文件权限', file_path=filepath, line_number=0,
                    title=f'敏感文件权限过宽: {mode}',
                    description=f'{basename} 的权限为 {mode}，可能被非授权用户读取',
                    evidence=f'chmod {mode}', recommendation='设置更严格的权限 (如 600 或 400)', cwe='CWE-732'
                ))
        except OSError:
            pass

        # 跳过二进制文件和大文件 (>1MB)
        try:
            fsize = os.path.getsize(filepath)
            if fsize > 1_000_000:
                return
        except OSError:
            return

        # 尝试读取文件内容
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except (IOError, PermissionError):
            return

        # === 判断文件类型，跳过规则定义文件自身扫描造成的误报 ===
        _is_rule_file = os.path.basename(filepath).lower() in (
            'file_analyzer.py', 'url_scanner.py', 'shannon_context.py',
            'hack_scanner.py',
        )

        # 1. 敏感信息检测
        for name, pattern, severity, cwe, desc, rec in SECRET_RULES:
            try:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # 规则定义文件的描述文本自引用 → 跳过
                        if _is_rule_file and ('发现' in line or '检测到' in line or '可能' in line) and not any(kw in line for kw in ['AKIA', '-----BEGIN', 'hooks.slack.com', '://', '\\u003c', '@']):
                            continue
                        self.stats['total_secrets'] += 1
                        self.findings.append(FileFinding(
                            severity=severity, category='敏感信息泄露', file_path=filepath,
                            line_number=i, title=f'发现{name}',
                            description=desc, evidence=line.strip()[:200], recommendation=rec,
                            cwe=cwe, confidence='high' if severity in ('critical', 'high') else 'medium'
                        ))
            except re.error:
                pass

        # 2. 危险代码模式检测
        ext = os.path.splitext(filepath)[1].lower()
        patterns = DANGEROUS_PATTERNS.get(ext, [])

        # Python额外检测：也检查.pyw,.pyx等
        if not patterns and '.py' in ext:
            patterns = DANGEROUS_PATTERNS.get('.py', [])

        for name, pattern, severity, cwe, desc, rec in patterns:
            try:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        # 规则定义文件自身扫描 → 跳过描述文本行
                        if _is_rule_file and ('发现' in line or '检测到' in line or '可能' in line or '不要' in line or '避免' in line or '使用' in line):
                            continue
                        self.stats['total_dangerous'] += 1
                        self.findings.append(FileFinding(
                            severity=severity, category='危险代码模式', file_path=filepath,
                            line_number=i, title=f'发现{name}',
                            description=desc, evidence=line.strip()[:200], recommendation=rec,
                            cwe=cwe, confidence='high' if severity == 'critical' else 'medium'
                        ))
            except re.error:
                pass

        # 3. package.json / requirements.txt 依赖安全检查
        self._check_deps(filepath, lines)

    def _infer_types_from_analysis(self):
        """从源码分析中收集变量类型信息，为动态 payload 生成提供线索（借鉴 Shannon）"""
        if not hasattr(self, '_type_map'):
            self.type_map = {}
        else:
            return  # already done
        
        ext_to_lang = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.jsx': 'javascript',
            '.tsx': 'typescript', '.php': 'php', '.java': 'java', '.go': 'go',
            '.rb': 'ruby', '.vue': 'vue', '.html': 'html',
        }
        
        # 重新扫描所有文件（收集变量类型 + XSS输出点 + SSRF目标）
        if os.path.isfile(self.scan_path):
            paths_to_scan = [self.scan_path]
        else:
            paths_to_scan = []
            for root, dirs, files in os.walk(self.scan_path):
                skip_dirs = ['.git', 'hack_report', '.svn', 'node_modules', '__pycache__', 'venv', '.venv', 'env']
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                paths_to_scan.extend(os.path.join(root, f) for f in files)

        for filepath in paths_to_scan:
            ext = os.path.splitext(filepath)[1].lower()
            lang = ext_to_lang.get(ext, '')
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except (IOError, PermissionError):
                continue

            basename = os.path.basename(filepath).lower()

            # --- 变量类型推断（借鉴 Shannon ContextAwarePayloadGenerator） ---
            if lang == 'php':
                # $_GET/$_POST['id'] → string|numeric|filetype
                for m in re.finditer(r'\$_(GET|POST|REQUEST)\["([^"]+)"\]', content):
                    var_name = m.group(2)
                    var_type = 'string'
                    # 通过变量名推断
                    if any(kw in var_name.lower() for kw in ['id', 'page', 'num', 'count', 'limit', 'offset']):
                        var_type = 'int'
                    if any(kw in var_name.lower() for kw in ['file', 'path', 'dir', 'folder']):
                        var_type = 'path'
                    if any(kw in var_name.lower() for kw in ['url', 'uri', 'link', 'redirect', 'dest', 'next']):
                        var_type = 'url'
                    self.type_map[var_name] = var_type
            
            elif lang in ('python',):
                # request.args['id'], request.form['name'] 等
                for m in re.finditer(r'request\.(args|form|values)\["([^"]+)"\]', content):
                    var_name = m.group(2)
                    param_source = m.group(1)
                    var_type = 'string'
                    if any(kw in var_name.lower() for kw in ['id', 'page', 'num']):
                        var_type = 'int'
                    self.type_map[var_name] = var_type
                
                # Flask route 中的 <id:int> 或 <name:string>
                for m in re.finditer(r'@app\.route\s*\([^)]*<([a-zA-Z_][a-zA-Z0-9_]*):(.+?)>', content):
                    var_name = m.group(1)
                    var_type = m.group(2)  # int, string, float, path, uuid
                    self.type_map[var_name] = var_type
            
            elif lang in ('javascript', 'typescript'):
                # req.params['id'], req.query.name, req.body.email
                for m in re.finditer(r'req\.(params|query|body)\["([^"]+)"\]', content):
                    var_name = m.group(2)
                    param_source = m.group(1)
                    var_type = 'string'
                    if any(kw in var_name.lower() for kw in ['id', 'page', 'num']):
                        var_type = 'int'
                    self.type_map[var_name] = var_type
                
                # Express route: app.get('/user/:id', ...)  
                for m in re.finditer(r'(?:get|post|put|delete)\s*\([^)]*["\'](?:[^"\']*?/)?:(\w+)', content):
                    var_name = m.group(1)
                    self.type_map[var_name] = 'path'
            
            elif lang == 'java':
                # @PathVariable Long id, @RequestParam String name
                for m in re.finditer(r'@(?:PathVariable|RequestParam)\s*\(?.*?"([^"]+)"', content):
                    var_name = m.group(1)
                    self.type_map[var_name] = 'string'
            
            # --- XSS 输出点收集（借鉴 Shannon innerHTML/eval tracking） ---
            if lang == 'javascript':
                for i, line in enumerate(lines, 1):
                    if re.search(r'\.innerHTML\s*=', line):
                        var_match = re.search(r'(\w+)\.innerHTML', line)
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'innerhtml', 'var': var_match.group(1) if var_match else ''})
                    if re.search(r'\.outerHTML\s*=', line):
                        var_match = re.search(r'(\w+)\.outerHTML', line)
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'outerhtml', 'var': var_match.group(1) if var_match else ''})
                    if re.search(r'document\.write\s*\(', line):
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'document_write'})
                    if re.search(r'dangerouslySetInnerHTML', line):
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'dangerous_innerhtml'})
                    if re.search(r'eval\s*\(.*(?:req|params|location)', line):
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'eval_user_input'})
            
            elif lang == 'php':
                for i, line in enumerate(lines, 1):
                    if re.search(r'\{?\$[^}]*output', line) or re.search(r'echo\s+.*(?:\$_|\$GET)', line):
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'php_echo'})
            
            elif lang == 'python':
                for i, line in enumerate(lines, 1):
                    if re.search(r'render.*template', line) or re.search(r'render_template\(', line):
                        self.output_points.append({'file': filepath, 'line': i, 'type': 'jinja_render'})
            
            # --- SSRF 目标收集（文件中发现的可配置 URL/URL参数） ---
            if lang == 'python':
                for i, line in enumerate(lines, 1):
                    if re.search(r'requests\.(get|post|put|delete|patch)\s*\(.*(?:url|param)', line):
                        self.ssrf_targets.append({'file': filepath, 'line': i, 'type': 'requests_call'})
            
            elif lang == 'javascript':
                for i, line in enumerate(lines, 1):
                    if re.search(r'fetch\s*\(.*(?:req|param|url)', line):
                        self.ssrf_targets.append({'file': filepath, 'line': i, 'type': 'fetch_call'})

    def _collect_output_points(self):
        """从 XSS 输出点收集数据，返回可用于编码绕过链分析的信息"""
        pass  # output_points already collected in _infer_types_from_analysis

    def _check_deps(self, filepath: str, lines: list):
        basename = os.path.basename(filepath).lower()
        content = '\n'.join(lines)

        if basename == 'package.json':
            for name, info in KNOWN_VULN_DEPS.items():
                pattern = f'"{name}"'
                if pattern in content:
                    self.findings.append(FileFinding(
                        severity=info['severity'], category='依赖漏洞', file_path=filepath, line_number=0,
                        title=info['title'], description=f'项目使用 {name}，可能存在 {info["cve"]} 漏洞',
                        evidence=f'发现依赖: {name}', recommendation=f'升级到最新版本或使用安全替代方案',
                        cwe='CWE-1104'
                    ))

        if basename in ('requirements.txt', 'package-lock.json', 'Pipfile', 'Gemfile'):
            for name, info in KNOWN_VULN_DEPS.items():
                pattern = f'{name}==' if name == 'log4j' else f'^{name}[>=<!=]?'
                try:
                    if re.search(pattern, content, re.MULTILINE):
                        self.findings.append(FileFinding(
                            severity=info['severity'], category='依赖漏洞', file_path=filepath, line_number=0,
                            title=info['title'], description=f'项目使用 {name}，可能存在已知漏洞',
                            evidence=f'发现依赖: {name}', recommendation=f'升级到最新版本', cwe='CWE-1104'
                        ))
                except re.error:
                    pass

    # ==================== 优化1: SQLi动态Payload生成（借鉴Shannon ContextAwarePayloadGenerator） ====================

    def generate_dynamic_sqli_payloads(self) -> List[Dict[str, Any]]:
        """
        根据文件分析中推断的变量类型，动态生成针对性SQLi payload。
        - $_GET['id']（名称含 id/page/num → int型）→ UNION SLEEP benchmark
        - $_GET['username']（string型）→ OR tautology、认证绕过
        - $_GET['file']（path型）→ 路径遍历/LFI
        返回: [{payload, description, var_name, var_type}]
        """
        payloads = []
        if not self._type_map:
            return payloads

        for var_name, var_type in self._type_map.items():
            inferred_type = var_type or self._infer_var_type(var_name)

            if inferred_type == 'int':
                payloads.extend([
                    {'payload': f"1 OR 1=1", 'description': f'数字型注入-tautology (参数: {var_name})'},
                    {'payload': f'-1 UNION SELECT NULL--', 'description': f'UNION联合注入-null列数探测 ({var_name})'},
                    {'payload': f'-1 UNION SELECT 1,2,3--', 'description': f'UNION数值列探测 ({var_name})'},
                    {'payload': f"1; DROP TABLE users--", 'description': f'DDL注入-表删除 ({var_name})'},
                    {'payload': f"1 AND SLEEP(5)--", 'description': f'时间盲注 (参数: {var_name})'},
                    {'payload': "1 AND benchmark(10000000,SHA1('test'))--", 'description': f'MySQL耗时注入 ({var_name})'},
                ])
            elif inferred_type == 'string':
                payloads.extend([
                    {"payload": "' OR '1'='1", 'description': f'字符串型OR注入 (参数: {var_name})'},
                    {"payload": f"admin'--", 'description': f'用户名绕过测试 (参数: {var_name})'},
                    {"payload": "' OR ''='", 'description': f'空字符串注入 (参数: {var_name})'},
                    {"payload": "\\'\nOR '1'='1--", 'description': f'换行符/编码绕过 (参数: {var_name})'},
                    {"payload": "admin%27%20OR%20%271%27=%271--", 'description': f'URL编码注入变体 ({var_name})'},
                ])
            elif inferred_type == 'path':
                payloads.extend([
                    {'payload': '../../../../etc/passwd', 'description': f'路径遍历-Unix (参数: {var_name})'},
                    {'payload': '..\\..\\..\\..\\windows\\system.ini', 'description': f'路径遍历-Windows (参数: {var_name})'},
                    {'payload': '....//....//etc/passwd', 'description': f'分隔符混淆绕过 (参数: {var_name})'},
                ])
            elif inferred_type == 'url':
                payloads.extend([
                    {'payload': 'http://127.0.0.1/admin', 'description': f'SSRF-内网探测 (参数: {var_name})'},
                    {'payload': 'file:///etc/passwd', 'description': f'file协议注入 (参数: {var_name})'},
                    {'payload': 'gopher://127.0.0.1:6379/', 'description': f'gopher协议SSRF (参数: {var_name})'},
                ])

        return payloads

    def _infer_var_type(self, var_name: str) -> str:
        """根据变量名推断类型（当文件分析无法确定时）"""
        name_lower = var_name.lower()
        if any(kw in name_lower for kw in ['id', 'uid', 'user_id', 'page', 'offset', 'limit', 'num', 'count']):
            return 'int'
        if any(kw in name_lower for kw in ['file', 'path', 'dir', 'folder']):
            return 'path'
        if any(kw in name_lower for kw in ['url', 'uri', 'link', 'redirect', 'dest', 'next', 'goto']):
            return 'url'
        return 'string'

    def get_summary(self) -> Dict[str, Any]:
        # 检测编程语言
        ext_to_lang = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'JSX',
            '.tsx': 'TSX', '.php': 'PHP', '.java': 'Java', '.go': 'Go', '.rs': 'Rust',
            '.rb': 'Ruby', '.c': 'C', '.cpp': 'C++', '.cs': 'C#', '.vue': 'Vue.js',
            '.yml': 'YAML', '.yaml': 'YAML', '.html': 'HTML', '.css': 'CSS',
            '.json': 'JSON', '.xml': 'XML', '.sql': 'SQL', '.sh': 'Shell', '.conf': 'Config',
        }
        languages = {}
        for ext in self.stats['file_types']:
            lang = ext_to_lang.get(ext, ext)
            languages[lang] = languages.get(lang, 0) + self.stats['file_types'][ext]

        return {
            **self.stats,
            'languages': languages,
            'scan_path': self.scan_path,
            'risk_score': min(100, self.stats['total_secrets'] * 15 + self.stats['total_dangerous'] * 10),
        }


def analyze_file_or_dir(scan_path: str) -> List[FileFinding]:
    """分析文件或目录"""
    path = os.path.abspath(scan_path)

    if not os.path.exists(path):
        print(f"❌ 路径不存在: {path}")
        return []

    print(f"\n{'='*60}")
    print(f"📁 分析目标: {path}")
    print(f"   类型: {'文件' if os.path.isfile(path) else '目录'}")
    print('='*60)

    analyzer = FileAnalyzer(path)
    findings = analyzer.analyze()
    summary = analyzer.get_summary()

    # 打印统计信息
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    print(f"\n📊 分析结果:")
    print(f"  扫描文件数:     {summary['files_scanned']}")
    print(f"  扫描目录数:     {summary['directories_scanned']}")
    print(f"  编程语言:       {', '.join(f'{k}: {v}个文件' for k, v in summary['languages'].items()) if summary['languages'] else '未知'}")
    print(f"\n🐛 发现漏洞:")
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = sev_counts.get(sev, 0)
        icon = {'critical': '☠️ ', 'high': '⚠️ ', 'medium': '🟡 ', 'low': '🔵 ', 'info': 'ℹ️ '}.get(sev, '')
        if count:
            print(f"  {icon}{sev.upper()}: {count}")

    # 打印详细发现
    for f in findings[:30]:  # 最多显示30条
        icon = {'critical': '☠️', 'high': '⚠️', 'medium': '🟡', 'low': '🔵', 'info': 'ℹ️'}.get(f.severity, '❓')
        line_str = f":{f.line_number}" if f.line_number else ""
        print(f"\n  [{icon}] {f.title}")
        print(f"      文件: {os.path.basename(f.file_path)}{line_str}")
        print(f"      描述: {f.description[:80]}")

    return findings


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='文件/代码安全分析器')
    parser.add_argument('path', help='要分析的文件或目录路径')
    args = parser.parse_args()

    results = analyze_file_or_dir(args.path)
    if results:
        print(f"\n{'='*60}")
        print(f"详细分析报告: 请使用 url_scanner.py --file {args.path} -o ./report")
