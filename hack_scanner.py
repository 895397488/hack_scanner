#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hack Scanner - 自动化漏洞扫描器
============================================================
只需提供文件路径或URL，即可自动执行安全检测。

用法:
    python hack_scanner.py --url https://example.com/path?param=value
    python hack_scanner.py --file ./path/to/files
    python hack_scanner.py --both -u URL -f DIRECTORY

输出:
    report.html     可视化HTML报告
    report.json     JSON格式报告数据
"""

import os
import sys
import json
import time
import logging
import argparse
from typing import List, Any, Dict
from datetime import datetime
from urllib.parse import urlparse

# 设置UTF-8输出编码
if sys.stdout.encoding and 'gbk' in sys.stdout.encoding.lower():
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding and 'gbk' in sys.stderr.encoding.lower():
    sys.stderr.reconfigure(encoding='utf-8')
os.environ['PYTHONIOENCODING'] = 'utf-8'

# 先导入全局 CONFIG（URLScanner 依赖）
_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
with open(_config_path, 'r', encoding='utf-8') as f:
    CONFIG = json.load(f)

# 导入模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_scanner import URLScanner, ScanResult, ReportGenerator, Severity, print_banner
from file_analyzer import FileAnalyzer, analyze_file_or_dir

# AI 自动分析模块（可选）
try:
    from ai_analyzer import AIAnalyzer, ai_analyze_url
    HAS_AI = True
except ImportError:
    HAS_AI = False

# Shannon白盒增强（可选，无依赖也能运行）
try:
    from shannon_context import ContextAnalyzer, DataFlowTracer
    HAS_SHANNON = True
except ImportError:
    HAS_SHANNON = False


class HackScanner:
    """综合安全扫描器 - 统一入口"""

    def __init__(self, output_dir: str = None, proxy: Dict[str, str] = None):
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'hack_report')
        self.proxy = proxy or {}
        self.all_findings: List[Any] = []
        self.results = {
            'url_scan': None,
            'file_scan': None,
            'combined_summary': {},
            'shannon_context': None,  # Shannon白盒分析上下文
        }
        # Shannon上下文分析器（如果可用）
        self.shannon_ctx: Optional['ContextAnalyzer'] = None
        if HAS_SHANNON:
            self.shannon_ctx = ContextAnalyzer()

    def scan_url(self, url: str) -> ScanResult:
        """扫描URL"""
        print(f"\n🎯 {'='*50}")
        print(f"  URL安全扫描: {url}")
        print(f"{'='*50}\n")

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # 将代理配置注入全局 CONFIG（URLScanner 从 config.json 读取）
        if self.proxy:
            CONFIG.setdefault('scanner', {})['proxy'] = self.proxy
            print(f"\U0001f578  HackScanner 已设置代理: {self.proxy}")

        scanner = URLScanner(output_dir=self.output_dir)
        result = scanner.scan(url)

        self.results['url_scan'] = result
        for f in result.findings:
            self.all_findings.append({
                'type': 'URL扫描',
                'finding': f.to_dict() if hasattr(f, 'to_dict') else f,
            })

        return result

    def scan_files(self, file_path: str) -> List[Any]:
        """扫描文件/目录"""
        print(f"\n📁 {'='*50}")
        print(f"  文件安全分析: {file_path}")
        print(f"{'='*50}\n")

        findings = analyze_file_or_dir(file_path)
        self.results['file_scan'] = findings

        for f in findings:
            self.all_findings.append({
                'type': '文件分析',
                'finding': f.to_dict() if hasattr(f, 'to_dict') else f,
            })

        return findings

    def generate_reports(self):
        """生成最终报告 — HTML+JSON，HTML内嵌完整JSON数据"""
        os.makedirs(self.output_dir, exist_ok=True)

        html_path = os.path.join(self.output_dir, 'report.html')
        json_path = os.path.join(self.output_dir, 'report.json')

        # ---- 构建综合报告数据（结构统一） ----
        combined_data = {
            'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {},
            'url_findings': [],
            'file_findings': [],
        }

        # URL扫描结果
        if self.results['url_scan']:
            us = self.results['url_scan']
            combined_data['summary']['url_target'] = us.target_url
            combined_data['summary']['url_findings_count'] = us.finding_count
            combined_data['summary']['url_critical'] = us.critical_count
            combined_data['summary']['url_high'] = us.high_count
            combined_data['summary']['url_technologies'] = us.technologies
            combined_data['summary']['url_subdomains'] = us.subdomains[:20]
            combined_data['url_findings'] = [f.to_dict() for f in us.findings]

        # 文件扫描结果
        if self.results['file_scan']:
            file_path_display = 'N/A'
            if hasattr(self.results['file_scan'], '__iter__') and len(self.results['file_scan']) > 0:
                first = self.results['file_scan'][0]
                file_path_display = getattr(first, 'file_path', str(first))
            combined_data['summary']['file_path'] = file_path_display
            combined_data['summary']['file_findings_count'] = len(self.results['file_scan'])
            combined_data['file_findings'] = [
                f.to_dict() if hasattr(f, 'to_dict') else f for f in self.results['file_scan']
            ]
            # 语言统计
            stats = {}  
            if hasattr(self, '_file_stats'):
                stats = getattr(self, '_file_stats', {}).get('languages', {})
            combined_data['summary']['languages'] = stats

        # 综合统计
        total_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for item in self.all_findings:
            finding = item['finding']
            sev = finding.get('severity', 'info') if isinstance(finding, dict) else getattr(finding, 'severity', 'info')
            if isinstance(sev, Severity):
                sev = sev.value
            total_sev[sev] = total_sev.get(sev, 0) + 1

        risk_score = (total_sev['critical'] * 25 + total_sev['high'] * 15 +
                      total_sev['medium'] * 5 + total_sev['low'] * 1)
        combined_data['summary']['risk_level'] = (
            '☠️ CRITICAL' if total_sev['critical'] > 0 else
            '🔴 HIGH RISK' if total_sev['high'] > 0 else
            '🟡 MODERATE' if total_sev['medium'] > 0 else
            '🟢 LOW RISK'
        )
        combined_data['summary']['risk_score'] = risk_score
        combined_data['summary']['total_findings'] = len(self.all_findings)
        combined_data['summary']['severity_breakdown'] = total_sev

        # ---- 写入JSON ----
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=2)

        # ---- 写入HTML（内嵌完整JSON数据） ----
        ReportGenerator.generate_from_combined(combined_data, html_path)

        print(f"\n📊 综合统计:")
        print(f"  总漏洞数: {len(self.all_findings)}")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if total_sev.get(sev, 0) > 0:
                icon = {'critical': '☠️ ', 'high': '⚠️ ', 'medium': '🟡 ', 'low': '🔵 ', 'info': 'ℹ️ '}.get(sev, '')
                print(f"  {icon}{sev.upper()}: {total_sev[sev]}")

        print(f"\n📄 报告已保存到:")
        print(f"  HTML: {html_path}  (内含完整JSON数据，点击展开)")
        print(f"  JSON: {json_path}")
        print(f"\n{'='*60}\n")

    def _ai_scan(self, url: str = None, file_path: str = None) -> Dict:
        """AI快速模式：根据目标类型执行扫描并返回统一报告数据结构"""
        report_data = {
            'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {},
            'url_findings': [],
            'file_findings': [],
        }
        
        # === 类型判断：URL vs 文件路径 ===
        is_url = url and (url.startswith(('http://', 'https://')))
        
        if is_url:
            target = url
            print(f"\U0001f3e2 AI 快速模式 — URL扫描: {target}")
            scanner = URLScanner(output_dir=self.output_dir)
            result = scanner.scan(target)
            
            report_data['summary']['url_target'] = target
            report_data['summary']['url_findings_count'] = result.finding_count
            report_data['summary']['url_critical'] = result.critical_count
            report_data['summary']['url_high'] = result.high_count
            report_data['summary']['url_technologies'] = result.technologies
            report_data['summary']['url_subdomains'] = result.subdomains[:20]
            report_data['url_findings'] = [f.to_dict() for f in result.findings]
            
        elif file_path:
            print(f"\U0001f4c1 AI 快速模式 — 文件扫描: {file_path}")
            findings = self.scan_files(file_path)
            
            report_data['summary']['file_path'] = file_path
            report_data['summary']['file_findings_count'] = len(findings)
            report_data['file_findings'] = [
                f.to_dict() if hasattr(f, 'to_dict') else f for f in findings
            ]
        
        # 统一风险评分
        total_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        all_findings = report_data['url_findings'] + report_data['file_findings']
        for f in all_findings:
            sev = f.get('severity', 'info') if isinstance(f, dict) else getattr(f, 'severity', 'info')
            if isinstance(sev, Severity):
                sev = sev.value
            total_sev[sev] = total_sev.get(sev, 0) + 1
        
        risk_score = (total_sev['critical'] * 25 + total_sev['high'] * 15 +
                      total_sev['medium'] * 5 + total_sev['low'] * 1)
        report_data['summary']['risk_level'] = (
            '☠️ CRITICAL' if total_sev['critical'] > 0 else
            '🔴 HIGH RISK' if total_sev['high'] > 0 else
            '🟡 MODERATE' if total_sev['medium'] > 0 else
            '🟢 LOW RISK'
        )
        report_data['summary']['risk_score'] = risk_score
        report_data['summary']['total_findings'] = len(all_findings)
        report_data['summary']['severity_breakdown'] = total_sev
        
        # 写入报告
        html_path = os.path.join(self.output_dir, 'report.html')
        json_path = os.path.join(self.output_dir, 'report.json')
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        ReportGenerator.generate_from_combined(report_data, html_path)
        
        print(f"\U0001f4ca 扫描完成 ({len(all_findings)} 个发现)")
        return report_data

    def run(self, url: str = None, file_path: str = None, use_ai: bool = False) -> Any:
        """运行扫描"""
        print_banner()

        if not url and not file_path:
            print("❌ 请至少提供一个参数: --url 或 --file")
            sys.exit(1)

        # AI 快速模式（扫描+AI分析一体化）
        if use_ai and HAS_AI:
            ai_conf = CONFIG.get('ai', {})
            if not ai_conf.get('enabled'):
                print("⚠️ AI 未启用。在 config.json 中设置 ai.enabled=true")
                return
            
            print("\U0001f916 启动 AI 自动分析模式...")
            # 根据目标类型分别处理
            report_data = self._ai_scan(url, file_path)
            
            # 将报告数据传给 AI 分析器
            from ai_analyzer import AIAnalyzer
            analyzer = AIAnalyzer()
            if not analyzer.enabled:
                print("⚠️ AI 未启用。在 config.json 中设置 ai.enabled=true")
                return
            
            ai_result = analyzer.analyze(report_data)
            
            # 输出结果
            if ai_result.get('analyzed'):
                print(f"\U0001f916 AI {analyzer.display_name}/{analyzer.model} 分析完成")
                
                # --- 生成 ai_report.html 并 iframe 嵌入 report.html ---
                from ai_analyzer import _md_to_html
                ai_text = ai_result['raw_response']
                
                # 保存 AI JSON
                ai_json_path = os.path.join(self.output_dir, 'ai_report.json')
                with open(ai_json_path, 'w', encoding='utf-8') as f:
                    json.dump(ai_result, f, ensure_ascii=False, indent=2)
                print(f"\U0001f4c4 AI JSON 已保存: {ai_json_path}")
                
                # Markdown → HTML
                ai_html_content = _md_to_html(ai_text)
                
                full_ai_html = (
                    '<!DOCTYPE html><html lang="zh"><head>'
                    '<meta charset="UTF-8"><style>'
                    '*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:1.5rem;line-height:1.8;font-size:.95rem}'
                    'pre{background:#161b22;padding:1rem;border-radius:8px;color:#e6edf3;font-size:.9rem;overflow-x:auto;margin:.5rem 0}'
                    'code{background:#21262d;padding:.15rem .4rem;border-radius:4px;color:#79c0ff;font-size:.85rem}'
                    'h3{color:#e6edf3;margin-top:1.5rem;border-bottom:2px solid #30363d;padding-bottom:.5rem}.ai-title{color:#f78166!important;margin:0!important;border:none!important}hr{border:none;border-top:1px solid #21262d;margin:1rem 0}'
                    'div{margin:.3rem 0;padding:.5rem .8rem;background:#161b22;border-left:3px solid #f78166}h4{color:#79c0ff;font-weight:normal}.blockquote{border-left:3px solid #484f58;color:#8b949e;font-style:italic;padding:.8rem 1rem;margin:.5rem 0}'
                    '</style></head><body>'
                    '<h2 class="ai-title">\U0001f916 AI 自动分析报告 (' + analyzer.display_name + '/' + analyzer.model + ')</h2>' + ai_html_content + '</body></html>'
                )
                ai_html_path = os.path.join(self.output_dir, 'ai_report.html')
                with open(ai_html_path, 'w', encoding='utf-8') as f:
                    f.write(full_ai_html)
                print(f"\U0001f4c5 AI HTML 报告已保存: {ai_html_path}")
                
                # iframe 嵌入 report.html
                iframe_html = (
                    '<div style="margin:1.5rem 0;border-radius:12px;overflow:hidden;border:1px solid #30363d;">'
                    '<h3 style="color:#f78166;padding:.8rem 1.2rem;margin:0;background:#161b22;font-size:1.1rem;">\U0001f916 AI 自动分析报告 (' + analyzer.display_name + '/' + analyzer.model + ')</h3>'
                    '<iframe src="ai_report.html" style="width:100%;height:800px;border:none;background:#0d1117;"></iframe>'
                    '</div>'
                )
                
                html_path = os.path.join(self.output_dir, 'report.html')
                if os.path.exists(html_path):
                    with open(html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    
                    marker = '</div>\n        <footer>'
                    # 兼容不同缩进的 footer 前
                    if marker not in html_content:
                        marker = '</div>\n    <footer>'
                    if marker not in html_content:
                        marker = '<footer>'
                    
                    if marker in html_content:
                        html_content = html_content.replace(marker, iframe_html + '\n' + marker)
                        with open(html_path, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        print(f"\U0001f4be report.html 已更新（含iframe嵌入AI报告）")
                    else:
                        print("⚠️ 未在 report.html 中找到插入位置，AI报告已单独保存为 ai_report.html")
                
            else:
                print(f"⚠️ {ai_result.get('error', 'AI分析未执行')}")
            
            return report_data

        if url:
            self.scan_url(url)

        if file_path:
            self.scan_files(file_path)

        # 生成报告
        self.generate_reports()


def main():
    parser = argparse.ArgumentParser(
        description='🔐 Hack Scanner - 自动化漏洞扫描器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --url https://example.com/path?id=1
  %(prog)s --file ./source-code/
  %(prog)s --both -u URL -f DIR

输出报告:
  report.html      HTML格式可视化报告（浏览器打开）
  report.json      JSON格式数据（供CI/CD集成）

支持检测:
  • OWASP TOP10 (SQL注入/XSS/SSRF/LFI/RCE等)
  • w3af 整合: XXE/文件上传/反序列化/CMS指纹
  • w3af 整合: Blind Timing SQLi / URL重定向SSRF
  • w3af 整合: VCS泄露(.git/.svn)/OpenAPI发现
  • w3af 整合: HTTP方法安全(TRACE/PUT/DELETE)
  • SSL/TLS证书检查
  • HTTP安全头 + 扩展安全头缺失检测
  • CORS错误配置
  • 敏感信息泄露检测
  • 子域名枚举
  • 目录爆破 (含SPA/CDN路径)
  • 代码静态分析 (Python/JS/PHP/Java/YAML等)
  • 依赖漏洞检测
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='要扫描的URL地址')
    group.add_argument('-f', '--file', help='要分析的文件或目录路径')

    parser.add_argument('--both', action='store_true', help='同时扫描URL和文件(需要-u和-f配合)')
    parser.add_argument('-o', '--output', default=os.path.join(os.getcwd(), 'hack_report'), help='报告输出目录 (默认: ./hack_report)')
    parser.add_argument('--deep', action='store_true', help='深度扫描模式（更慢但更全面）')
    parser.add_argument('--proxy', type=str, default='', help='代理地址，例如: http://127.0.0.1:7890 或 socks5://127.0.0.1:1080')
    parser.add_argument('--ai', action='store_true', help='启用 AI 自动分析（需要 config.json 中 ai.enabled=true）')

    args = parser.parse_args()

    # 处理 --both
    url_target = args.url if hasattr(args, 'url') and args.url else None
    file_target = args.file if hasattr(args, 'file') and args.file else None

    # 合并命令行 proxy + config.json proxy
    cli_proxy = {'enabled': False}
    if args.proxy:
        # 自动转换协议前缀
        if not args.proxy.startswith(('http://', 'https://', 'socks5://')):
            args.proxy = 'http://' + args.proxy
        cli_proxy = {'enabled': True, 'http': args.proxy, 'https': args.proxy}
    elif CONFIG.get('scanner', {}).get('proxy', {}).get('enabled'):
        cli_proxy = CONFIG['scanner']['proxy']

    scanner = HackScanner(output_dir=args.output, proxy=cli_proxy)
    scanner.run(url=url_target, file_path=file_target, use_ai=args.ai)


if __name__ == '__main__':
    main()
