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
from typing import List, Any
from datetime import datetime

# 设置UTF-8输出编码
if sys.stdout.encoding and 'gbk' in sys.stdout.encoding.lower():
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding and 'gbk' in sys.stderr.encoding.lower():
    sys.stderr.reconfigure(encoding='utf-8')
os.environ['PYTHONIOENCODING'] = 'utf-8'

# 导入模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_scanner import URLScanner, ScanResult, ReportGenerator, Severity, print_banner
from file_analyzer import FileAnalyzer, analyze_file_or_dir

# Shannon白盒增强（可选，无依赖也能运行）
try:
    from shannon_context import ContextAnalyzer, DataFlowTracer
    HAS_SHANNON = True
except ImportError:
    HAS_SHANNON = False


class HackScanner:
    """综合安全扫描器 - 统一入口"""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'hack_report')
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

    def run(self, url: str = None, file_path: str = None):
        """运行扫描"""
        print_banner()

        if not url and not file_path:
            print("❌ 请至少提供一个参数: --url 或 --file")
            sys.exit(1)

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
  • SSL/TLS证书检查
  • HTTP安全头缺失检测
  • CORS错误配置
  • 敏感信息泄露检测
  • 子域名枚举
  • 目录爆破
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

    args = parser.parse_args()

    # 处理 --both
    url_target = args.url if hasattr(args, 'url') and args.url else None
    file_target = args.file if hasattr(args, 'file') and args.file else None

    scanner = HackScanner(output_dir=args.output)
    scanner.run(url=url_target, file_path=file_target)


if __name__ == '__main__':
    main()
