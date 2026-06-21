#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hack Scanner 引导界面 - 所有交互在此完成"""

import os, sys, json, subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')
HACK_REPORT = os.path.join(SCRIPT_DIR, 'hack_report')

MODELS = [
    ("1", "qwen",     "Qwen (通义千问)"),
    ("2", "glm",      "GLM (智谱)"),
    ("3", "moonshot", "Kimi (月之暗面)"),
    ("4", "deepseek", "DeepSeek (深度求索)"),
    ("5", "siliconflow","SiliconFlow (硅基流动)"),
    ("6", "gemini",   "Gemini (Google)"),
    ("7", "openai",   "GPT (OpenAI)"),
    ("8", "claude",   "Claude (Anthropic)"),
    ("9", "ollama",   "Ollama (本地部署，无需API Key)"),
]

ENV_MAP = {
    'qwen': 'DASHSCOPE_API_KEY', 'glm': 'ZHIPUAI_API_KEY',
    'moonshot': 'MOONSHOT_API_KEY', 'deepseek': 'DEEPSEEK_API_KEY',
    'siliconflow': 'SILICONFLOW_API_KEY', 'gemini': 'GEMINI_API_KEY',
    'openai': 'OPENAI_API_KEY', 'claude': 'ANTHROPIC_API_KEY',
}

MODEL_MAP = {
    'qwen': 'qwen-max', 'glm': 'glm-4-flash', 'moonshot': 'moonshot-v1-8k',
    'deepseek': 'deepseek-chat', 'siliconflow': 'Qwen/Qwen2.5-7B-Instruct',
    'gemini': 'gemini-2.0-flash', 'openai': 'gpt-4.1-mini',
    'claude': 'claude-sonnet-4-20250514', 'ollama': 'qwen3.6:35b',
}

def ensure_dirs():
    os.makedirs(HACK_REPORT, exist_ok=True)

def print_menu(title):
    print("\n" + "=" * 40)
    print(f"   {title}")
    print("=" * 40)

def get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    # 重新初始化 config.json
    cfg = init_config()
    save_config(cfg)
    return cfg

def init_config():
    """生成默认配置并写入文件"""
    default_cfg = {
        "scanner": {
            "timeout": 30, "max_depth": 3, "max_pages": 100,
            "concurrent": 5, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HackScanner/1.0",
            "proxy": {"enabled": False, "http": "", "https": ""}
        },
        "ai": {
            "enabled": False, "provider": "ollama", "model": "qwen3.6:35b",
            "base_url": "", "api_key": "", "temperature": 0.2, "max_tokens": 4096
        },
        "urls": {
            "check_ssl": True, "check_headers": True, "check_cors": True,
            "check_sqli": True, "check_xss": True, "check_ssrf": True,
            "check_rce": True, "check_lfi": True, "check_wwn": True,
            "check_sensitive_data": True, "enum_subdomains": True,
            "dir_busting": {"enabled": True, "wordlist": ["common.txt", "directory-list-2.3-small.txt"], "status_codes": [200, 301, 302, 403, 401, 500]}
        },
        "files": {"check_secrets": True, "check_permissions": True, "check_dependencies": True, "vuln_db": "cve-db.json"},
        "report": {"format": ["html", "json"], "output_dir": ".",
                   "severity_colors": {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d"}},
        "tools": {"sqlmap_path": "", "nmap_path": "", "nikto_path": "", "dirb_path": ""}
    }
    save_config(default_cfg)
    return default_cfg

def save_config(cfg):
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def enable_ai():
    print_menu("=== 可选的AI模型 ===")
    for num, key, name in MODELS:
        env_key = ENV_MAP.get(key)
        if env_key:
            val = os.environ.get(env_key, '')
            suffix = f" [已配置:{val[:4]}...]" if val else ""
            print(f"  [{num}] {name}{suffix}")
        else:
            print(f"  [{num}] {name} (无需API Key)")

    while True:
        choice = input("\n请选择模型编号 [1-9]: ").strip()
        matched = [m for m in MODELS if m[0] == choice]
        if matched:
            break
        print("无效选择，请输入 1-9")

    num, key, name = matched[0]
    
    api_key = ""
    env_key = ENV_MAP.get(key)
    if env_key:
        existing = os.environ.get(env_key, '')
        if existing:
            masked = '***' + existing[-4:]
            print(f"\n检测到 {env_key}: {masked}")
            use_env = input("使用环境变量? (y/n) [y]: ").strip().lower()
            if use_env != 'n':
                api_key = existing
            else:
                api_key = input(f"请输入 {env_key}: ").strip()
        else:
            api_key = input(f"请输入 {env_key}: ").strip()

    cfg = get_config()
    cfg['ai'] = {
        'enabled': True, 'provider': key,
        'model': MODEL_MAP.get(key, 'qwen3.6:35b'),
        'base_url': '', 'api_key': api_key,
        'temperature': 0.2, 'max_tokens': 4096
    }
    save_config(cfg)
    print(f"\n已选择: {name}")

def disable_ai():
    cfg = get_config()
    cfg.setdefault('ai', {})['enabled'] = False
    save_config(cfg)
    print("AI分析已禁用")

def run_scan(target, scan_type, use_ai):
    ensure_dirs()
    if scan_type == 'url':
        cmd = [sys.executable, 'hack_scanner.py', '-u', target]
    elif scan_type == 'file':
        cmd = [sys.executable, 'hack_scanner.py', '-f', target]
    else:
        cmd = [sys.executable, 'hack_scanner.py']

    if use_ai:
        cmd.append('--ai')
    print(f"\n正在执行: {' '.join(cmd)}")
    subprocess.run(cmd)

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_menu("Hack Scanner - 自动化漏洞扫描器 v2.0")
        
        # === 第一步：选择扫描类型 ===
        print("\n=== 请选择扫描类型 ===")
        print("  [1] URL 黑盒扫描（网站漏洞检测）")
        print("  [2] 文件白盒分析（本地项目源码审计）")
        
        scan_choice = input("\n请选择 [1/2]: ").strip()
        
        if scan_choice == '1':
            # URL 扫描
            target = input("\n请输入目标URL: ").strip()
            while not target:
                print("错误: URL不能为空，请重试。")
                target = input("请输入目标URL: ").strip()
        elif scan_choice == '2':
            # 文件扫描
            target = input("\n请输入本地项目路径 (文件或目录): ").strip()
            while not target:
                print("错误: 路径不能为空，请重试。")
                target = input("请输入本地项目路径: ").strip()
        else:
            print("无效选择，请重新运行。")
            input("按 Enter 继续...")
            continue
        
        # === 第二步：选择 AI 模式 ===
        print_menu("请选择分析模式")
        print("\n  [1] 仅扫描 (不做AI分析)")
        print("  [2] 启用AI分析 + 自动解读结果")
        
        mode = input("\n请选择 [1/2]: ").strip()
        
        use_ai = False
        if mode == "2":
            enable_ai()
            use_ai = True
        else:
            disable_ai()

        confirm = input(f"\n确认扫描此{'URL' if scan_choice == '1' else '文件'}? (y/n) [y]: ").strip().lower()
        if confirm != 'n':
            run_scan(target, 'url' if scan_choice == '1' else 'file', use_ai)
        
        cont = input("\n是否继续? (y/n) [y]: ").strip().lower()
        if cont == 'n':
            print("\n再见！")
            break

if __name__ == '__main__':
    main()
