#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hack Scanner 初始化向导
=======================
交互式配置 AI、代理、扫描参数，自动写入 config.json。

用法:
    python init.py           # 交互模式
    python init.py --auto    # 自动使用默认值（不交互）
"""

import os
import sys
import json
import platform

# ====== Windows cmd UTF-8 输出修复 ======
if sys.platform == 'win32':
    import codecs
    if not hasattr(sys.stdout, '_utf8'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')

# ==================== AI Provider 矩阵 ====================
AI_PROVIDERS = [
    # ── 国产商业 ──
    ("qwen",   "通义千问 Qwen (DashScope)",    "https://dashscope.aliyuncs.com/compatible-mode/v1",  "DASHSCOPE_API_KEY", "qwen-max"),
    ("glm",    "智谱 GLM (ZhipuAI)",          "https://open.bigmodel.cn/api/paas/v4/chat/completions", "ZHIPUAI_API_KEY",   "glm-4-flash"),
    ("moonshot","月之暗面 Kimi (Moonshot)",    "https://api.moonshot.cn/v1/chat/completions",  "MOONSHOT_API_KEY",  "moonshot-v1-8k"),
    ("deepseek","深度求索 DeepSeek",           "https://api.deepseek.com/v1/chat/completions",      "DEEPSEEK_API_KEY",  "deepseek-chat"),
    ("siliconflow","硅基流动 SiliconFlow",     "https://api.siliconflow.cn/v1/chat/completions",   "SILICONFLOW_API_KEY","Qwen/Qwen2.5-7B-Instruct"),
    # ── 国际商业 ──
    ("gemini", "Google Gemini",                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "GEMINI_API_KEY","gemini-2.0-flash"),
    ("openai", "OpenAI (GPT)",                 "https://api.openai.com/v1/chat/completions",            "OPENAI_API_KEY",     "gpt-4.1-mini"),
    ("claude", "Anthropic Claude",             "https://api.anthropic.com/v1/messages",                   "ANTHROPIC_API_KEY","claude-sonnet-4-20250514"),
    # ── 本地开源 ──
    ("ollama", "Ollama (本地)",                "http://127.0.0.1:11434",                                None,                  "qwen3.6:35b"),
    ("vllm",   "vLLM (本地推理)",              "http://127.0.0.1:8000/v1/chat/completions",             None,                 "Qwen/Qwen2.5-7B-Instruct"),
    ("lmdeploy","LMDeploy (本地推理)",          "http://127.0.0.1:23333/v1/chat/completions",              None,                  "Qwen/Qwen2.5-7B-Instruct"),
]

SYSTEM_INFO = platform.system()
IS_WIN = SYSTEM_INFO == 'Windows'

def print_banner():
    """打印横幅"""
    w = 60
    top = '\u2554' + '\u2550' * w + '\u2557'
    bot = '\u255a' + '\u2550' * w + '\u255d'
    print(top)
    print('\u2551   \U0001f9e0  Hack Scanner 初始化向导              \u2551')
    print('\u2551                                          \u2551')
    print('\u2551   Config generator & wizard              \u2551')
    print(bot)
    print()

def read_config():
    """读取现有 config.json"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def write_config(config):
    """写入 config.json"""
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    print(f"\u2705 配置已保存: {CONFIG_PATH}")

# ==================== 交互式输入 ====================

def prompt(msg, default=None):
    """带默认值的交互输入"""
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"  {msg}{suffix}: ").strip()
    return val if val else (default if default is not None else '')

def select_from_list(items, prompt_text):
    """从列表中单选，返回 (index, selected_item)"""
    print(f"\n{prompt_text}")
    for i, item in enumerate(items):
        prefix = '\U0001f51a ' if len(item) > 1 else ''
        print(f"  {i+1}. {prefix}{item[0]:8s} | {item[1]}")
    while True:
        n = input("  请选择 [1-" + str(len(items)) + "]: ").strip()
        try:
            idx = int(n) - 1
            if 0 <= idx < len(items):
                return idx, items[idx]
        except ValueError:
            pass
        print("  \u274c 请输入有效数字")

def auto_detect_ollama():
    """自动检测本地 Ollama"""
    try:
        import requests
        resp = requests.get('http://127.0.0.1:11434/api/tags', timeout=5)
        if resp.status_code == 200:
            models = [m['name'] for m in resp.json().get('models', [])]
            return len(models) > 0, models
    except Exception:
        pass
    return False, []

# ==================== 向导步骤 ====================

def step_ai_config(auto=False):
    """配置 AI"""
    if auto:
        provider = "ollama"
        model = "qwen3.6:35b"
        base_url = ""
        api_key = ""
        print("  \U0001f916 使用默认 Ollama (本地)")
        return {
            'enabled': True,
            'provider': provider,
            'model': model,
            'base_url': base_url,
            'api_key': api_key,
            'temperature': 0.2,
            'max_tokens': 4096
        }

    enabled = prompt("是否启用 AI 分析", "yes").lower()
    if enabled not in ('y', 'yes', '1'):
        return {'enabled': False}

    # 选择 provider
    idx, prov = select_from_list(AI_PROVIDERS, "\U0001f916 请选择 AI 提供商:")
    key, name, default_url, env_key, default_model = prov

    # 自动检测 Ollama 模型
    if key == 'ollama':
        has_ollama, ollama_models = auto_detect_ollama()
        if has_ollama:
            print(f"\n  \U0001f4e6 检测到 {len(ollama_models)} 个 Ollama 模型: {', '.join(ollama_models)}")
            model_idx, model = select_from_list([(m, m) for m in ollama_models], "选择模型:")
        else:
            print("  \u274c 未检测到 Ollama，使用默认值 qwen3.6:35b")
            model = default_model
    elif key == 'vllm' or key == 'lmdeploy':
        print(f"  \U0001f4e6 本地推理服务: {default_url}")
        model = prompt("模型名", default_model)
    else:
        # 商业 API - 需要 Key
        has_key = False
        if env_key:
            existing = os.environ.get(env_key, '')
            if existing and len(existing) > 10:
                masked = '***' + existing[-4:]
                print(f"  \U0001f511 检测到环境变量 {env_key}: {masked}")
                has_key = True
        api_key = prompt(f"API Key (或留空手动配置)", '') or os.environ.get(env_key, '')

    base_url = prompt("Base URL (留空使用默认)", default_url)

    print()
    return {
        'enabled': True,
        'provider': key,
        'model': model if key != 'ollama' else (default_model if not has_ollama else model),
        'base_url': base_url if base_url else '',
        'api_key': api_key,
        'temperature': 0.2,
        'max_tokens': 4096
    }

def step_proxy_config(auto=False):
    """配置代理"""
    if auto:
        return {'enabled': False, 'http': '', 'https': ''}

    enabled = prompt("是否启用扫描代理 (如 Clash/Fiddler)", "no").lower()
    if enabled not in ('y', 'yes', '1'):
        return {'enabled': False, 'http': '', 'https': ''}

    proxy_url = prompt("代理地址 (如 http://127.0.0.1:7890)", "http://127.0.0.1:7890")
    return {
        'enabled': True,
        'http': proxy_url,
        'https': proxy_url
    }

def step_scan_config(auto=False):
    """配置扫描参数"""
    if auto:
        print("  \U0001f50d 使用默认扫描参数")
        return

    print("\n\u27a1 扫描参数 (当前值 → 输入新值，留空保持):")
    timeout = prompt("请求超时(秒)", "30")
    max_pages = prompt("最大页面数", "100")
    concurrent = prompt("并发线程数", "5")

    write_config(read_config())

def step_summary():
    """显示配置摘要"""
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = json.load(f)

    print("\n" + "\u2554" + "\u2550" * 56 + "\u2557")
    print("\u2551   \U0001f4cb 配置摘要                                  \u2551")
    print("\u2551                                            \u2551")

    ai = config.get('ai', {})
    if ai.get('enabled'):
        prov_name = AI_PROVIDERS[[p[0] for p in AI_PROVIDERS].index(ai['provider'])][1] if ai['provider'] in [p[0] for p in AI_PROVIDERS] else ai['provider']
        print(f"  \U0001f916 AI: {prov_name} / {ai['model']}")
    else:
        print("  \u274c AI: 未启用")

    proxy = config.get('scanner', {}).get('proxy', {})
    if proxy.get('enabled'):
        print(f"  \U0001f578 代理: {proxy['http']}")
    else:
        print("  \U0001f511 代理: 未启用")

    scanner = config.get('scanner', {})
    print(f"  \U0001f50d 超时: {scanner.get('timeout', 30)}s | "
          f"并发: {scanner.get('concurrent', 5)} | "
          f"最大页面: {scanner.get('max_pages', 100)}")

    print("\u255a" + "\u2550" * 56 + "\u255d")
    print()

def main():
    auto = '--auto' in sys.argv
    if not IS_WIN:
        sys.stdout.reconfigure(encoding='utf-8')

    print_banner()
    print(f"\U0001f4bb 系统: {SYSTEM_INFO} | Python: {platform.python_version()}")
    print("\U0001f4d6 配置文件: " + CONFIG_PATH)
    print("\U0001f527 " + "-" * 58)

    if auto:
        print("\n\U0001f31a 自动模式 - 使用默认配置:\n")
        ai_conf = step_ai_config(auto=True)
        proxy_conf = step_proxy_config(auto=True)
    else:
        # 步骤 1: AI
        ai_conf = step_ai_config(auto=False)
        input("\n\u23e9 Enter 继续...")

        # 步骤 2: 代理
        proxy_conf = step_proxy_config(auto=False)
        input("\n\u23e9 Enter 继续...")

        # 步骤 3: 扫描参数
        step_scan_config(auto=False)
        print()

    # 合并配置
    existing = read_config()

    if 'ai' in ai_conf and ai_conf['enabled']:
        existing['ai'] = ai_conf
    else:
        existing.setdefault('ai', {})
        existing['ai'].update(ai_conf)

    scanner = existing.setdefault('scanner', {})
    proxy = existing.get('scanner', {}).get('proxy', {}) if 'scanner' in existing else {}
    if not isinstance(proxy, dict):
        proxy = {}
        scanner['proxy'] = proxy
    if proxy_conf['enabled']:
        proxy.update({
            'enabled': True,
            'http': proxy_conf['http'],
            'https': proxy_conf['https']
        })
    elif not proxy.get('enabled'):
        proxy.setdefault('enabled', False)

    write_config(existing)

    step_summary()

    if not auto:
        confirm = prompt("应用配置?", "yes").lower()
        if confirm in ('y', 'yes', '1'):
            print("\U0001f389 初始化完成!")
            print(f"\n\U0001f4a1 测试命令:")
            print(f"  python hack_scanner.py --url https://example.com")
            print(f"  python hack_scanner.py --url https://example.com --ai")
        else:
            print("\u26d4 配置未应用，如需修改请再次运行 init.py")

    # 清理历史残留
    import shutil
    pycache = os.path.join(SCRIPT_DIR, '__pycache__')
    if os.path.exists(pycache):
        shutil.rmtree(pycache)

if __name__ == '__main__':
    main()
