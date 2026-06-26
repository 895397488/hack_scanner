#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI 模型选择器 — 交互式选择并更新 config.json"""

import os, sys, json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')

MODELS = [
    ("1", "qwen",     "Qwen (通义千问)",          "DASHSCOPE_API_KEY",  "qwen-max"),
    ("2", "glm",      "GLM (智谱)",               "ZHIPUAI_API_KEY",    "glm-4-flash"),
    ("3", "moonshot", "Kimi (月之暗面)",          "MOONSHOT_API_KEY",   "moonshot-v1-8k"),
    ("4", "deepseek", "DeepSeek (深度求索)",       "DEEPSEEK_API_KEY",   "deepseek-chat"),
    ("5", "siliconflow","SiliconFlow (硅基流动)",  "SILICONFLOW_API_KEY","Qwen/Qwen2.5-7B-Instruct"),
    ("6", "gemini",   "Gemini (Google)",          "GEMINI_API_KEY",     "gemini-2.0-flash"),
    ("7", "openai",   "GPT (OpenAI)",             "OPENAI_API_KEY",     "gpt-4.1-mini"),
    ("8", "claude",   "Claude (Anthropic)",       "ANTHROPIC_API_KEY","claude-sonnet-4-20250514"),
    ("9", "ollama",   "Ollama (本地)",            None,                 "qwen3.6:35b"),
    ("10", "vllm",    "vLLM (本地推理)",          None,                 "Qwen/Qwen2.5-7B-Instruct"),
    ("11", "lmdeploy","LMDeploy (本地推理)",       None,                 "Qwen/Qwen2.5-7B-Instruct"),
]

def main():
    # 支持 bat 传参 (python init_ai.py qwen) 或交互式选择
    import sys
    
    matched = None
    for arg in sys.argv[1:]:
        matched = [m for m in MODELS if m[1] == arg]
        if matched:
            break

    if not matched:
        print("\n=== Hack Scanner AI 模型选择 ===\n")
        for num, key, name, _, default in MODELS:
            env_info = f" [{os.environ.get(name,'(not set)')[:20]}...]" if os.environ.get(name,'') else ""
            print(f"  [{num}] {name}{env_info}")
        while True:
            choice = input("\n请选择 [1-11]: ").strip()
            matched = [m for m in MODELS if m[0] == choice]
            if matched: break
            print("无效选择，请输入 1-11")

    num, key, name, env_key, default_model = matched[0]

    api_key = ""
    if env_key:
        existing = os.environ.get(env_key, '')
        if existing:
            masked = '***' + existing[-4:]
            print(f"\n检测到 {env_key}: {masked}")
            ans = input("使用环境变量? (y/n) [y]: ").strip().lower()
            if ans in ('n','no','0'):
                api_key = input(f"请输入 API Key: ").strip() or ''
            else:
                api_key = existing
        else:
            api_key = input(f"请输入 {env_key}: ").strip()

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    cfg['ai'] = {'enabled': True, 'provider': key, 'model': default_model, 'base_url': '', 'api_key': api_key, 'temperature': 0.2, 'max_tokens': 4096}
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    print(f"\n已选择: {name} / {default_model}\n")

if __name__ == '__main__':
    main()
