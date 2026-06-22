#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 自动漏洞分析模块 v2.0 — 多 AI 代理
======================================
支持所有已知大模型厂商的 API，自动适配不同协议：
- OpenAI 兼容 (qwen/glm/moonshot/deepseek/siliconflow/gemini/openai/vllm/lmdeploy)
- Anthropic Claude 原生协议
- Ollama 本地流式 JSONL

用法:
    python hack_scanner.py --url URL --ai
    python ai_analyzer.py https://target.com       # 独立运行
"""

import os
import sys
import json
import re
import time
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('ai_analyzer')

# ==================== Tool Call Limiter (借鉴 PentAGI) ====================
MAX_GENERAL_CALLS = 50
MAX_LIMITED_CALLS = 20

class CallLimiter:
    """追踪 AI 调用次数，防止死循环。借鉴 PentAGI tool call limits。"""
    def __init__(self, mode: str = 'general'):
        self.mode = mode
        self.call_count = 0
        self.limit = MAX_LIMITED_CALLS if mode == 'limited' else MAX_GENERAL_CALLS
        self.exhausted = False
    def check(self) -> bool:
        """返回 True=可以继续调用, False=已用完"""
        if self.exhausted:
            return False
        self.call_count += 1
        if self.call_count > self.limit:
            self.exhausted = True
            logger.warning(f"⚠️ AI 工具调用已达上限 ({self.limit})，停止进一步分析")
            return False
        return True
    def status(self) -> dict:
        return {'mode': self.mode, 'call_count': self.call_count,
                'limit': self.limit, 'remaining': max(0, self.limit - self.call_count),
                'exhausted': self.exhausted}

# ========== 当前目录的配置文件 ==========
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_SCRIPT_DIR, 'config.json')
with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
    CONFIG = json.load(f)

# 加载 providers 矩阵
_PROVIDER_DB_PATH = os.path.join(_SCRIPT_DIR, 'config.json')
with open(_PROVIDER_DB_PATH, 'r', encoding='utf-8') as f:
    CONFIG = json.load(f)

# ========== AI 提供商矩阵（内置）==========
PROVIDER_DB = {
  "providers": {
    "qwen": {"name":"通义千问 Qwen","display_name":"Qwen","category":"国产商业","api_type":"openai_compatible","default_base_url":"https://dashscope.aliyuncs.com/compatible-mode/v1","env_api_key":"DASHSCOPE_API_KEY","default_model":"qwen-plus","models":["qwen-turbo","qwen-plus","qwen-max","qwen-max-latest","qwen-vl-plus","qwen-vl-max"],"api_path":"/v1/chat/completions"},
    "glm": {"name":"智谱 GLM","display_name":"GLM","category":"国产商业","api_type":"openai_compatible","default_base_url":"https://open.bigmodel.cn/api/paas/v4/chat/completions","env_api_key":"ZHIPUAI_API_KEY","default_model":"glm-4-flash","models":["glm-4","glm-4-plus","glm-4-airx","glm-4-air","glm-4-flash","glm-5"],"api_path":"/api/paas/v4/chat/completions"},
    "moonshot": {"name":"月之暗面 Kimi","display_name":"Kimi","category":"国产商业","api_type":"openai_compatible","default_base_url":"https://api.moonshot.cn/v1/chat/completions","env_api_key":"MOONSHOT_API_KEY","default_model":"moonshot-v1-8k","models":["moonshot-v1-8k","moonshot-v1-32k","moonshot-v1-128k"],"api_path":"/v1/chat/completions"},
    "deepseek": {"name":"深度求索 DeepSeek","display_name":"DeepSeek","category":"国产商业","api_type":"openai_compatible","default_base_url":"https://api.deepseek.com/v1/chat/completions","env_api_key":"DEEPSEEK_API_KEY","default_model":"deepseek-chat","models":["deepseek-chat","deepseek-coder","deepseek-reasoner"],"api_path":"/v1/chat/completions"},
    "siliconflow": {"name":"硅基流动 SiliconFlow","display_name":"SiliconFlow","category":"国产商业","api_type":"openai_compatible","default_base_url":"https://api.siliconflow.cn/v1/chat/completions","env_api_key":"SILICONFLOW_API_KEY","default_model":"Qwen/Qwen2.5-7B-Instruct","models":["Qwen/Qwen2.5-72B-Instruct","meta-llama/Llama-3.3-70B-Instruct"],"api_path":"/v1/chat/completions"},
    "gemini": {"name":"Google Gemini","display_name":"Gemini","category":"国际商业","api_type":"openai_compatible","default_base_url":"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions","env_api_key":"GEMINI_API_KEY","default_model":"gemini-2.0-flash","models":["gemini-2.5-pro-preview-05-06","gemini-2.0-flash","gemini-2.0-flash-lite","gemini-1.5-flash"],"api_path":"/v1beta/openai/chat/completions"},
    "openai": {"name":"OpenAI GPT","display_name":"OpenAI","category":"国际商业","api_type":"openai_compatible","default_base_url":"https://api.openai.com/v1/chat/completions","env_api_key":"OPENAI_API_KEY","default_model":"gpt-4.1-mini","models":["gpt-4.1","gpt-4.1-mini","gpt-4o-mini","gpt-4o","gpt-4-turbo"],"api_path":"/v1/chat/completions"},
    "claude": {"name":"Anthropic Claude","display_name":"Claude","category":"国际商业","api_type":"anthropic","default_base_url":"https://api.anthropic.com/v1/messages","env_api_key":"ANTHROPIC_API_KEY","default_model":"claude-sonnet-4-20250514","models":["claude-opus-4-1","claude-sonnet-4-20250514","claude-haiku-4-20250514"],"api_path":"/v1/messages"},
    "ollama": {"name":"Ollama 本地开源","display_name":"Ollama","category":"本地开源","api_type":"ollama","default_base_url":"http://127.0.0.1:11434","env_api_key":None,"default_model":"qwen3.6:35b","models":["qwen3.6:35b","qwen3:8b","gemma4:31b"],"api_path":"/api/chat"},
    "vllm": {"name":"vLLM 本地推理","display_name":"vLLM","category":"本地开源","api_type":"openai_compatible","default_base_url":"http://127.0.0.1:8000/v1/chat/completions","env_api_key":None,"default_model":"Qwen/Qwen2.5-7B-Instruct","models":["Qwen/Qwen2.5-7B-Instruct","meta-llama/Llama-3.3-70B-Instruct"],"api_path":"/v1/chat/completions"},
    "lmdeploy": {"name":"LMDeploy 本地推理","display_name":"LMDeploy","category":"本地开源","api_type":"openai_compatible","default_base_url":"http://127.0.0.1:23333/v1/chat/completions","env_api_key":None,"default_model":"Qwen/Qwen2.5-7B-Instruct","models":["Qwen/Qwen2.5-7B-Instruct"],"api_path":"/v1/chat/completions"}
  },
  "list_all_models": {"ollama":["qwen3.6:35b","qwen3:8b","gemma4:31b"],"vllm":["Qwen/Qwen2.5-7B-Instruct"],"lmdeploy":["Qwen/Qwen2.5-7B-Instruct"]}
}


class AIAnalyzer:
    """多 AI 代理分析器 — 统一接口，自动适配底层协议"""

    def __init__(self):
        ai_conf = CONFIG.get('ai', {})
        self.enabled = ai_conf.get('enabled', False)
        if not self.enabled:
            return

        # 解析 provider 配置
        self.provider_key = ai_conf.get('provider', 'ollama')
        self.model = ai_conf.get('model', '')
        self.base_url = ai_conf.get('base_url', '')
        self.api_key = ai_conf.get('api_key', '')
        self.temperature = ai_conf.get('temperature', 0.2)
        self.max_tokens = ai_conf.get('max_tokens', 8192)

        # 从 providers 矩阵获取 provider 元信息
        provider_info = PROVIDER_DB.get('providers', {}).get(self.provider_key, {})
        self.api_type = provider_info.get('api_type', 'openai_compatible') if provider_info else 'ollama'
        self.display_name = provider_info.get('display_name', self.provider_key) if provider_info else self.provider_key
        self.category = provider_info.get('category', '') if provider_info else ''

        # 自动填充默认值
        if not self.model:
            self.model = provider_info.get('default_model', 'qwen3.6:35b') if provider_info else 'qwen3.6:35b'
        if not self.base_url:
            self.base_url = provider_info.get('default_base_url', 'http://127.0.0.1:11434') if provider_info else 'http://127.0.0.1:11434'

        # 自动设置 API Key（防御 None）
        env_key = provider_info.get('env_api_key') if provider_info else None
        if not self.api_key and env_key:
            self.api_key = os.environ.get(env_key, '')

        # 自动设置 API Key（防御 None）
        env_key = provider_info.get('env_api_key') if provider_info else None
        if not self.api_key and env_key:
            self.api_key = os.environ.get(env_key, '')

        logger.info(f"✅ AI 代理已启用: [{self.category}] {self.display_name} | "
                    f"模型={self.model} | API协议={self.api_type}")

    def _get_env_key(self) -> str:
        """获取对应 provider 的环境变量 Key"""
        info = PROVIDER_DB.get('providers', {}).get(self.provider_key, {})
        return info.get('env_api_key') if info else None

    # ==================== 核心方法 ====================

    def analyze(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """分析扫描结果，返回 AI 解读报告"""
        if not self.enabled:
            return {'error': 'AI 未启用。在 config.json 中设置 ai.enabled=true'}

        findings = scan_result.get('url_findings', []) + scan_result.get('file_findings', [])
        summary = scan_result.get('summary', {})

        # Context Summarizer：当 findings 过多时自动压缩（借鉴 PentAGI csum）
        if len(findings) > 100:
            found = self.summarize_findings(findings, max_keep=100)
            findings_list = found['findings']
            compression_info = f" [已压缩: {found['original_count']}→{found['kept_count']}条]"
        else:
            findings_list = findings
            compression_info = ""

        # 目标信息（URL 或文件路径）
        target = summary.get('url_target') or summary.get('file_path', 'N/A')
        scan_type = 'URL' if summary.get('url_target') else ('文件' if summary.get('file_path') else '未知')
        technologies = summary.get('url_technologies', [])
        subdomains_list = summary.get('url_subdomains', [])

        system_prompt = """你是一个专业的网络安全分析师（Penetration Tester），擅长:
1. 解读漏洞扫描报告并评估真实风险
2. 给出具体的修复建议和验证步骤
3. 根据漏洞分布自主决定下一步扫描策略
4. 用中文输出，结构清晰

请以以下格式输出:
## 📋 风险评估摘要
（总体评价 + 关键发现）

## 🔴 高危/中危漏洞详情
对每个中危及以上漏洞分别给出:
- **漏洞**: [名称]
- **风险**: [解释实际影响]
- **修复**: [具体操作步骤]
- **验证**: [如何确认已修复]

## 💡 低危 / 建议项
（批量给出修复建议）

## 🎯 下一步建议
（如果发现了可能相关的深层漏洞，建议追加的扫描策略，包含具体命令工具如 subfinder/nuclei/httpx 等）"""

        user_prompt = f"""请分析以下安全扫描报告:{compression_info}

**目标类型**: {scan_type}
**扫描目标**: {target}
**风险等级**: {summary.get('risk_level', 'N/A')} (评分: {summary.get('risk_score', 0)})
**总发现数**: {len(findings_list)}{f' (原始{len(findings)}条)' if len(findings) > 100 else ''}

---
漏洞清单:
```json
{json.dumps({'findings': findings_list, 'technologies': technologies, 
              'subdomains': subdomains_list}, ensure_ascii=False, indent=2)}
```"""

        response = self._call_llm(system_prompt, user_prompt)
        
        return {
            'provider': self.provider_key,
            'display_name': self.display_name,
            'model': self.model,
            'raw_response': response,
            'analyzed': True,
        }

    def _get_api_path(self) -> str:
        """从 providers 矩阵获取 API 端点路径"""
        info = PROVIDER_DB.get('providers', {}).get(self.provider_key, {})
        return info.get('api_path', '') if info else ''

    def _call_llm(self, system: str, user: str) -> str:
        """统一调用 LLM — 自动适配不同协议"""
        import requests as req

        # ---------- OpenAI 兼容协议 (qwen/glm/moonshot/deepseek/siliconflow/gemini/openai/vllm/lmdeploy) ----------
        if self.api_type == 'openai_compatible':
            headers = {'Content-Type': 'application/json'}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            payload = {
                'model': self.model,
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user', 'content': user},
                ],
                'temperature': self.temperature,
                'max_tokens': self.max_tokens,
            }

        # ---------- Anthropic Claude 原生协议 ----------
        elif self.api_type == 'anthropic':
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': self.api_key or '',
                'anthropic-version': '2023-06-01',
            }
            payload = {
                'model': self.model,
                'messages': [
                    {'role': 'user', 'content': user},
                ],
                'system': system,
                'temperature': self.temperature,
                'max_tokens': self.max_tokens,
            }

        # ---------- Ollama 本地流式协议 ----------
        elif self.api_type == 'ollama':
            headers = {'Content-Type': 'application/json'}
            payload = {
                'model': self.model,
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user', 'content': user},
                ],
                'stream': True,  # Ollama 默认流式
            }

        else:
            return f"不支持的 API 类型: {self.api_type}"

        # 构建最终 URL
        url = self.base_url.rstrip('/')
        api_path = self._get_api_path() or (
            '/v1/chat/completions' if self.api_type == 'openai_compatible' else
            '/api/chat' if self.api_type == 'ollama' else
            '/v1/messages' if self.api_type == 'anthropic' else ''
        )
        if url.endswith(api_path):
            pass  # already has the path
        elif '/' in url.lstrip('/') and not url.endswith('/api') and not url.endswith('/v1'):
            url += api_path
        else:
            url += api_path

        logger.info(f"🤖 正在调用 AI ({self.display_name}/{self.model}) [{self.api_type}]...")
        start = time.time()
        
        try:
            resp = req.post(url, json=payload, headers=headers, timeout=120)
            resp.encoding = 'utf-8'
            elapsed = time.time() - start

            if resp.status_code == 200:
                # ---------- Anthropic Claude 格式 ----------
                if self.api_type == 'anthropic':
                    data = resp.json()
                    content_list = data.get('content', [])
                    content_parts = [c.get('text', '') for c in content_list if isinstance(c, dict) and c.get('type') == 'text']
                    content = ''.join(content_parts)

                # ---------- Ollama 流式 JSONL 格式 ----------
                elif self.api_type == 'ollama':
                    content_parts = []
                    for line in resp.text.strip().split('\n'):
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                            msg = chunk.get('message', {})
                            text = msg.get('content', '')
                            if text:
                                content_parts.append(text)
                        except json.JSONDecodeError:
                            continue
                    content = ''.join(content_parts)

                # ---------- OpenAI 兼容格式 (GPT/Gemini/Qwen/GLM/Kimi/DeepSeek/SiliconFlow/vLLM/LMDeploy) ----------
                else:
                    data = resp.json()
                    content = data.get('choices', [{}])[0].get('message', {}).get('content', '')

                logger.info(f"✅ AI 分析完成 ({elapsed:.1f}s, {len(content)} chars)")
                return content
            else:
                error_detail = resp.text[:500]
                logger.error(f"❌ AI API 调用失败 [{self.display_name}]: HTTP {resp.status_code}")
                return f"AI API 错误 (HTTP {resp.status_code}): {error_detail}"

        except req.exceptions.ConnectionError as e:
            logger.error(f"❌ AI API 连接失败 ({url}): {e}")
            return f"无法连接到 AI API ({url})，请检查网络或配置。"
        except req.exceptions.Timeout:
            logger.error(f"❌ AI API 请求超时")
            return "AI 请求超时，请重试或增加 timeout。"
        except json.JSONDecodeError as e:
            logger.error(f"❌ AI API JSON 解析错误: {e}")
            return f"AI 响应格式异常: {resp.text[:200]}"
        except Exception as e:
            logger.error(f"❌ AI 调用异常: {type(e).__name__}: {e}")
            return f"AI 调用异常 ({type(e).__name__}): {e}"


# ==================== Markdown -> HTML ====================

def _md_to_html(text):
    """Markdown -> HTML 转换（支持标题/粗体/列表/code块/嵌套项/表格）"""
    lines = text.split('\n')
    h = ''
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        # --- code blocks (``` ... ```) ---
        if line.strip().startswith('```'):
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < n and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            # close code block (skip the closing ```
            if i < n:
                i += 1
            escaped = '\n'.join(code_lines).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
            lang_attr = f' class="{lang}"' if lang else ''
            h += f'<pre style="background:#161b22;padding:1rem;border-radius:8px;color:#e6edf3;font-size:.9rem;overflow-x:auto;margin:.5rem 0">' + escaped + '</pre>\n'
            continue

        # --- horizontal rules (---) ---
        if re.match(r'^-{3,}\s*$', line):
            h += '<hr style="border:none;border-top:1px solid #21262d;margin:1rem 0;">\n'
            i += 1
            continue

        # --- markdown table detection (lines starting with |) ---
        if line.strip().startswith('|'):
            table_rows = []
            while i < n and lines[i].strip().startswith('|'):
                table_rows.append(lines[i])
                i += 1
            h += _render_table(table_rows)
            continue

        # --- ## headers ---
        m = re.match(r'^## (.+)$', line)
        if m:
            h += '<h3 style="color:#e6edf3;margin-top:2rem;border-bottom:2px solid #30363d;padding-bottom:.5rem;">\U0001f4cb ' + _esc(m.group(1)) + '</h3>\n'
            i += 1
            continue

        # --- ### headers ---
        m = re.match(r'^### (.+)$', line)
        if m:
            h += '<h4 style="color:#79c0ff;margin-top:1.2rem;font-weight:normal;">' + _esc(m.group(1)) + '</h4>\n'
            i += 1
            continue

        # --- blockquotes (>) ---
        m = re.match(r'^> (.+)$', line)
        if m:
            h += '<div style="margin:.5rem 0;padding:.8rem 1rem;border-left:3px solid #484f58;color:#8b949e;font-style:italic;">' + _inline(m.group(1)) + '</div>\n'
            i += 1
            continue

        # --- numbered list (1. text) ---
        m = re.match(r'^(\s*)(\d+)\. (.+)$', line)
        if m:
            h += '<div style="margin:.3rem 0;padding:.5rem .8rem;background:#161b22;border-left:3px solid #f78166;">' + m.group(2) + '. ' + _inline(m.group(3)) + '</div>\n'
            i += 1
            continue

        # --- nested bullet list (  - text) ---
        m = re.match(r'^( {2,})- (.+)$', line)
        if m:
            h += '<div style="margin:.3rem 0;padding:.5rem .8rem .5rem 1.2rem;background:#161b22;border-left:3px solid #79c0ff;font-size:.9em;">' + _inline(m.group(2)) + '</div>\n'
            i += 1
            continue

        # --- bullet list (- text) ---
        m = re.match(r'^- (.+)$', line)
        if m:
            h += '<div style="margin:.3rem 0;padding:.5rem .8rem;background:#161b22;border-left:3px solid #f78166;">' + _inline(m.group(1)) + '</div>\n'
            i += 1
            continue

        # --- bold inline (**text**) (must process inside paragraph content) ---
        # --- collect paragraph lines until blank or block element ---
        para_lines = []
        while i < n:
            pl = lines[i]
            if pl.strip() == '':
                break
            # Stop if we hit a block element (header, code block, table, hr, quote, list)
            if re.match(r'^## ', pl) or re.match(r'^### ', pl):
                break
            if pl.strip().startswith('```'):
                break
            if pl.strip().startswith('|') and i > 0 and lines[i-1].strip() != '':
                break
            if re.match(r'^-{3,}\s*$', pl):
                break
            if re.match(r'^> |^\s*\d+\. |^( {2,})- |^- ', pl):
                break
            para_lines.append(pl)
            i += 1

        if para_lines:
            para = ' '.join(para_lines)
            h += '<div style="margin:.5rem 0;line-height:1.8;">' + _inline(para) + '</div>\n'
        elif not para_lines and i < n and lines[i].strip() == '':
            # blank line between blocks, just skip
            i += 1
            continue
        else:
            # fallback: treat as plain paragraph text
            if line.strip():
                h += '<div style="margin:.5rem 0;line-height:1.8;">' + _inline(line) + '</div>\n'
            i += 1

    return h


def _esc(s):
    """Escape HTML in text."""
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _inline(line):
    """处理行内格式：先转义，再插标签"""
    e = _esc(line)
    e = re.sub(r'`([^`]+)`', r'<code style="background:#21262d;padding:0.15rem 0.4rem;border-radius:4px;color:#79c0ff;font-size:.85rem;">\1</code>', e)
    e = re.sub(r'\*\*(.+?)\*\*', r'<strong style="color:#e6edf3;">\1</strong>', e)
    return e


def _render_table(table_rows):
    """Render a markdown table as an HTML table."""
    if not table_rows:
        return ''

    def split_row(row):
        # Split by | but handle content between pipes carefully
        parts = row.strip().strip('|').split('|')
        return [p.strip() for p in parts]

    rows = [split_row(r) for r in table_rows]
    if not rows:
        return ''

    # Find column count
    max_cols = max(len(r) for r in rows)
    # Normalize all rows to same number of columns
    for r in rows:
        while len(r) < max_cols:
            r.append('')

    cols = max_cols
    NL = chr(10)
    result = '<table style="width:100%;border-collapse:collapse;margin:.5rem 0;">' + NL
    result += '<tr style="background:#161b22;">' + NL
    # Header row
    for cell in rows[0]:
        result += f'<th style="padding:.6rem;border-bottom:2px solid #30363d;color:#e6edf3;text-align:left;">{_inline(cell)}</th>\n'
    result += '</tr>\n'

    # Separator row is at index 1, skip it
    # Markdown table separator lines have cells like ':---' or '---' (dash-based)
    is_separator = lambda r: len(r) > 0 and all(
        c.strip().startswith(':') or c.strip().startswith('-') for c in r if c.strip()
    ) and any('-' in c for c in r)
    data_start = 2 if len(rows) > 1 and is_separator(rows[1]) else 1

    # Data rows
    for r in rows[data_start:]:
        result += '<tr style="border-bottom:1px solid #21262d;">' + NL
        for cell in r:
            result += f'<td style="padding:.5rem .6rem;color:#c9d1d9;">{_inline(cell)}</td>\n'
        result += '</tr>\n'

    result += '</table>'
    return result


# ==================== 便捷函数 ====================

def ai_analyze_url(url: str, output_dir: str = None) -> Dict[str, Any]:
    """一条龙: 扫描 + AI分析 + HTML注入"""
    from url_scanner import URLScanner, ReportGenerator

    print("\U0001f916 启动 AI 自动分析流程...")
    
    # 1. 执行扫描
    scanner = URLScanner(output_dir=output_dir)
    result = scanner.scan(url)
    
    os.makedirs(output_dir or '.', exist_ok=True)
    html_path = os.path.join(output_dir or '.', 'report.html')
    json_path = os.path.join(output_dir or '.', 'report.json')

    ReportGenerator.generate(result, html_path)

    report_data = {
        'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'url_target': result.target_url,
            'url_findings_count': result.finding_count,
            'url_critical': result.critical_count,
            'url_high': result.high_count,
            'url_technologies': result.technologies,
            'url_subdomains': result.subdomains[:20],
            'risk_level': ('\u2620\ufe0f CRITICAL' if result.critical_count > 0 else
                           '\U0001f534 HIGH RISK' if result.high_count > 0 else
                           '\U0001f7e1 MODERATE' if sum(1 for f in result.findings if f.severity.value == 'medium') > 0 else
                           '\U0001f7e2 LOW RISK'),
            'risk_score': result.critical_count * 25 + result.high_count * 15 +
                          sum(1 for f in result.findings if f.severity.value == 'medium') * 5 +
                          sum(1 for f in result.findings if f.severity.value == 'low'),
            'total_findings': result.finding_count,
            'severity_breakdown': {
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': sum(1 for f in result.findings if f.severity.value == 'medium'),
                'low': sum(1 for f in result.findings if f.severity.value == 'low'),
                'info': sum(1 for f in result.findings if f.severity.value == 'info'),
            },
        },
        'url_findings': [f.to_dict() for f in result.findings],
        'file_findings': [],
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    with open(json_path, 'r', encoding='utf-8') as f:
        report_data = json.load(f)

    print(f"\U0001f4ca 扫描完成 ({result.finding_count} 个发现)")
    
    # 2. AI分析
    analyzer = AIAnalyzer()
    ai_result = analyzer.analyze(report_data)
    
    if ai_result.get('analyzed'):
        print(f"\U0001f916 AI {analyzer.display_name}/{analyzer.model} 分析完成")
        ai_text = ai_result['raw_response']
        
        # 保存AI JSON
        ai_json_path = os.path.join(os.path.dirname(json_path), 'ai_report.json')
        with open(ai_json_path, 'w', encoding='utf-8') as f:
            json.dump(ai_result, f, ensure_ascii=False, indent=2)
        print(f"\U0001f4c4 AI JSON 已保存: {ai_json_path}")
        
        # 独立HTML + iframe嵌入（避免嵌套div冲突）
        ai_html_path = os.path.join(os.path.dirname(json_path), 'ai_report.html')
        ai_html = _md_to_html(ai_text)
        full_ai_html = (
            '<!DOCTYPE html><html lang="zh"><head>'
            '<meta charset="UTF-8"><style>'
            '*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:1.5rem;line-height:1.8;font-size:.95rem}'
            'pre{background:#161b22;padding:1rem;border-radius:8px;color:#e6edf3;font-size:.9rem;overflow-x:auto;margin:.5rem 0}'
            'code{background:#21262d;padding:.15rem .4rem;border-radius:4px;color:#79c0ff;font-size:.85rem}'
            'h3{color:#e6edf3;margin-top:1.5rem;border-bottom:2px solid #30363d;padding-bottom:.5rem}.ai-title{color:#f78166!important;margin:0!important;border:none!important}hr{border:none;border-top:1px solid #21262d;margin:1rem 0}'
            'div{margin:.3rem 0;padding:.5rem .8rem;background:#161b22;border-left:3px solid #f78166}h4{color:#79c0ff;font-weight:normal}.blockquote{border-left:3px solid #484f58;color:#8b949e;font-style:italic;padding:.8rem 1rem;margin:.5rem 0}'
            '</style></head><body>'
            '<h2 class="ai-title">\U0001f916 AI 自动分析报告 (' + analyzer.display_name + '/' + analyzer.model + ')</h2>' + ai_html + '</body></html>'
        )
        with open(ai_html_path, 'w', encoding='utf-8') as f:
            f.write(full_ai_html)
        print(f"\U0001f4c5 AI HTML 报告已保存: {ai_html_path}")
        
        iframe_html = (
            '<div style="margin:1.5rem 0;border-radius:12px;overflow:hidden;border:1px solid #30363d;">'
            '<h3 style="color:#f78166;padding:.8rem 1.2rem;margin:0;background:#161b22;font-size:1.1rem;">\U0001f916 AI 自动分析报告 (' + analyzer.display_name + '/' + analyzer.model + ')</h3>'
            '<iframe src="ai_report.html" style="width:100%;height:800px;border:none;background:#0d1117;"></iframe>'
            '</div>'
        )
        
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        marker = '</div>\n        <footer>'
        if marker in html_content:
            html_content = html_content.replace(marker, iframe_html + '\n' + marker)
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\U0001f4be report.html 已更新（含iframe嵌入AI报告）")
        else:
            print("⚠️ 未在 report.html 中找到插入位置")
    else:
        print(f"\u26a0\ufe0f {ai_result.get('error', 'AI分析未执行')}")

    return {'scan_result': result, 'ai_result': ai_result}


if __name__ == '__main__':
    if len(sys.argv) > 1:
        target = sys.argv[1]
        ai_analyze_url(target)
    else:
        print("用法: python ai_analyzer.py https://target.com")
