# 🔐 Hack Scanner — 自动化漏洞扫描器

**基于 Shannon 架构的 Web/代码综合安全扫描框架**

## 📖 目录

- [功能特性](#功能特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [使用方式](#使用方式)
- [模块说明](#模块说明)
- [配置说明](#配置说明)
- [输出报告](#输出报告)
- [注意事项](#注意事项)

---

## 功能特性

### Web URL 扫描（黑盒）
- **OWASP TOP10 基础检测**：SQL注入、XSS、SSRF、RCE、LFI 等
- **HTTP 安全头检查**：`X-Frame-Options`、`CSP`、`Referrer-Policy` 等缺失告警
- **SSL/TLS 证书检测**：过期、弱密码套件、自签证书识别
- **CORS 错误配置**：跨域资源共享泄露检测
- **子域名枚举**：自动提取并列出所有子域
- **目录爆破**：基于词表的敏感路径发现
- **技术栈指纹**：识别服务器环境、框架、CDN 等

### 代码文件扫描（白盒）
- **敏感信息泄露**：密钥/密码/API Token 在源码中硬编码检测
- **文件权限检测**：可写目录、配置文件暴露风险
- **依赖漏洞分析**：第三方库 CVE 匹配
- **支持语言**：Python / JavaScript / PHP / Java / YAML

### Shannon 增强（白盒驱动黑盒）
- **上下文感知 Payload 生成**：从源码中发现的路由/变量自动构造针对性测试用例
- **数据流追踪（Source → Sink）**：追踪用户输入到危险函数的传播路径
- **API 端点发现**：从代码中抽取 API 路由定义
- **认证绕过测试**：登录/JWT/Session 相关漏洞探测

### AI 自动分析
- **多模型支持**：Ollama（本地）、Qwen、GLM、GPT、Claude 等主流大模型
- **自动解读报告**：将扫描结果转化为可读的安全分析报告
- **下一步建议**：智能推荐后续渗透测试策略

### 可视化报告
- **HTML 报告**：彩色卡片式展示，支持展开查看完整 JSON 数据
- **JSON 数据**：结构化机器可读格式，便于 CI/CD 集成

---

## 系统要求

```
Python >= 3.10
pip install -r requirements.txt
```

**核心依赖：**
| 依赖 | 用途 |
|------|------|
| `requests` / `urllib3` | HTTP 请求与连接管理 |
| `beautifulsoup4` / `lxml` | HTML 解析与技术栈提取 |
| `tldextract` | 子域名提取 |
| `pyyaml` | YAML 配置解析 |
| `jinja2` | 报告模板渲染 |
| `cryptography` | SSL/TLS 证书检查 |

**可选依赖：**
- `python-nmap`：端口扫描增强（需系统安装 nmap）
- `nltk`：NLP 辅助分析
- `pdfkit` / `weasyprint`：PDF 报告导出

---

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 初始化配置（交互式向导）
```bash
python init.py
```
或直接使用默认配置运行，后续在 `config.json` 中修改。

### 3. 快速扫描示例
```bash
# 仅扫描 URL
python hack_scanner.py --url https://example.com

# 仅分析代码文件/目录
python hack_scanner.py --file ./src/

# 同时扫描 URL + 代码
python hack_scanner.py --both -u https://example.com -f ./src/

# 启用 AI 自动分析
python hack_scanner.py --url https://example.com --ai
```

---

## 使用方式

### 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-u, --url` | 目标 URL（必需） | `--url https://target.com` |
| `-f, --file` | 要分析的文件/目录路径（必需） | `--file ./src/` |
| `--both` | 同时执行 URL + 文件扫描 | `--both -u URL -f DIR` |
| `--ai` | 启用 AI 自动分析解读 | `--url URL --ai` |
| `-o, --output` | 报告输出目录（默认：当前目录/hack_report） | `-o ./reports/` |
| `--deep` | 深度扫描模式（更慢但更全面） | `--deep` |
| `--proxy` | HTTP/SOCKS5 代理地址 | `--proxy http://127.0.0.1:7890` |

### 交互式启动器
```bash
python launcher.py
```
提供图形化菜单：
- 输入目标 URL
- 选择仅扫描 / AI 分析模式
- 配置 AI 模型（支持 10+ 厂商）

---

## 模块说明

### `hack_scanner.py` — 主入口
综合扫描器，统一协调 URL 扫描和代码文件分析。

```python
from hack_scanner import HackScanner

scanner = HackScanner(output_dir='./output/')
# 仅 URL 扫描
result = scanner.scan_url('https://example.com')
# 仅文件扫描
findings = scanner.scan_files('./source-code/')
# 同时执行
scanner.run(url='https://example.com', file_path='./src/', use_ai=True)
```

### `url_scanner.py` — URL 安全扫描器
核心模块，负责所有 Web 层面的漏洞检测：

```
URLScanner
├── ScanResult          # 扫描结果数据结构
│   ├── findings        # VulnFinding[] 漏洞列表
│   ├── http_headers    # HTTP 响应头
│   ├── ssl_info       # SSL/TLS 信息
│   ├── technologies   # 技术栈指纹
│   ├── subdomains     # 子域名列表
│   └── dir_bust_results # 目录爆破结果
├── scan()            # 执行完整扫描
├── ReportGenerator.generate()    # 生成 HTML 报告
├── ReportGenerator.generate_from_combined()  # 生成综合报告
```

**检测能力矩阵：**
| 类别 | 检测方法 |
|------|----------|
| SQL注入 | HTTP参数模糊测试 + Shannon上下文引导 |
| XSS | 反射/存储型输入点测试 |
| SSRF | 内部IP/本地服务探测 |
| RCE/LFI | 路径穿越与命令执行Payload测试 |
| SSL/TLS | 证书过期、弱算法、自签检测 |
| CORS | Allow-Origin/Wildcard检查 |
| 安全头 | Missing-XFrame/CSP/Referrer-Policy等 |
| 子域名 | HTTP重定向 + DNS记录提取 |
| 目录爆破 | 多词表并发探测 |

### `file_analyzer.py` — 代码文件扫描器
分析源码中的安全风险：

```python
from file_analyzer import analyze_file_or_dir
findings = analyze_file_or_dir('./my-project/')
```

**检测能力：**
- **敏感信息**：正则匹配密钥/密码/API Key 模式
- **文件权限**：检查可写目录和敏感配置文件的访问控制
- **依赖安全**：匹配 CVE 数据库中的已知漏洞
- **语言分析**：自动识别 Python/JS/PHP/Java/YAML 并应用针对性规则

### `shannon_context.py` — Shannon 上下文增强（可选）
白盒驱动黑盒的核心模块，提供源码分析到动态测试的桥梁：

| 类 | 功能 |
|---|---|
| `ContextAnalyzer` | 综合代码上下文分析 |
| `ContextAwarePayloadGenerator` | 根据代码变量名构造针对性测试载荷 |
| `APIEndpointDiscoverer` | 从源码中发现 API 端点 |
| `DataFlowTracer` | Source → Sink 数据流追踪 |

> 使用方式：直接导入即可，若依赖缺失会自动降级为普通扫描模式。

### `ai_analyzer.py` — AI 自动分析模块
将扫描结果交给大模型解读，生成可读的安全报告：

**支持的 AI 提供商：**
| 提供商 | API Key 环境变量 | 默认模型 |
|--------|-----------------|---------|
| Ollama（本地） | 无 | qwen3.6:35b |
| Qwen（通义千问） | `DASHSCOPE_API_KEY` | qwen-max |
| GLM（智谱） | `ZHIPUAI_API_KEY` | glm-4-flash |
| Kimi（月之暗面） | `MOONSHOT_API_KEY` | moonshot-v1-8k |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| SiliconFlow | `SILICONFLOW_API_KEY` | Qwen/Qwen2.5-7B-Instruct |
| Gemini | `GEMINI_API_KEY` | gemini-2.0-flash |
| OpenAI GPT | `OPENAI_API_KEY` | gpt-4.1-mini |
| Claude | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |

### `init.py` / `init_ai.py` — 配置向导
交互式配置工具，自动写入 `config.json`。

---

## 配置说明

所有配置保存在 `config.json` 中：

```jsonc
{
  "scanner": {
    "timeout": 30,           // 请求超时秒数
    "max_depth": 3,          // 爬取最大深度
    "max_pages": 100,        // 最大扫描页面数
    "concurrent": 5,         // 并发线程数
    "user_agent": "...",     // HTTP User-Agent
    "proxy": {               // 代理配置
      "enabled": false,
      "http": "http://127.0.0.1:7890",
      "https": "http://127.0.0.1:7890"
    }
  },
  "ai": {
    "enabled": false,        // 是否启用 AI 分析
    "provider": "ollama",   // 提供商
    "model": "qwen3.6:35b", // 模型名
    "base_url": "http://127.0.0.1:11434",
    "api_key": "",           // API Key（本地模型可留空）
    "temperature": 0.2,      // 创造性（越低越保守）
    "max_tokens": 4096       // 最大输出 Token 数
  },
  "urls": {
    "check_ssl": true,       // SSL/TLS 检查
    "check_headers": true,   // HTTP安全头检查
    "check_cors": true,      // CORS 配置检查
    "check_sqli": true,      // SQL注入检测
    "check_xss": true,       // XSS 检测
    "check_ssrf": true,      // SSRF 检测
    "check_rce": true,       // RCE 检测
    "check_lfi": true,       // LFI 检测
    "enum_subdomains": true, // 子域名枚举
    "dir_busting": { ... }   // 目录爆破配置
  },
  "files": {
    "check_secrets": true,   // 敏感信息泄露检测
    "check_permissions": true,// 文件权限检查
    "check_dependencies": true// 依赖漏洞检测
  }
}
```

---

## 输出报告

扫描完成后，在 `output_dir/` 目录下生成：

### 📄 `report.html` — HTML 可视化报告
- 风险评级卡片（总漏洞数 / 严重 / 高危 / 中危）
- HTTP 响应头完整列表
- 技术栈与子域名展示
- 漏洞详情卡片（颜色编码 severity + CWE + CVSS + 修复建议）
- 发现的目录/路径表格
- **可展开的 JSON 数据区**：点击可查看完整的原始扫描数据

### 📄 `report.json` — JSON 结构化数据
```json
{
  "scan_timestamp": "2024-XX-XX XX:XX:XX",
  "summary": {
    "url_target": "...",
    "risk_level": "🟡 MODERATE",
    "risk_score": 15,
    "severity_breakdown": { "critical": 0, "high": 0, "medium": 2, "low": 5 },
    ...
  },
  "url_findings": [...],     // URL扫描发现的漏洞列表
  "file_findings": [...]     // 文件分析发现的漏洞列表
}
```

### 📄 `ai_report.html` / `ai_report.json` — AI 分析报告（需启用 AI）
- **AI JSON**：完整的 LLM 响应原始文本
- **AI HTML**：Markdown → HTML 渲染的安全分析报告，包含：
  - 风险评估摘要
  - 高/中危漏洞详细分析与修复方案
  - 低危建议表格
  - 下一步渗透测试策略建议

---

## 注意事项

> ⚠️ **本工具仅限授权安全评估使用**
> 
> - 仅在**拥有合法授权**的目标上运行扫描
> - 请遵守相关法律法规和靶场规则
> - 不要对未授权目标进行探测或利用
> - 生产环境测试建议先用 `--deep` 模式在低峰时段执行

### 常见问题

| 问题 | 解决方法 |
|------|---------|
| 依赖安装失败 | 尝试 `pip install --upgrade pip` 后重试 |
| AI 分析无法连接 | 检查 config.json 中的 `base_url` 和 API Key 配置 |
| 目录爆破无结果 | 确认词表文件（common.txt）存在于当前目录 |
| 中文显示乱码 | 设置环境变量 `PYTHONIOENCODING=utf-8` |
