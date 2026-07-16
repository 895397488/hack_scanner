# 🔐 Hack Scanner — 自动化漏洞扫描器

**基于 Shannon 架构的 Web/代码综合安全扫描框架**

> **v8.0 — 修复一些bug，并加入SPA 路由发现，隐藏 API 端点发现，前端框架指纹识别，状态管理检测，Console 日志捕获，控制台输出（含 API key、配置等敏感信息。
> **v7.0 — 修复一些bug。
> **v6.0 — DeepSec Matcher 引擎整合（2026-07）**：从 deepsec (vercel-labs/deepsec) 移植 ~110 条正则规则，支持跨语言漏洞检测、框架门控扫描、自定义规则加载、多匹配器去重 + 置信度提升。
> **v5.1 — 安全加固更新（2026-06）**：全局限速器、危险模式默认关闭、扫描前确认、dry-run 预览，修复 DoS 级别的请求风暴问题。
> **v5.0 — Pentest-Swarm-AI 借鉴更新（2026-06）**：新增 CRLF注入、JWT漏洞、GraphQL安全、子域名接管、云桶枚举、OOB盲注等 10+ 检测能力，引入 Playbook 扫描工作流 + 假阳性缓存机制。
> **v4.0 — w3af 深度整合更新（2026-06）**：新增 XXE、文件上传、反序列化、Blind Timing SQLi、VCS泄露、OpenAPI发现等 14 项检测能力，扫描步骤从 13 → 24 步。

## 📖 目录

- [功能特性](#功能特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [Agent 集成（MCP）](#agent-集成mcp)
- [使用方式](#使用方式)
- [模块说明](#模块说明)
- [配置说明](#配置说明)
- [输出报告](#输出报告)
- [注意事项](#注意事项)
- [更新日志](#更新日志)

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

### Playbook 扫描工作流（Pentest-Swarm-AI Phase 2.3 借鉴）
- **OWASP Top 10 评估**：覆盖全部 OWASP Top 10 类别的自动化扫描
- **Bug Bounty 快速狩猎**：聚焦 IDOR/SSRF/未授权访问等高 ROI 漏洞
- **内部网络评估**：端口、服务、未授权访问全面检测
- **CI/CD 安全检查**：敏感文件泄露和配置错误扫描
- **CTF 解题辅助**：Web CTF 常见漏洞快速检测

### 假阳性缓存（Pentest-Swarm-AI Phase 4.3.4 借鉴）
- 自动记录已确认的误报，避免重复报告
- 支持按目标+漏洞类型配置抑制规则

### AI 自动分析
- **多模型支持**：Ollama（本地）、Qwen、GLM、GPT、Claude 等主流大模型
- **自动解读报告**：将扫描结果转化为可读的安全分析报告
- **下一步建议**：智能推荐后续渗透测试策略

### 可视化报告
- **HTML 报告**：彩色卡片式展示，支持展开查看完整 JSON 数据
- **JSON 数据**：结构化机器可读格式，便于 CI/CD 集成

### DeepSec Matcher 引擎（v5.2 新增）
从 [deepsec (vercel-labs/deepsec)](https://github.com/vercel-labs/deepsec) 移植的 ~110 条正则规则静态分析引擎。

**检测类别：**

| 类别 | 说明 | 示例 |
|------|------|------|
| **通用匹配器** (GENERIC_MATCHERS) | 跨语言漏洞模式，始终运行 | SQL注入、XSS、SSRF、RCE、路径遍历、反序列化、CORS、密钥泄露等 ~15 类 |
| **框架门控匹配器** (FRAMEWORK_MATCHERS) | 基于检测到的技术栈触发 | Express/Fastify/NestJS/Django/Flask/FastAPI/Laravel/Rails/Gin/Echo 等 ~20 框架 |
| **IaC 匹配器** (IAC_MATCHERS) | 基础设施即代码安全 | Dockerfile(特权/根用户/curl管道)、Terraform(IAM宽权限/明文密钥)、GitHub Actions(注入向量) |
| **ORM 匹配器** (ORM_MATCHERS) | ORM raw SQL 注入检测 | Prisma/$queryRawUnsafe、Drizzle raw、SQLAlchemy text()、Django extra()/raw()、Laravel whereRaw |
| **NoSQL 注入检测** | NoSQL 注入模式 | `.find(req)`、`ObjectIds?($gt/$ne)` 等 |

**核心特性：**

- **噪声分层 (Noise Tiers)**：三种精度级别控制误报率
  - `precise` — 高信号/低误报 → severity **high**
  - `normal` — 宽泛模式/AI 消歧 → severity **medium**
  - `noisy` — 入口点覆盖/更全面 → severity **low**
- **多匹配器去重**：同一行被多个 matcher 命中时自动去重，保留最高 severity
- **置信度提升**：同一位置被 ≥2 个不同 matcher 命中的发现自动提升 severity（`high→critical`, `medium→high`）
- **框架门控**：仅当检测到对应技术栈时才触发框架特定规则（如 Django → 检查 CSRF 豁免/DEBUG=True）
- **自定义规则**：通过 `deepsec-custom.json` 加载项目特有 matcher
- **项目上下文注入 (INFO.md)**：从项目上下文文件提取认证原语、威胁模型、已知误报，减少误报

**新增文件：**

| 文件 | 用途 |
|------|------|
| `deepsec_matchers.py` | ~110 条正则规则 + DeepsecMatcherEngine 引擎 |
| `deepsec-info-template.md` | 项目上下文模板（填写后可大幅降低误报） |
| `deepsec-custom-sample.json` | 自定义 matcher 示例，可重命名为 `deepsec-custom.json` 使用 |

---

## 安全机制（v5.1）

### 速率限制（防止 DoS）
- **默认每域名间隔 2 秒**，全局最小间隔 0.5 秒
- 所有请求通过全局包裹器自动限速，无并发风暴
- 配置项：`scanner.rate_limit`

### 危险模式默认关闭
以下操作默认禁用，需 `--unsafe` 或手动开启：

| 危险操作 | 风险等级 | 说明 |
|---------|---------|------|
| Webshell 上传 | ☠️ CRITICAL | 向目标上传 PHP/ASPX 后门并执行命令 |
| 密码暴力破解 | ☠️ CRITICAL | 向登录接口发送大量凭据 POST 请求 |
| 支付篡改测试 | 🔴 HIGH | 修改金额进行负值/零值购买 |
| SQL Sleep DoS | 🔴 HIGH | 注入 `SLEEP()` 导致数据库延迟 |
| SSRF 内网探测 | 🔴 HIGH | 通过 gopher/dict/ldap 协议探测内网服务 |
| HTTP DELETE/PUT | 🟡 MEDIUM | 发送破坏性 HTTP 方法请求 |
| 密码重置邮件触发 | 🟡 MEDIUM | 向任意邮箱发送重置邮件（可能 spam） |

### OOB/盲注入默认启用
以下测试会触发外部回调服务器：

| 模式 | 说明 |
|------|------|
| Blind XSS (OOB) | 注入 JS payload，通过 interact.sh 等外带 cookie |
| Blind SSRF (OOB) | 触发目标服务器向 OOB 域发起请求 |
| Blind RCE (OOB) | 注入命令执行 payload 通过 DNS/HTTP 外泄 |

### CLI 安全控制

```bash
# 预览（不发送任何请求）
python hack_scanner.py --dry-run -u https://example.com

# 默认扫描（自动限速 + 外部域名确认提示）
python hack_scanner.py -u https://example.com

# 启用危险模式（仅用于授权测试）
python hack_scanner.py -u https://example.com --unsafe

# 禁用 OOB/盲注入（降低外连风险）
python hack_scanner.py -u https://example.com --disable-oob

# 启用 DeepSec Matcher 引擎（补充 ~110 条正则规则检测）
python hack_scanner.py -f ./src/ --deepsec-matchers
```

### 交互式危险模式选择菜单

扫描外部域名时，会弹出交互式菜单，逐项显示当前状态：

```text
🔴 危险测试模式（默认关闭）：
  [D1] ⬜ 已禁用 — Webshell 上传测试: 上传 PHP/ASPX 后门并执行命令
  [D2] ⬜ 已禁用 — 密码暴力破解: 向登录接口发送暴力尝试请求
  ...

📡 OOB/盲注入测试（默认启用）：
  [P1] 📡 已启用 — 盲 XSS (OOB): 注入 JS payload 外连回调服务器
  [P2] 📡 已启用 — 盲 SSRF (OOB): 触发服务器向 OOB 域发起请求

📊 当前: 3/11 项启用
输入编号逗号分隔切换 (如 D1,P3)，回车确认。
  选择: _
```

- 输入编号（逗号分隔）切换对应模式开关状态
- 直接回车保持当前配置不变
- `--unsafe` 预设为全部开启，在菜单中可逐条关闭
- `--disable-oob` 预设 OOB 全部关闭，在菜单中可逐条恢复

---

## Pentest-Swarm-AI 借鉴对比矩阵

| 检测能力 | Hack v4.0 | Hack v5.0 | Pentest-Swarm-AI 来源 |
|---|---|---|---|
| CRLF 注入 & HTTP响应拆分 | ❌ | ✅ | Phase 5.11 crlfuzz |
| JWT Token 漏洞 (none-alg/弱密钥) | ❌ | ✅ | Phase 2.1.11 jwt_tool |
| GraphQL 安全 (introspection/batching) | ❌ | ✅ | Phase 5.5 GraphQL |
| HTTP参数污染 (HPP) | ❌ | ✅ | Phase 2.1.13 arjun |
| Subdomain Takeover (40+服务探测) | ❌ | ✅ | Phase 5.6.1 |
| 云存储桶暴露 (S3/GCS/Azure) | ❌ | ✅ | Phase 5.6.2 |
| OOB盲注 (Blind XSS/SSRF/RCE) | ❌ | ✅ | Phase 5.8 interact.sh |
| HTTP请求走私 (CL.TE/TE.CL) | ❌ | ✅ | Phase 5.11.1 |
| Web Cache Poisoning | ❌ | ✅ | Phase 5.11.4 |
| Playbook 扫描工作流 | ❌ | ✅ | Phase 2.3 |
| FP假阳性缓存 | ❌ | ✅ | Phase 4.3.4 |
| OSINT (Shodan/Censys/GitHub) | ❌ | 🔲 预留 | Phase 6.7 |
| Nuclei 模板引擎集成 | ❌ | 🔲 预留 | Phase 2.1 nuclei |

> ✅ = 已完成, 🔲 = 规划中（保留接口，后续通过二进制工具集成）

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

# **启用 DeepSec Matcher 引擎**（~110条正则规则补充检测）
python hack_scanner.py --file ./src/ --deepsec-matchers
```
# 使用脚本
scan_URL_Files.bat

---

## Agent 集成（MCP）

Hack Scanner 提供 **MCP (Model Context Protocol) Server**，支持 Claude Code、Cursor、Windsurf、OpenClaw、Codex 等主流 AI agent 直接调用。

### MCP 暴露的工具（21个）

| # | 工具名 | 功能 | 依赖 | 安装命令 |
|---|--------|------|------|---------|
| 1 | `url_scan` | URL OWASP Top 10 漏洞扫描 | — | — |
| 2 | `file_analyze` | 代码 SAST（敏感信息/密钥/注入） | — | — |
| 3 | `subdomain_takeover_check` | 子域名接管（Dangling CNAME） | dnspython | 已有 |
| 4 | `cloud_bucket_enum` | 云桶枚举（S3/GCS/Azure） | — | — |
| 5 | `waf_detect` | WAF/IPS 检测（100+产品识别） | wafw00f | pip install wafw00f |
| 6 | `sql_exploit` | SQLi 自动化利用 + DB指纹 | sqlmap | pip install sqlmap |
| 7 | `web_fuzz` | 路径/参数模糊测试（ffuf） | ffuf | go install / apt / brew |
| 8 | `osint_recon_tool` | OSINT：IP/WHOIS/Shodan API 侦察 | shodan, whois | pip install shodan whois |
| 9 | `ssl_deep_scan_tool` | SSL/TLS 深度分析（协议/密码套件/CVE） | sslyze | pip install sslyze |
| 10 | `network_scan_tool` | masscan+nmap 端口扫描 + 主机发现 | python-nmap(已有)+masscan | apt/brew/choco install masscan |
| 11 | `file_meta_tool` | 文件元数据+隐写（EXIF/Office/PDF） | exifread, whois | pip install exifread |
| 12 | `domain_typosquat` | 域名混淆/钓鱼检测（typosquatting/homograph） | rapidfuzz(已有) | — |
| 13 | `dns_recon_tool` | DNS 区域转移 (AXFR) + 所有记录查询 | dnspython(已有) | — |
| 14 | `cve_lookup` | CVE 漏洞查询（NVD API） | urllib(stdlib) | — |
| 15 | `webshell_detect` | Webshell/后门文件检测（PHP/ASP/JSP/Python） | — | — |
| 16 | `cert_monitor_tool` | SSL/TLS 证书透明度监控 + 被动子域名枚举 | urllib(stdlib) | — |
| **17** | **`zap_scan_tool`** | **OWASP ZAP Spider+ActiveScan（浏览器自动化）** | zaproxy(已有)+docker | pip install zaproxy |
| **18** | **`git_secret_scan`** | **Git 仓库密钥泄露检测（Gitleaks）** | gitleaks | go install github.com/...gitleaks/v2@latest |
| **19** | **`nuclei_scan_tool`** | **Nuclei 模板驱动漏洞扫描（6000+模板）** | nuclei | go install github.com/...nuclei/v2/cmd/nuclei@latest |
| **20** | **`gobuster_tool`** | **GoBuster dir/VHost/DNS 多模式爆破** | gobuster | go install github.com/OJ/gobuster/v3@latest |
| **21** | **`hydra_scan_tool`** | **密码暴力破解测试（SSH/FTP/HTTP等50+协议）** | hydra | apt install hydra / brew install theharvester |
| **17** | **`zap_scan_tool`** | **OWASP ZAP Spider+ActiveScan（浏览器自动化）** | zaproxy(已有)+docker | pip install zaproxy |
| **18** | **`git_secret_scan`** | **Git 仓库密钥泄露检测（Gitleaks）** | gitleaks | go install github.com/...gitleaks/v2@latest |
| **19** | **`nuclei_scan_tool`** | **Nuclei 模板驱动漏洞扫描（6000+模板）** | nuclei | go install github.com/...nuclei/v2/cmd/nuclei@latest |
| **20** | **`gobuster_tool`** | **GoBuster dir/VHost/DNS 多模式爆破** | gobuster | go install github.com/OJ/gobuster/v3@latest |
| **21** | **`hydra_scan_tool`** | **密码暴力破解测试（SSH/FTP/HTTP等50+协议）** | hydra | apt install hydra / brew install theharvester |

### Claude Code

在 `~\.claude\settings.json` 中添加：

```jsonc
{
  "mcpServers": {
    "hack_scanner": {
      "command": "python",
      "args": ["C:\Users\Administrator\hack_scanner\mcp_server.py"],
      "cwd": "C:\Users\Administrator\hack_scanner"
    }
  }
}
```
args和cwd的值请根据hack_scanner的实际路径填写
然后直接在聊天中说 **"扫描 https://example.com"**，agent 会自动发现并调用工具。

### Cursor / Windsurf

在编辑器设置中找到 MCP Servers 配置，添加：

| 字段 | 值 |
|------|-----|
| **Transport** | `stdio` |
| **Command** | `python` |
| **Args** | `C:\Users\Administrator\hack_scanner\mcp_server.py` |
| **Working Directory** | `C:\Users\Administrator\hack_scanner` |

### 通用 MCP Client（CLI）

任何支持 MCP stdio transport 的客户端：

```jsonc
{
  "mcpServers": {
    "hack_scanner": {
      "command": "python",
      "args": ["C:\Users\Administrator\hack_scanner\mcp_server.py"]
    }
  }
}
```

### Linux / WSL

```jsonc
{
  "mcpServers": {
    "hack_scanner": {
      "command": "python3",
      "args": ["/home/yourname/hack_scanner/mcp_server.py"],
      "cwd": "/home/yourname/hack_scanner"
    }
  }
}
```

### Agent 调用示例

配置完成后，agent 可以直接使用这些自然语言指令：

| 自然语言指令 | 调用的工具 |
|---|---|
| "扫描这个 URL: https://example.com/admin?id=1" | `url_scan` |
| "分析这段代码的安全问题 ./src/" | `file_analyze` |
| "检查 example.com 的子域名接管风险" | `subdomain_takeover_check` |
| "枚举 example.com 的云存储桶" | `cloud_bucket_enum` |
| "检测 target.com 的 WAF" | `waf_detect` |
| "利用 /page?id=1 的 SQLi" | `sql_exploit(url, param="id")` |
| "模糊测试 https://example.com/ 的路径" | `web_fuzz(target, fuzz_type="paths")` |
| "侦察 example.com（OSINT）" | `osint_recon_tool(domain)` |
| "深度 SSL/TLS 分析" | `ssl_deep_scan_tool(url)` |
| "扫描 192.168.1.0/24 的网络和端口" | `network_scan_tool(target)` |
| "分析 photo.jpg 的元数据和隐写" | `file_meta_tool(path, stego=True)` |
| "检测 google.com 的钓鱼域名变种" | `domain_typosquat(domain="google.com")` |
| "侦察 example.com 的 DNS 记录" | `dns_recon_tool(domain="example.com")` |
| "查询 CVE-2024-1234 详情" | `cve_lookup(query_type="cve", cve_id="CVE-2024-1234")` |
| "查 apache httpd 2.4.49 的 CVE" | `cve_lookup(query_type="package", vendor="apache", product="httpd", version="2.4.49")` |
| "扫描 upload/ 目录的 Webshell" | `webshell_detect(path="./upload/")` |
| "监控 example.com 的证书信息" | `cert_monitor_tool(domain="example.com")` |
| "ZAP 全面扫描 https://example.com" | `zap_scan_tool(url)` |
| "分析 repo 的 Git 密钥泄露" | `git_secret_scan(repo_path="./my-repo")` |
| "用 Nuclei 扫描 example.com" | `nuclei_scan_tool(target="https://example.com")` |
| "GoBuster dir 爆破 example.com/" | `gobuster_tool(target, mode="dir")` |
| "SSH 暴力破解测试 10.0.0.1" | `hydra_scan_tool(target="10.0.0.1", service="ssh")` |

### 安装依赖

**全部 pip 依赖（一行命令）：**
```bash
pip install -r requirements.txt
```

**可选 CLI 工具（按需安装）：**
```bash
# sqlmap — SQLi 自动化利用
pip install sqlmap

# ffuf — Web 模糊测试
go install github.com/ffuf/ffuf/v2@latest   # or apt/brew/choco install ffuf

# masscan — 极速端口扫描
apt install masscan                          # Ubuntu/Debian
brew install masscan                         # macOS
choco install masscan                        # Windows Scoop
# https://github.com/robertdavidgraham/masscan

# nmap — 网络扫描（大多数系统自带）
apt install nmap   / brew install nmap   / choco install nmap

# Shodan API Key — OSINT 侦察（免费注册）
# https://account.shodan.io/account

# ZAP Docker — OWASP ZAP 自动化扫描
docker run -d --name zap -p 8090:8090 ghcr.io/zaproxy/zaproxy:stable

# Gitleaks — Git 密钥泄露检测
go install github.com/zricethezav/gitleaks/v2@latest

# Nuclei — 模板驱动漏洞扫描
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# GoBuster — dir/VHost/DNS 爆破
go install github.com/OJ/gobuster/v3@latest

# Hydra — SSH/FTP 密码暴力破解测试
apt install hydra   / brew install theharvester   / choco install hydra
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
| `--deepsec-matchers` | **启用 DeepSec Matcher 引擎**（~110条正则规则） | `-f ./src/ --deepsec-matchers` |
| `-o, --output` | 报告输出目录（默认：当前目录/hack_report） | `-o ./reports/` |
| `--deep` | 深度扫描模式（更慢但更全面） | `--deep` |
| `--proxy` | HTTP/SOCKS5 代理地址 | `--proxy http://127.0.0.1:7890` |
| `--dry-run` | **预览测试，不发送任何请求** | `--dry-run --url URL` |
| `--unsafe` | **启用危险模式（覆盖 config.json）** | `--unsafe --url URL` |
| `--disable-oob` | **禁用 OOB/盲注入外部回调** | `--disable-oob --url URL` |

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
| **未授权访问** | 敏感路径匿名探测（200+JSON/API端点） |
| **越权访问(IDOR)** | ID参数替换/路径ID遍历 + 数组对比 |
| **CSRF** | Token缺失/SameCookie/跨域凭证检测 |
| **密码重置** | Token强度/枚举性/CSRF保护检查 |

### `file_analyzer.py` — 代码文件扫描器
分析源码中的安全风险，**支持 DeepSec Matcher 引擎补充检测**：

```python
from file_analyzer import analyze_file_or_dir, FileAnalyzer

# 基础扫描
findings = analyze_file_or_dir('./my-project/')

# 启用 DeepSec Matcher 引擎（~110条正则规则）
analyzer = FileAnalyzer('./my-project/', deepsec_enabled=True)
findings = analyzer.analyze()
summary = analyzer.get_deepsec_summary()
# {'enabled': True, 'total_findings': N, 'categories': {...}}
```

**检测能力：**
- **敏感信息**：正则匹配密钥/密码/API Key 模式
- **文件权限**：检查可写目录和敏感配置文件的访问控制
- **依赖安全**：匹配 CVE 数据库中的已知漏洞
- **语言分析**：自动识别 Python/JS/PHP/Java/YAML 并应用针对性规则
- **DeepSec Matcher（可选）**：~110条跨语言正则规则，覆盖 SQLi/XSS/SSRF/RCE/IaC 等

### `deepsec_matchers.py` — DeepSec Matcher 引擎（v5.2 新增）
从 [deepsec (vercel-labs/deepsec)](https://github.com/vercel-labs/deepsec) 移植的静态分析引擎：

```python
from deepsec_matchers import (
    DeepsecMatcherEngine, NOISE_TIER_LABEL, set_project_context
)

engine = DeepsecMatcherEngine('./my-project/')
engine.detect_technologies()   # 框架门控（package.json/requirements.txt/...）
set_project_context('deepsec-info.md')  # 项目上下文注入，减少误报
findings = engine.scan(noise_tiers=['precise', 'normal'], dedup=True)
```

**核心特性：**
- **噪声分层**：`precise`(高信号→high) / `normal`(AI消歧→medium) / `noisy`(全覆盖→low)
- **多匹配器去重**：同一行被不同 matcher 命中时保留最高 severity，避免重复报告
- **置信度提升**：同一位置 ≥2 个 matcher 命中 → 自动提升 severity
- **自定义规则**：`deepsec-custom.json` 加载项目特有检测

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

### `deepsec_matchers.py` — DeepSec Matcher 引擎（v5.2 新增）
从 deepsec 移植的 ~110 条正则规则引擎，用于代码文件静态分析补充检测：

```python
from deepsec_matchers import (
    DeepsecMatcherEngine, NOISE_TIER_LABEL, set_project_context
)

# 初始化并自动检测技术栈
engine = DeepsecMatcherEngine('./my-project/')
engine.detect_technologies()   # 扫描 package.json/requirements.txt/composer.json...

# 加载项目上下文（减少误报）
set_project_context('deepsec-info.md')

# 运行扫描（指定噪声层级，默认 ['precise', 'normal']）
findings = engine.scan(noise_tiers=['precise', 'normal'], dedup=True)

# 获取统计摘要
print(f"发现 {len(findings)} 条潜在问题")
```

**自定义规则加载**：在项目目录放置 `deepsec-custom.json`，引擎启动时自动加载：

```jsonc
{
  "custom_matchers": [
    {
      "slug": "my-custom-check",
      "noise_tier": "precise",
      "description": "项目特有检测规则",
      "patterns": [["your-regex-here", 0]]
    }
  ]
}
```

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
    },
    "rate_limit": {          // 速率限制（防止 DoS）
      "enabled": true,       // 默认启用
      "per_domain_sec": 2.0, // 每域名最小间隔（秒）
      "global_min_sec": 0.5  // 全局最小请求间隔（秒）
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
    "check_secrets": true,          // 敏感信息泄露检测
    "check_permissions": true,      // 文件权限检查
    "check_dependencies": true,     // 依赖漏洞检测
    "deepsec_matchers": true,       // **DeepSec Matcher 引擎开关**（v5.2）
    "deepsec_noise_tiers": ["precise", "normal"],  // 噪声层级（可选"noisy"）
    "deepsec_info_path": "",        // 项目上下文文件路径（减少误报）
    "deepsec_custom_matchers": "deepsec-custom.json"  // 自定义规则文件名
  },
  "safety": {                  // 安全控制（v5.1 新增）
    "confirm_external_scan": true,
    "max_requests_per_domain": 50,
    "dangerous_modes": {
      "webshell_upload": false,
      "brute_force_password": false,
      "payment_tampering": false,
      "sql_sleep_dos": false,
      "ssrf_internal_probes": false,
      "http_delete_put": false,
      "password_reset_trigger": false,
      "dns_nuke": false
    }
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
- **AI HTML**：Markdown → HTML 渲染的安全分析报告，**严格遵循 SRC 报告标准格式**：

| 章节 | 内容 |
|------|------|
| 风险评估摘要 | 总体评价 + 关键发现清单 + 数据量级评估 |
| 高危漏洞详情 | 逐条按 SRC 6段式输出（漏洞信息→复现步骤→PoC→影响证明→修复建议→验证方法） |
| 低危/建议项 | 批量列出 Low/Info 级别及修复建议 |
| 下一步扫描策略 | 针对深层风险的建议（含具体工具命令） |

**高危漏洞报告标准格式：**
```
🔴【漏洞信息】        ← 标题/URL/类型/CVSS
📝【复现步骤】         ← 编号步骤，任何人可100%复现
💻【PoC / HTTP原文】   ← curl/Burp可直接使用的请求
💥【影响证明】         ← 实际危害证据（非理论可能）
🛠【修复建议】         ← 具体到代码/配置级别
🧪【验证方法】         ← 测试人员验收标准
```

### 🎯 Playbook 扫描工作流

v5.0 新增 **Playbook** 系统，可将不同场景的扫描配置打包为可复用模板（借鉴 Pentest-Swarm-AI playbook 系统）。

**内置 Playbook：**

| Playbook | 用途 | 适用场景 |
|---|---|---|
| `owasp-top10` | 全面OWASP Top 10评估 | 定期安全审计 |
| `bug-bounty` | Bug Bounty 快速狩猎 | 高ROI漏洞探测（IDOR/SSRF/未授权） |
| `internal-network` | 内部网络评估 | 内网安全巡检 |
| `ci-cd-security` | CI/CD安全检查 | 敏感文件泄露检测 |
| `ctf-solver` | CTF解题辅助 | Web CTF快速扫描 |

**使用自定义 Playbook：**
```python
from scanners.playbooks import PlaybookRunner, FPFalsePositiveCache

# 列出所有可用 playbook
playbooks = PlaybookRunner.list_playbooks()

# 加载并应用 Bug Bounty playbook
pb = PlaybookRunner.get_playbook('bug-bounty')
new_config = PlaybookRunner.apply_to_config(pb, current_config)

# 从自定义 JSON 文件加载
custom_pb = PlaybookRunner.load_custom_playbook('my-playbook.json')
```

---

## 注意事项

> ⚠️ **本工具仅限授权安全评估使用**
> 
> - 仅在**拥有合法授权**的目标上运行扫描
> - 请遵守相关法律法规和靶场规则
> - 不要对未授权目标进行探测或利用
> - 生产环境测试建议先用 `--deep` 模式在低峰时段执行

## 更新日志

### v5.0 — Pentest-Swarm-AI 借鉴更新（2026-06）
**核心来源：[Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI)**

新增完全缺失的 10+ 项检测能力：
- **CRLF 注入检测** (借鉴 Phase 5.11 crlfuzz adapter) — HTTP响应拆分、Cookie注入
- **JWT Token 漏洞** (借鉴 Phase 2.1.11 jwt_tool adapter) — none-alg/弱密钥/kid注入
- **GraphQL 安全测试** (借鉴 Phase 5.5) — introspection暴露/batching攻击
- **HTTP参数污染** (借鉴 Phase 2.1.13 arjun adapter) — 同名参数多次发送探测
- **子域名接管** (借鉴 Phase 5.6.1) — 40+ DNS CNAME dangling服务检测
- **云存储桶暴露** (借鉴 Phase 5.6.2) — S3/GCS/Azure bucket枚举
- **OOB盲注检测** (借鉴 Phase 5.8 interact.sh) — Blind XSS/SSRF/RCE外带信道
- **HTTP请求走私** (借鉴 Phase 5.11.1) — CL.TE/TE.CL patterns
- **Web Cache Poisoning** (借鉴 Phase 5.11.4) — CDN缓存投毒检测

新增架构特性：
- **Playbook 扫描工作流** (借鉴 Phase 2.3) — OWASP/BugBounty/Internal等预置模板
- **FP假阳性缓存** (借鉴 Phase 4.3.4) — 避免重复报告已知误报

配置新增选项（config.json `urls` 部分）：
```json
"check_crlf_injection": true,       // CRLF注入检测
"check_jwt_vulnerability": true,    // JWT漏洞检测
"check_subdomain_takeover": true,   // 子域名接管检测
"check_graphql_security": true,     // GraphQL安全测试
"check_http_param_pollution": true, // HTTP参数污染检测
"check_oob_blind_xss": true,        // OOB盲XSS检测
"check_oob_blind_ssrf": true,       // OOB盲SSRF检测
"check_oob_blind_rce": true,        // OOB盲RCE检测
```

---

### v5.1 — 安全加固更新（2026-06）
**修复：扫描器曾导致目标网站 HTTP/2 协议栈崩溃（ERR_HTTP2_PROTOCOL_ERROR）**

新增防护机制：
- **全局限速器** (`rate_limiter.py`)：默认每域名间隔 2s，全局最小 0.5s
- **危险模式默认关闭**：Webshell上传、暴力破解、支付篡改等全部禁用
- **扫描前确认**：外部域名扫描需手动输入 y 继续
- **`--dry-run` 预览模式**：列出所有测试项，不发送任何请求
- **CLI 安全控制**：`--unsafe` / `--disable-oob` 命令行开关

配置新增选项（config.json 根目录）：
```jsonc
{
  "scanner": {
    "rate_limit": {
      "enabled": true,        // 限速器开关
      "per_domain_sec": 2.0,  // 每域名最小间隔（秒）
      "global_min_sec": 0.5   // 全局最小间隔（秒）
    }
  },
  "safety": {
    "confirm_external_scan": true,     // 外部域名扫描前确认
    "dangerous_modes": {               // 危险模式（全部默认 false）
      "webshell_upload": false,
      "brute_force_password": false,
      "payment_tampering": false,
      "sql_sleep_dos": false,
      "ssrf_internal_probes": false,
      "http_delete_put": false,
      "password_reset_trigger": false,
      "dns_nuke": false
    }
  }
}
```

---

### v6.0 — DeepSec Matcher 引擎整合（2026-07）
**核心来源：[deepsec (vercel-labs/deepsec)](https://github.com/vercel-labs/deepsec) v2.1.2**

新增 ~110 条正则规则，覆盖 5 大类检测：

| 类别 | 规则数 | 说明 |
|------|--------|------|
| `GENERIC_MATCHERS` | ~85  | SQLi/XSS/SSRF/RCE/路径遍历/反序列化/CORS/密钥泄露等 15 跨语言模式 |
| `FRAMEWORK_MATCHERS` | ~20 | 基于技术栈门控：Express/Django/Flask/FastAPI/Laravel/Rails/Gin 等 |
| `IAC_MATCHERS` | ~8 | Dockerfile/Terraform/GitHub Actions 安全检测 |
| `ORM_MATCHERS` | ~6 | Prisma/Drizzle/SQLAlchemy/Django/Laravel raw SQL 注入 |
| NoSQL 注入 | ~3 | MongoDB find() 直接合并、ObjectId 注入 |

**新增核心能力：**
- **噪声分层**：`precise`（高信号）/ `normal`（AI消歧）/ `noisy`（全覆盖），默认 `[precise, normal]`
- **多匹配器去重 + 置信度提升**：同一行被 ≥2 matcher 命中时自动提升 severity
- **自定义规则**：`deepsec-custom.json` 加载项目特有检测
- **INFO.md 项目上下文注入**：减少误报，增强信号

**新增文件：** `deepsec_matchers.py` / `deepsec-info-template.md` / `deepsec-custom-sample.json`

**配置新增选项（config.json `files` 部分）：**
```json
"deepsec_matchers": true,            // DeepSec 引擎开关
"deepsec_noise_tiers": ["precise", "normal"],  // 噪声层级
"deepsec_info_path": "",             // 项目上下文文件路径
"deepsec_custom_matchers": "deepsec-custom.json"  // 自定义规则文件名
```
# hack_scanner v8.0 — Acunetix v25 模块升级指南

## 概述

本版本从 [Acunetix v25](https://www.acunetix.com/)（Invicti/Web Security Scanner）借鉴了多个核心模块的概念与实现，在不破坏现有功能的前提下，增强了 hack_scanner 的以下能力：

- **主动 WAF/CDN/IPS 感知** — 类似 AcuSensor 的探针机制
- **Headless Browser JS 渲染** — 类似 Acunetix Chromium 引擎的深度扫描
- **分布式扫描集群** — 类似 apihub + NATS 的消息驱动架构
- **精确域名解析** — 基于 Acunetix 的 public_suffix_list.dat (13626+ 条记录)

## ⚠️ 重要声明

本升级**仅借鉴 Acunetix 的模块设计理念与公开功能概念**，不复制 Acunetix 的任何专有代码、规则集或商业内容。所有新模块均为 hack_scanner 原生 Python 实现。

---

## 新增模块清单

### 1. `scanners/acusensor_sensor.py` — AcuSensor-Style WAF 感知传感器

**来源：** Acunetix AcuSensor / sensor-bridge.exe

| 功能 | 说明 |
|------|------|
| WAF 深度指纹识别 | 50+ WAF 产品检测（Cloudflare, Akamai, Imperva, ModSecurity...） |
| CDN 边缘节点检测 | 识别 Cloudflare、Akamai、Fastly 等 CDN 及 Edge IP |
| 敏感请求头注入探测 | 测试 WAF 是否拦截/篡改 X-Forwarded-For、User-Agent 等头部 |
| Cookie 篡改检测 | 注入 XSS/命令注入探针到 Cookie，检测 WAF 的响应修改行为 |
| 参数探针注入分析 | 模拟 AcuSensor 探针（HTTP/XSS/SQLi/LFI），判断是否被过滤 |
| 服务器技术栈指纹识别 | Web 服务器（Nginx/Apache/IIS/Tomcat）、框架（Express/Django/Spring...） |
| 传感器绕过可能性评估 | 根据探测结果综合评估 WAF 可绕过性 |

**使用方式：**
```python
from scanners.acusensor_sensor import AcusensorSensor, detect_with_sensor

# 完整探测
sensor = AcusensorSensor()
result = sensor.detect("https://target.com")
print(result['wafs_detected'])        # → ['Cloudflare']
print(result['cdn_detected'])         # → {'is_cdn': True, 'cdn_providers': ['Cloudflare']}
print(result['server_bypass_possible'])  # → True/False

# 快捷方式
result = detect_with_sensor("https://target.com")
```

### 2. `scanners/js_render_scanner.py` — Headless Browser JS 渲染引擎

**来源：** Acunetix Chromium 引擎

| 功能 | 说明 |
|------|------|
| SPA 路由发现 | React Router / Vue Router / Angular 路由提取 |
| 隐藏 API 端点发现 | XHR/Fetch/Ajax 请求 URL 提取 |
| 前端框架指纹识别 | React/Vue/Angular/Next.js/Nuxt/Svelte/Gatsby/Remix... |
| 状态管理检测 | Redux/Vuex/MobX/NgRx/Pinia/Zustand |
| Console 日志捕获 | Headless Browser 控制台输出（含 API key、配置等敏感信息） |
| CSP/NSP 策略分析 | 内容安全策略与 nonce 配置检查 |

**使用方式：**
```python
from scanners.js_render_scanner import JSRenderScanner, render_js_page

# 完整扫描
scanner = JSRenderScanner()  # 自动选择 selenium/playwright 或 HTTP+JS 回退
result = scanner.render_and_analyze("https://app.example.com")
print(result['frameworks_detected'])   # → ['React', 'Redux']
print(result['api_endpoints_found'])   # → ['/api/users', '/api/auth/login']
print(result['spa_routes_found'])      # → ['/dashboard', '/settings/profile']

# 快捷方式（无浏览器时自动回退到 HTTP+JS 源码分析）
result = render_js_page("https://app.example.com")
```

### 3. `scanners/distributed_messaging.py` — NATS-Style 分布式扫描协调器

**来源：** Acunetix apihub + nats-server

| 功能 | 说明 |
|------|------|
| Topic-based 消息路由 | 20+ 预定义主题（端口扫描、SSL检查、WAF检测等） |
| 本地内存消息总线 | 无需外部 NATS 服务器，纯 Python 实现 |
| 动态工作节点管理 | spawn/remove/heartbeat 生命周期控制 |
| 集群健康状态监控 | 空闲/忙碌/离线统计 + 心跳延迟 |
| 紧急停止机制 | 一键停止所有扫描任务 |

**使用方式：**
```python
from scanners.distributed_messaging import ScanCluster, ScanTopic

# 创建集群并启动工作节点
cluster = ScanCluster(max_workers=8)
cluster.spawn_workers(4, capabilities=['subdomain_enum', 'waf_detect'])

# 分发扫描任务
task_id = cluster.distribute_task(
    topic=ScanTopic.SUBDOMAIN_ENUM.value,
    task_data={'command': 'enum_subdomains', 'target': 'example.com'},
)

# 收集结果
results = cluster.collect_results(ScanTopic.SUBDOMAIN_ENUM.value, timeout=60)
health = cluster.get_cluster_health()  # → {'idle': 3, 'busy': 1, ...}
```

### 4. `scanners/domain_util.py` + `data/tld/public_suffix_list.dat` — 精确域名解析器

**来源：** Acunetix data/tld/public_suffix_list.dat (13626+ 条记录)

| 功能 | 说明 |
|------|------|
| 注册域名提取 | www.example.co.uk → example.co.uk（区分受限/开放 TLD） |
| 子域名关系验证 | sub.example.com is_subdomain_of(example.com) → True |
| 公共后缀检测 | .com/.co.uk/.ac.uk 等 13626+ 条 PSL 规则 |
| 通配符支持 | *.sch.uk 等通配符规则解析 |

**使用方式：**
```python
from scanners.domain_util import parse_domain, is_subdomain_of, get_psl

base = parse_domain('www.sub.example.co.uk')     # → 'co.uk' (受限 TLD)
base2 = parse_domain('mail.google.com')          # → 'google.com' (开放 TLD)
is_child = is_subdomain_of('sub.example.co.uk', 'co.uk')  # → True

psl = get_psl()  # 全局单例
registrable = psl.get_registrable_domain('www.deep.nested.sch.uk')  # → 'sch.uk'
```

---

## 模块对比矩阵

| 能力 | hack_scanner v6.0 | Acunetix v25 | v7.0 新能力 |
|------|------------------|--------------|------------|
| WAF 检测 | wafw00f (被动) | AcuSensor (主动探针+指纹) | ✅ **主动WAF探测（50+产品）** |
| JS渲染扫描 | ❌ | Chromium 引擎 | ✅ **Selenium/Playwright + HTTP回退** |
| CDN识别 | 无 | server header分析 | ✅ **Edge IP + CDN header 检测** |
| 分布式扫描 | concurrent threads | apihub + NATS | ✅ **Topic-based 消息队列集群** |
| 精确域名解析 | tldextract (可选) | public_suffix_list.dat | ✅ **13626条 PSL 规则内置支持** |
| Cookie安全检测 | ❌ | AcuSensor cookie tamper | ✅ **Cookie注入探针分析** |
| 请求头过滤检测 | ❌ | sensor-bridge analysis | ✅ **WAF header mangle 检测** |
| SPA路由发现 | ❌ | Chromium JS rendering | ✅ **React/Vue/Angular/Nuxt/Svelte** |
| 隐藏API端点 | ❌ | Chromium network monitoring | ✅ **XHR/Fetch/Console日志提取** |

---

## 配置扩展

新增 `acunetix` 配置段（config.json）：

```json
{
  "acunetix": {
    "acu_sensor": {
      "enabled": false,
      "deep_fingerprint": true,
      "cookie_tamper_test": true,
      "header_injection_test": true,
      "sensitive_param_probe": true
    },
    "js_renderer": {
      "enabled": false,
      "engine": "selenium",
      "timeout": 30,
      "skip_if_no_browser": true
    },
    "distributed": {
      "enabled": false,
      "max_workers": 8,
      "collect_timeout": 60
    },
    "tld_list": {
      "enabled": true,
      "path": "data/tld/public_suffix_list.dat"
    }
  }
}
```

---

## 兼容性

- ✅ **零破坏**：所有 hack_scanner v6.0 功能完整保留
- ✅ **渐进式启用**：新模块默认禁用（config.json），按需开启
- ✅ **优雅降级**：JS渲染引擎在无浏览器时回退到 HTTP+JS 源码分析
- ✅ **零额外依赖**：domain_util 和 acusensor_sensor 无需任何外部库
- ⚠️ **可选依赖**：js_render_scanner 需 selenium/playwright（可选安装）

## 文件变更清单

| 类型 | 文件 | 说明 |
|------|------|------|
| 🆕 新增 | `scanners/acusensor_sensor.py` | AcuSensor WAF 感知传感器 (480+行) |
| 🆕 新增 | `scanners/js_render_scanner.py` | JS渲染引擎 + SPA端点发现 (350+行) |
| 🆕 新增 | `scanners/distributed_messaging.py` | 分布式扫描集群协调器 (340+行) |
| 🆕 新增 | `scanners/domain_util.py` | PSL精确域名解析器 (180+行) |
| ➕ 扩展 | `scanners/__init__.py` | 导出所有新模块 + ACUNETIX_MODULES 清单 |
| ✅ 复制 | `data/tld/public_suffix_list.dat` | Acunetix TLD 列表 (13626行) |
| ✏️ 修改 | `config.json` | 新增 acunetix 配置段 |

---

### 常见问题

| 问题 | 解决方法 |
|------|---------|
| 依赖安装失败 | 尝试 `pip install --upgrade pip` 后重试 |
| AI 分析无法连接 | 检查 config.json 中的 `base_url` 和 API Key 配置 |
| 目录爆破无结果 | 确认词表文件（common.txt）存在于当前目录 |
| 中文显示乱码 | 设置环境变量 `PYTHONIOENCODING=utf-8` |

---
