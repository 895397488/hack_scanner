# 🔐 Hack Scanner — Python 原生综合漏洞扫描框架

---

## 系统架构

```
┌─────────────────────────────────────────────────┐
│            launcher.py (交互式菜单)                │
│          hack_scanner.py (主扫描引擎)              │
│          url_scanner.py  (URL/文件扫描核心)         │
│          ai_analyzer.py  (AI 自动分析报告)          │
├─────────────────────────────────────────────────┤
│                  核心库层                          │
│   mcp_server.py │ rate_limiter.py │ init_ai.py    │
│   shannon_context.py (上下文感知 payload 生成)      │
├─────────────────────────────────────────────────┤
│           scanners/ 扫描器集合 (68 模块)           │
│  ┌───────────┬────────────┬───────────┬────────┐ │
│  │ 基础检测    │ Acunetix   │ w3af     │ Swarm AI│ │
│  │ CRLF/ JWT │ acu_sensor │ pii_grep │orchestrator││
│  │ SSRF/XSS  │ js_renderer│ bloom    │prompts   │ │
│  │ subdomain │ distributed│ timing   │dedup     │ │
│  │ graphql   │ domain_util│ payload  │recon_parser││
│  └───────────┴────────────┴───────────┴────────┘ │
│  ┌───────────┬────────────┬───────────┬────────┐ │
│  │扩展扫描器   │高级功能      │Playbook    │训练系统│ │
│  │nmap/hydra │auth_session │playbooks   │classifier││
│  │zap/nuclei │waf_bypass  │LLM引擎     │training │ │
│  │gobuster/ssl│export_engine│SSO测试     │legacy   │ │
│  └───────────┴────────────┴───────────┴────────┘ │
├─────────────────────────────────────────────────┤
│              数据/配置层                           │
│   data/tld/ (13626+ TLD规则)                     │
│   config.json │ deepsec_custom.json              │
└─────────────────────────────────────────────────┘
```

---

## 功能特性

### Web URL 扫描（黑盒）

| 类别 | 能力 | 模块 |
|------|------|------|
| **SQL 注入** | Union/Blind/Timing/Boolean-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) | `url_scanner`, `sql_exploit`, `w3af_vuln_patterns`, `w3af_timing_detector` |
| **XSS** | 反射型/存储型/DOM-based，含 payload 变异引擎（8 种编码技术） | `url_scanner`, `w3af_payload_engine` |
| **SSRF** | 内网探测/云元数据访问/重定向攻击检测 | `url_scanner`, `oob_detector` |
| **RCE / LFI / XXE** | 命令注入、路径遍历、XML 外部实体注入 | `url_scanner`, `w3af_vuln_patterns` |
| **CSRF / CORS** | Token 缺失检测、跨域资源共享错误配置 | `url_scanner` |
| **反序列化** | Java/PHP/Pickle/ObjectSerializer 漏洞检测 | `url_scanner` |
| **文件上传** | Webshell 检测 + 上传点测试 | `url_scanner`, `webshell_detector` |
| **SSL/TLS** | 过期证书、弱密码套件、SNI、OCSP stapling (通过 sslyze) | `ssl_deep_scan` |
| **HTTP 安全头** | CSP/X-Frame-Options/Referrer-Policy/HSTS 等缺失告警 | `url_scanner` |
| **技术栈指纹** | 服务器环境、框架、CDN、前端框架（React/Vue/Angular/Next.js） | `domain_util`, `js_render_scanner` |

### Acunetix v25 能力迁移

| 能力 | 说明 | 模块 |
|------|------|------|
| **AcuSensor WAF 感知** | 主动探测 WAF/CDN/IPS（50+ 产品指纹），模拟多语言探针部署 | `acuser_sensor` |
| **JS 渲染引擎** | Headless Browser (Selenium/Playwright) 渲染 SPA，发现隐藏 API 端点 | `js_render_scanner`, `crawler` |
| **前端框架识别** | React/Vue/Angular/Next.js/Nuxt/Svelte + 状态管理 (Redux/Vuex/Pinia/Zustand) | `js_render_scanner` |
| **分布式扫描** | NATS-Style Topic 消息路由，动态工作节点管理，集群健康监控 | `distributed_messaging` |
| **精确域名解析** | public_suffix_list.dat (13626+ 条记录)，注册域名提取、子域名验证 | `domain_util` |

### w3af-1.6.49 能力迁移

| 能力 | 说明 | 模块 |
|------|------|------|
| **PII/凭证 Grep** | 信用卡号、API Key、密码硬编码、连接字符串（7 类 PII） | `w3af_pii_grep` |
| **布隆过滤器去重** | 动态增长 Bloom Filter (0.1% FPR)，O(1) URL 去重 | `w3af_bloom_filter` |
| **Blind Timing SQLi** | MySQL SLEEP()/PostgreSQL pg_sleep()/MSSQL WAITFOR DELAY (多轮统计验证) | `w3af_timing_detector` |
| **Payload 变异引擎** | URL/Hex/Unicode/Base64/MD5/SHA256 + WAF 绕过编码（8 技术） | `w3af_payload_engine` |
| **漏洞模式数据库** | 10+ 类检测模式：SQLi/XSS/CSRF/LDAP-Inject/XPath-Inject/ReDoS/SSRF/RFI/LFI | `w3af_vuln_patterns` |
| **MITM Proxy** | 本地 HTTP/HTTPS 代理，请求拦截/篡改，响应修改检测防御机制 | `w3af_proxy_server` |

### Pentest-Swarm-AI Swarm AI（18 模块 Python 原生重写）

| 能力 | 说明 | 模块 |
|------|------|------|
| **蜂群编排器** | ReAct 循环，4 阶段流程 (RECON → CLASSIFY → EXPLOIT → REPORT) | `swarm_orchestrator` |
| **漏洞分类器+评分** | FalsePositiveFilter + CVSS v3.1 base score 完整实现 | `swarm_classifier` |
| **Exploit 执行引擎** | 6 层安全门控 (scope/白名单/SafeMode/shell元字符/dry-run/timeout) | `swarm_exploit_engine` |
| **攻击链构建** | 13 条规则自动推导（sqli→auth_bypass, xss→session_hijack 等） | `swarm_path_builder` |
| **Shell 安全解析** | shlex + 逐字符引号状态机，危险 token 检测 | `swarm_shell_parser` |
| **费洛蒙系统** | 14 种发现类型，半衰期衰减（24h→SESSION 15min），自动过期 | `swarm_pheromones` |
| **LLM Prompt 工厂** | 7 种攻击类型 + RefusalHandler (24条拒绝短语) + 指数退避重试 | `swarm_prompts` |
| **Few-shot 示例库** | GraphQL/JWT/IDOR 攻击场景（含 user/assistant 对话对） | `swarm_prompt_examples` |
| **侦察解析器** | nmap/Gobuster/httprobe/httpx/subfinder/dnsx/katana/gau/nuclei 输出解析 | `swarm_recon_parser` |
| **报告生成器** | SARIF/Bugcrowd/HackerOne/Markdown/CSV/HTML/SARIF JSON (8 格式) | `swarm_report_generator` |
| **Bounty 估算** | CVE/CVSS → Bugcrowd payout ranges 映射 | `swarm_bounty_estimator` |
| **去重引擎** | Jaccard (含 stopword) + SimHash 内容聚类（threshold=0.85） | `swarm_dedup` |
| **证据收集器** | HTTP 请求文件(.http)、response header、proof text、截图集成 | `swarm_evidence` |
| **质量门控** | 三维评分 (clarity/impact/reproducibility)，Wooden bucket 效应 | `swarm_quality_gate` |
| **ROI 计算器** | Green(>10x)/Yellow(2-10x)/Red(<2x) 分级，per-finding breakdown | `swarm_roi_calculator` |
| **训练数据生成** | classifier/exploit/recon/report 四类样本 + 朴素贝叶斯分类器 | `swarm_training_data` |
| **Playbook 执行** | 7 个工作流 (OWASP-top10/Bug-Bounty/API-Security/CI-CD/CTF/External-ASM/Internal) | `swarm_playbooks` |
| **Legacy Bridge** | PentestAI 纯 Python 重写 (PentestAgent/PentestSession/SwarmOrchestrator) | `swarm_legacy_bridge` |

### 扩展扫描器（独立工具）

| 模块 | 外部工具 | 能力 |
|------|---------|------|
| `nuclei_scanner` | Nuclei | 模板驱动漏洞扫描 (5000+ 社区模板) |
| `gobuster_wrapper` | GoBuster | 目录/VHost/DNS 爆破 |
| `hydra_wrapper` | Hydra | HTTP/SSH/FTP 登录暴力破解 |
| `zap_scanner` | OWASP ZAP | 自动化被动扫描+主动扫描+Spider |
| `dns_zone_transfer` | dig/nslookup | DNS 区域转移 + AXFR + A/MX/TXT/SRV 查询 |
| `git_secret_scanner` | git-secret-hunter | Git 仓库密钥泄露检测 |
| `google_dorker` | Google Hacking DB | 4000+ 侦察 Dorks (GHDB) |
| `network_scan` | nmap | 端口扫描 / 主机发现 (`-sS`, `-sV`) |
| `cve_lookup` | NVD API | CVE 查询 + 包漏洞匹配 |
| `webshell_detector` | — | Webshell/后门文件模式检测 |
| `domain_cert_monitor` | certspotter/crt.sh | 证书透明度子域名监控 |
| `subdomain_takeover` | — | 子域名接管 + AWS S3/GCE 桶枚举 |
| `crlf_detector` | — | CRLF注入 / HTTP响应拆分 / Web缓存投毒 |
| `jwt_detector` | — | JWT 算法混淆/空密钥/未签名攻击 |
| `graphql_detector` | — | GraphQL Introspection / BOLA /类型注入 |
| `http_param_pollution` | — | HTTP参数污染 (HPP) + 参数发现 |
| `oob_detector` | interact.sh | Blind XSS / Blind SSRF / Blind RCE / OOB 检测 |
| `playbooks` | — | 扫描工作流 + 假阳性缓存 |
| `osint_recon` | shodan, whois | OSINT 侦察 + ASN/Whois/IP-信息收集 |
| `file_meta` | exifread | 文件元数据/隐写检测（EXIF/GIS） |
| `domain_similarity` | — | 域名混淆(typosquat)检测 + 相似度评分 |

### Shannon 上下文增强（白盒驱动黑盒）

- **上下文感知 Payload 生成**：从源码中发现的路由/变量自动构造针对性测试用例
- **数据流追踪 (Source → Sink)**：追踪用户输入到危险函数的传播路径
- **API 端点发现**：从代码中抽取 API 路由定义
- **框架门控匹配器**：Django→CSRF, Flask→DEBUG, Express→Helmet（仅当检测到技术栈时触发）
- **噪声分层**：`precise`(高信号/低误报) / `normal`(宽泛模式/AI消歧) / `noisy`(入口点覆盖)

### Playbook 扫描工作流

| Playbook | 阶段数 | 适用场景 |
|----------|--------|---------|
| **OWASP Top 10** | 4 | 全面 OWASP 评估 |
| **Bug Bounty** | 4 | 子域名枚举 + SQLmap 主动升级 |
| **API Security** | 2 | REST/GraphQL API 扫描 |
| **CI/CD Security** | 4 | Secret 扫描 + SAST + SARIF 输出 |
| **CTF Solver** | 4 | Web CTF 自动解题流程 |
| **External ASM** | 5 | 被动 OSINT + 攻击面监控 |
| **Internal Network** | 3 | 内网渗透（需 scope_file 验证） |

### AI 自动分析

- **多模型支持**：Ollama（本地）、通义千问、GLM、Kimi、DeepSeek、SiliconFlow、Gemini、GPT、Claude
- **自动解读报告**：扫描结果 → 可读安全分析报告
- **渗透策略推荐**：下一步建议 + 优先级排序

### 高级功能

| 能力 | 说明 |
|------|------|
| **认证会话管理** | Auto-login / Cookie/Token持久化 / OAuth2注入 / mTLS 证书认证 |
| **WAF 绕过引擎** | Payload编码(6种) + HTTP参数分裂 + Header操作 + Case随机化 + Null-byte注入 |
| **多格式报告导出** | PDF / CSV / Markdown / RST / DVCS XML / SARIF 2.1.0 / Bugcrowd / HackerOne (8 格式) |
| **登录序列录制** | 多步认证录制(login→2FA→captcha→redirect) + JSON序列化 + 重放验证 |
| **SSO/MFA/SAML测试** | Okta/Google/AzureAD/ADFS/Auth0/Keycloak 检测 + SAML签名绕过 + OAuth2 flow探测 |
| **持续回归扫描** | 定时任务 + 结果比对 + 漏洞趋势分析 + Regressionscore 加权 |
| **MITM 代理** | 中间人 TLS 解密 + 动态证书签发（自研 CA） |
| **扫描配置模板** | quick/basic/thorough/professional 四级预设 |
| **WAF 规则导出** | F5 iRules / Cloudflare JSON / ModSecurity (3 格式) |
| **内网资产发现** | ARP/SNMP/MQTT/SMB/Redis 协议探测 |
| **云桶增强枚举** | boto3 S3/GCS/Azure 多策略云存储桶扫描 |

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 安装外部工具（可选，部分能力需要）

```bash
# 核心工具（推荐安装）
apt install nmap        # 端口扫描 / 主机发现
pip install wafw00f     # WAF 指纹检测

# 高级漏洞扫描
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*.deb && dpkg -i nuclei_*.deb  # Nuclei 模板引擎
apt install gobuster    # 目录/VHost/DNS 爆破
apt install hydra       # 暴力破解

# Web 自动化扫描器
pip install zaproxy     # OWASP ZAP Python API

# 本地 AI（推荐，无需 API Key）
# https://ollama.ai/download → 下载后运行: ollama pull qwen3.6:35b

# 浏览器引擎（JS渲染/SPA路由发现需要）
pip install selenium    # Chrome/Firefox headless
playwright install      # Chromium/Blink/WebKit 内核
```

### 3. 最小使用示例

```bash
# URL 扫描
python hack_scanner.py --url https://example.com/path?param=value

# 文件目录扫描
python hack_scanner.py --file ./path/to/source_code

# 交互式菜单（推荐）
python launcher.py
```

---

## 使用方式

### CLI 参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--url <URL>` | 目标 URL | `--url https://target.com/admin?id=1` |
| `--file <DIR>` | 源码目录扫描 | `--file ./my-project` |
| `--both` | 同时 URL + 文件 | `--both -u URL -f DIR` |

### Playbook 执行（Swarm AI）

```python
from scanners.swarm_playbooks import execute_playbook, list_playbooks

# 查看可用 playbook
for name in list_playbooks():
    print(f"  {name}")

# 执行 OWASP Top 10 全面扫描
results = execute_playbook(
    "owasp-top10",
    targets=["https://target.com"],
    simulate=False,      # False = 真实执行，True = dry-run 预览
)
```

### AI 报告生成

```python
from scanners.swarm_report_generator import ReportGenerator, ReportFormat

report = ReportGenerator()
markdown = report.generate(findings, ReportFormat.MARKDOWN)
sarif   = report.generate(findings, ReportFormat.SARIF)
bugcrowd = report.generate(findings, ReportFormat.BUGBOUNTY)
```

---

## 配置说明

全局配置位于 `config.json`，结构如下：

| 顶层 Key | 作用 | 关键子项 |
|----------|------|---------|
| `scanner` | 扫描核心参数 | timeout(30s), max_depth(3), max_pages(100), concurrent(5) |
| `scanner.proxy` | HTTP(S) 代理 | enabled, http, https |
| `scanner.rate_limit` | 请求限速 | enabled, per_domain_sec(2.0), global_min_sec(0.5) |
| `ai` | AI 分析配置 | provider/ollama, model/qwen3.6:35b, temperature/max_tokens |
| `urls` | URL 检查开关组 | ssl/check_headers/check_cors/check_sqli/check_xss/... |
| `urls.dir_busting` | 目录爆破配置 | enabled, wordlist列表, status_codes |
| `safety` | 安全护栏 | confirm_external_scan, max_requests_per_domain, dangerous_modes |
| `files` | 文件扫描选项 | check_secrets/check_permissions/check_dependencies/deepsec_matchers |
| `report` | 报告输出设置 | format[html,json], output_dir, severity_colors |
| `tools` | 外部工具路径 | sqlmap_path, nmap_path, nikto_path, dirb_path |
| `acunetix` | Acunetix v25 能力 | acu_sensor, js_renderer, distributed, tld_list, report_formats |
| `scan_profiles` | 扫描预设配置 | quick/basic/thorough/professional（含 timeout + rate_limit_rpm） |
| `mitm_proxy` | MITM 代理 | listen_port(8080), cert_store_path, auto_renew_certs |
| `waf_rules` | WAF 规则导出 | export_on_complete, formats[f5_ireule,cloudflare_json] |
| `zero_discovery` | 内网资产发现 | scan_level, port_range[21,22,80,139,445,6379,...], smb/snmp/mqtt/redis |

**危险模式默认关闭（需手动开启）：**
`webshell_upload`, `brute_force_password`, `payment_tampering`, `sql_sleep_dos`, `ssrf_internal_probes`, `http_delete_put`, `password_reset_trigger`, `dns_nuke`

---

## 报告格式

| 格式 | 说明 | 适用场景 |
|------|------|---------|
| **HTML** | 彩色卡片式展示，支持展开 JSON | 人工审查 |
| **JSON** | 结构化机器可读格式 | CI/CD 集成、自动化分析 |
| **PDF** | WeasyPrint / wkhtmltopdf 渲染 | 正式报告交付 |
| **CSV** | Tabular 表格导出 | Excel 分析 |
| **Markdown** | SRC report style Markdown | GitHub Wiki / Slack |
| **RST** | reStructuredText | Sphinx/Doc 文档 |
| **DVCS XML** | DevCraft Vulnerability Scan 兼容格式 | DVCS 平台对接 |
| **SARIF 2.1.0** | GitHub/Sarif 标准化漏洞数据 | IDE/CI 集成 |
| **Bugcrowd** | Bugcrowd HackerOne VDP 提交模板 | 漏洞赏金平台提交 |
| **HackerOne** | HackerOne Program Report 格式 | H1 平台直接提交 |

---

## DeepSec Matcher 引擎

从 [deepsec](https://github.com/vercel-labs/deepsec) 移植的 ~110 条正则规则静态分析引擎。

| 匹配器类别 | 说明 | 示例模式 |
|-----------|------|---------|
| **通用匹配器** (GENERIC_MATCHERS) | 跨语言漏洞模式，始终运行 | SQLi, XSS, SSRF, RCE, LFI, CSRF, Key泄露 (~15 类) |
| **框架门控匹配器** (FRAMEWORK_MATCHERS) | 基于技术栈触发（Django→CSRF豁免检测） | Express/Fastify/NestJS/Django/Flask/FastAPI/Laravel/Rails/Gin/Echo (~20 框架) |
| **IaC 匹配器** (IAC_MATCHERS) | Dockerfile/Terraform/GitHub Actions 安全 | 特权容器/根用户/curl管道/IAM宽权限/明文密钥 |
| **ORM 匹配器** (ORM_MATCHERS) | ORM raw SQL 注入 | Prisma/$queryRawUnsafe, Drizzle raw, SQLAlchemy text() |

---

## MCP Agent 集成

项目提供 `mcp_server.py` 实现 MCP (Model Context Protocol) 标准化接口，允许任何支持 MCP 的客户端（Claude Desktop、Cursor、VS Code MCP extension）直接调用扫描能力。

```python
# 启动 MCP Server
python mcp_server.py

# 或在 Claude Desktop settings.json 中配置:
{
    "mcpServers": {
        "hack_scanner": {
            "command": "python",
            "args": ["mcp_server.py"]
        }
    }
}
```

---

## 技术栈依赖

### 核心依赖（必需，直接 import）

| 包 | 用途 | 引用文件数 |
|----|------|-----------|
| `requests>=2.31` | HTTP 客户端 + 限速包裹 | 7 个 scanner |
| `beautifulsoup4>=4.12` | HTML/XML 解析（BS4） | 5 个 scanner |
| `lxml>=4.9` | 高性能 XML/HTML 解析 | core |
| `pyyaml>=6.0` | YAML 配置加载 (playbooks) | playbooks, config |
| `jinja2>=3.1` | 报告模板渲染 | report templates |
| `python-nmap>=0.7` | nmap Python API | network_scan |
| `dnspython>=2.8` | DNS 查询 (dig/nslookup) | dns_zone_transfer, domain_util |
| `cryptography>=42` | X.509 证书签发/验证 | cert_factory (MITM CA) |
| `certifi>=2024` | CA root certificates | mitm_proxy, cert_factory |

### AI / MCP（推荐）

| 包 | 用途 |
|----|------|
| `mcp>=1.0` | Model Context Protocol 集成 |
| `nltk>=3.8` | NLP（上下文分析、文本相似度） |

### 安全工具（推荐安装）

| 包 | 外部工具 | 用途 |
|----|---------|------|
| `wafw00f>=2.4` | wafw00f (pip) | WAF/CDN 指纹识别 |
| `shodan>=1.31` | shodan API | Shodan 搜索引擎 |
| `sslyze>=6.3` | sslyze CLI | SSL/TLS 深度分析（sslyze 引擎） |
| `exifread>=3.5` | exifread (pip) | EXIF/GIS 元数据提取 |
| `whois>=1.20240129` | whois CLI | WHOIS 查询 |
| `zaproxy>=0.6` | OWASP ZAP Python API | ZAP 自动化扫描 |

### 浏览器引擎（JS渲染/SPA路由发现）

| 包 | 用途 |
|----|------|
| `selenium>=4.15` | Chrome/Firefox headless (Selenium) |
| `playwright>=1.40` | Chromium/Blink/WebKit 浏览器引擎（备选 Selenium） |
| `nest_asyncio>=1.6` | Playwright sync API 兼容 asyncio event loop |

### 文档生成

| 包 | 用途 |
|----|------|
| `pdfkit>=1.0` | wkhtmltopdf 渲染 PDF |
| `weasyprint>=59` | CSS → PDF (备选 pdfkit) |

### 云存储（可选）

| 包 | 用途 |
|----|------|
| `boto3>=1.34` | AWS S3/GCS/Azure 桶枚举 |
| `bcrypt>=4.1` | probe identifiers session 密码哈希 |
| `gevent>=24` | MITM 代理 + 并发扫描（greenlet-based）性能优化 |

---

## 安全声明

> **⚠️ Hack Scanner 仅用于授权的安全测试和渗透测试。**
> 
> - **限速强制启用**：所有 HTTP 请求经过全局速率限制器包裹，防止 DoS 级别的请求风暴
> - **危险模式默认关闭**：webshell上传/暴力破解/支付篡改/SQL睡眠DoS/ssrf内部探测 等 8 种危险操作需手动开启
| `--url` | 目标 URL | `--url https://target.com/admin?id=1` |
| `--file` | 源码目录扫描 | `--file ./my-project` |
| `--both` | 同时 URL + 文件 | `--both -u URL -f DIR` |

### Playbook（Swarm AI）

```bash
python launcher.py  # 选择 Playbook 模式 → 输入目标 URL/目录
```

### MCP Agent 集成

```bash
python mcp_server.py  # 启动后连接 Claude Desktop / Cursor / VS Code MCP extension
```

---

## 配置说明

全局配置位于 `config.json`，核心结构：

| Key | 说明 |
|-----|------|
| `scanner.*` | HTTP 客户端设置（timeout/max_depth/max_pages/concurrent） |
| `scanner.proxy` | 代理配置 |
| `scanner.rate_limit` | 限速参数（per_domain_sec / global_min_sec） |
| `ai.*` | AI 分析配置（provider/model/temperature/max_tokens） |
| `urls.*` | URL 检查开关组（SSL/CORS/SQLi/XSS/SSRF/RCE/LFI/XXE/...） |
| `urls.dir_busting` | 目录爆破词表 + HTTP 状态码白名单 |
| `safety.*` | **安全护栏**（confirm_external_scan, max_requests_per_domain, dangerous_modes） |
| `files.*` | 文件扫描选项（secrets/permissions/deepsec_matchers/deepsec_noise_tiers） |
| `report.*` | 报告输出格式、目录、严重程度颜色映射 |
| `tools.*` | 外部工具路径（sqlmap/nmap/nikto/dirb） |
| `acunetix.*` | AcuSensor/JS渲染/分布式扫描/TLD列表/报告格式开关 |
| `scan_profiles.*` | quick/basic/thorough/professional 四级预设 |
| `mitm_proxy.*` | MITM 代理配置（端口、证书存储路径） |
| `waf_rules.*` | WAF 规则导出设置（F5 iRules/Cloudflare JSON） |

---

## 输出报告

- **hack_report/report.html** — 彩色卡片式 HTML 报告，按严重程度分组展示发现项
- **report.json** — JSON 结构化数据，含每条发现的详细证据链

---

## Shannon 架构（白盒驱动黑盒）

项目核心为 Shannon 上下文分析引擎：从源码中自动提取路由定义、认证原语、输入源(Sink)和输出点(Source)，据此生成针对性的渗透测试 payload。这使扫描器超越简单 fuzzing，实现**数据流感知**的智能测试。

- `shannon_context.py` — 数据流追踪核心
- `ai_analyzer.py` — AI 辅助分析（自动解读报告、推荐后续策略）
- `deepsec_matchers.py` — ~110 条跨语言正则规则引擎

---

## 项目结构

```
hack_scanner/
├── hack_scanner.py        # 主扫描器入口 (URL + file) (~35K)
├── url_scanner.py         # URL 扫描引擎核心 (~230K, 67 个模块依赖此)
├── ai_analyzer.py         # AI 自动分析报告生成器
├── launcher.py            # 交互式菜单 UI (9 种 AI 模型选择)
├── mcp_server.py          # MCP Agent 集成服务器
│
├── init.py                # 初始化框架 (配置加载/模块发现)
├── init_ai.py             # AI Provider 初始化 (Ollama/Qwen/GLM/GPT/Claude...)
├── rate_limiter.py        # 全局请求限速器 (防止 DoS)
├── shannon_context.py     # Shannon 数据流追踪引擎 (~37K)
│
├── scanners/              # 扫描器集合 (69 个 Python 模块)
│   ├── crlf_detector.py     # CRLF注入 / HTTP响应拆分 / Web缓存投毒
│   ├── jwt_detector.py      # JWT算法混淆/空密钥攻击检测
│   ├── subdomain_takeover.py # 子域名接管 + 云桶枚举
│   ├── graphql_detector.py  # GraphQL Introspection/BOLA/类型注入
│   ├── http_param_pollution.py # HTTP参数污染检测
│   ├── oob_detector.py      # Blind XSS/SSRF/RCE (interact.sh)
│   ├── playbooks.py         # Playbook runner + FP缓存机制
│   ├── w3af_bloom_filter.py  # 布隆过滤器 URL 去重
│   ├── w3af_payload_engine.py # Payload变异引擎 (8编码技术)
│   ├── w3af_proxy_server.py  # MITM HTTP/HTTPS 代理服务器
│   ├── w3af_timing_detector.py # Blind Timing SQLi 检测
│   ├── w3af_vuln_patterns.py  # 漏洞模式数据库 (~200条正则)
│   ├── swarm_classifier.py    # 漏洞分类器 + CVSS v3.1 评分
│   ├── swarm_exploit_engine.py  # Exploit执行引擎 (6层安全门控)
│   ├── swarm_orchestrator.py  # 蜂群编排器 + ReAct循环
│   ├── swarm_playbooks.py     # 7个工作流 Python原生实现
│   ├── swarm_prompts.py       # LLM Prompt工厂 + RefusalHandler
│   ├── swarm_report_generator.py # SARIF/Bugcrowd/HackerOne 报告
│   ├── swarm_bounty_estimator.py # Bounty估算引擎
│   ├── swarm_dedup.py         # Jaccard + SimHash去重聚类
│   ├── swarm_evidence.py      # 证据收集器 (HTTP req/response)
│   ├── swarm_quality_gate.py  # 质量门控 (3维评分)
│   ├── swarm_roi_calculator.py  # ROI计算引擎 (>10x/2-10x/<2x分级)
│   ├── swarm_training_data.py   # 训练数据生成 + 朴素贝叶斯分类器
│   ├── swarm_recon_parser.py    # nmap/Gobuster/katana 输出解析
│   ├── swarm_legacy_bridge.py   # PentestAI Python 重写
│   ├── acu_sensor_lang_deploy.py # AcuSensor多语言探针部署
│   ├── acu_sensor_sensor.py     # WAF深度指纹(50+产品) + CDN检测
│   ├── js_render_scanner.py     # Headless Browser SPA分析引擎
│   ├── distributed_messaging.py  # NATS-style分布式扫描集群
│   ├── domain_util.py           # 精确域名解析器 (13626条PSL规则)
│   ├── auth_session.py          # 认证会话管理 (auto-login/OAuth2/mTLS)
│   ├── waf_bypass.py            # WAF绕过引擎 (6种编码+参数分裂)
│   ├── export_engine.py         # 多格式报告导出 (PDF/CSV/Markdown...)
│   ├── login_sequence.py        # 登录序列录制器 (login→2FA→captcha)
│   ├── ssoprobe.py              # SSO/MFA/SAML测试模块
│   ├── continuous_scan.py       # 持续回归扫描框架
│   ├── mitm_proxy_scanner.py    # MITM代理扫描器
│   ├── scan_profiles.py         # 扫描配置模板管理
│   ├── waf_rule_generator.py    # WAF规则生成器 (F5/Cloudflare/ModSecurity)
│   ├── cert_factory.py          # MITM CA证书工厂
│   ├── zero_discovery.py        # 内网资产发现 (ARP/SNMP/MQTT/SMB)
│   ├── boto3_bucket_enhancer.py # 增强版云存储桶枚举
│   ├── nuclei_scanner.py        # Nuclei模板驱动漏洞扫描
│   ├── gobuster_wrapper.py      # GoBuster目录/VHost/DNS爆破
│   ├── hydra_wrapper.py         # Hydra暴力破解 (HTTP/SSH/FTP)
│   ├── zap_scanner.py           # OWASP ZAP自动化扫描
│   ├── dns_zone_transfer.py     # DNS区域转移 + 记录查询
│   ├── git_secret_scanner.py    # Git仓库密钥泄露检测
│   ├── google_dorker.py         # Google Hacking Dorks侦察
│   ├── network_scan.py          # nmap端口扫描/主机发现
│   ├── ssl_deep_scan.py         # SSL/TLS深度分析(sslyze)
│   ├── cve_lookup.py            # CVE查询 (NVD API)
│   ├── webshell_detector.py     # Webshell后门检测
│   ├── domain_cert_monitor.py   # 证书透明度子域名监控
│   ├── file_meta.py             # 文件元数据/隐写检测(exifread)
│   ├── domain_similarity.py     # 域名混淆(typosquat)检测
│   └── crawler.py               # DeepScan递归站点爬虫(三层:HTTP/Selenium/Playwright)
│
├── config.json              # 全局配置 (~250行, 14个顶级key)
├── requirements.txt         # Python依赖清单 (28 包)
├── deepsec-custom-sample.json   # DeepSec matcher 自定义规则模板
├── deepsec-info-template.md     # DeepSec 项目上下文模板
│
├── data/                    # 数据文件
│   └── tld/public_suffix_list.dat  # 13626+ TLD公共后缀列表
│
└── scan_URL_Files.bat       # Windows 一键启动脚本 (清理缓存 + 运行launcher)
```

---

## 模块导出索引

`scanners/__init__.py` 提供完整模块化导出。导入方式：

```python
from scanners import ALL_SCANNER_MODULES, ACUNETIX_MIGRATION_MODULES
from scanners import W3AF_MIGRATION_MODULES, SWARM_MIGRATION_MODULES

# 查看可用扫描器列表
for name, meta in ALL_SCANNER_MODULES.items():
    print(f"{name}: {meta['description']}")
```

---

## 更新日志

| 版本 | 日期 | 主要变更 |
|------|------|---------|
| **v8.0** | 2026-07-17 | Acunetix v25 + w3af-1.6.49 + Pentest-Swarm-AI 全面整合 (Swarm AI 18模块, WAF绕过引擎, MITM代理, Bloom过滤器, Payload引擎等) |
| **v7.0** | 2026-06 | 漏洞修复、SPA路由发现、隐藏API端点检测、前端框架指纹识别、状态管理检测 |
| **v6.0** | 2026-07 | DeepSec Matcher 引擎整合（~110条正则规则，跨语言漏洞检测，框架门控扫描） |
| **v5.1** | 2026-06 | 安全加固：全局限速器、危险模式默认关闭、扫描前确认、dry-run预览 |
| **v5.0** | 2026-06 | Pentest-Swarm-AI Phase 2/4 借鉴：CRLF注入/JWT漏洞/GraphQL安全/子域名接管/OOB盲注 + Playbook工作流 |
| **v4.0** | 2026-06 | w3af深度整合：XXE/文件上传/反序列化/Blind Timing SQLi/VCS泄露/OpenAPI发现等14项能力 |

---

## 许可

本项目仅供授权的安全测试和教育用途使用。使用者需遵守当地法律法规。
