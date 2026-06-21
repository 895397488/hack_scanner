# Hack Scanner - 自动化漏洞扫描器 🔐

> 只需提供文件或URL，即可自动执行全方位安全检测。
>
> **核心增强 (Shannon-inspired)**: 白盒+黑盒融合 — 先分析源码发现攻击面，再用针对性payload进行动态验证。借鉴 Shannon AI Pentester 的 Source→Sink 数据流追踪、API端点自动发现、上下文感知payload生成等能力。

## 🚀 快速开始

### 安装依赖

```bash
cd C:\Users\Administrator\Downloads\hack
pip install -r requirements.txt
```

### 使用方法

#### 1. 扫描 URL/网站

```bash
python hack_scanner.py -u https://example.com/path?id=1
```
或者打开 scan_URL.bat 输入网址后回车

#### 2. 分析文件/代码目录

```bash
python hack_scanner.py -f .\file-path
```
或者打开 scan_files.bat 输入路径后回车

#### 3. 同时扫描

```bash
python hack_scanner.py -u https://example.com -f ./project/ -o ./output/
```

## 📋 检测能力

### 🔥 Shannon白盒增强能力（新增）

| 能力 | 说明 |
|------|------|
| **Source→Sink数据流追踪** | 追踪Python/PHP/JS代码中HTTP输入→危险函数的完整传播链，自动提升可疑漏洞的置信度 |
| **上下文感知Payload生成** | 根据源码发现的变量名、类型和框架（Flask/Django/Spring等）自动生成针对性注入payload |
| **API端点自动发现** | 从Express/Flask/Django/Spring/FastAPI路由定义中自动提取端点，对每个端点执行完整测试 |
| **技术栈自动识别** | 从代码特征自动检测框架、CMS、WAF等，指导扫描策略调整 |

### URL 扫描 (OWASP TOP10)

| 检测类型 | 说明 | 严重程度 |
|---------|------|---------|
| SQL注入 | GET参数注入测试 + 时间盲注 | Critical/High |
| XSS反射型 | 多种XSS载荷测试 | High |
| SSRF | file/gopher/dict协议探测 | Critical |
| LFI/路径遍历 | ../../ 等跳转符号测试 | Critical |
| 命令注入(RCE) | shell执行检测 | Critical |
| SSL/TLS | 证书有效期、协议版本检查 | High |
| HTTP安全头 | CSP/HSTS/XSS-Protection等缺失 | Medium/Low |
| CORS错误配置 | wildcard + credentials检测 | Critical/High |
| 敏感信息泄露 | API Key/密码/JWT/私钥等 | Critical/High |
| 子域名枚举 | crt.sh + 常见子域名暴力枚举 | Info |
| 目录爆破 | 100+ 常见路径检测 | High |
| 技术栈识别 | 前端框架/CMS/WAF指纹 | Info |

### 文件/代码分析

| 检测类型 | 说明 |
|---------|------|
| 硬编码凭证 | AWS Key/API Token/Password/JWT Secret等 |
| 危险函数 | eval/exec/os.system/unserialize等 |
| SQL注入模式 | 字符串拼接SQL查询 |
| 文件包含漏洞 | 动态include/require检测 |
| 依赖漏洞 | express/lodash/django/log4j等已知CVE |
| Docker安全 | privileged容器/主机网络/敏感目录挂载 |
| 敏感文件名 | .env/id_rsa/shadow/.htpasswd等 |
| Nginx配置 | server_tokens/autoindex等暴露问题 |

### 支持的文件类型

- `*.py` Python - 危险函数+SQL注入+反序列化
- `*.js` JavaScript - eval/XSS/原型链
- `*.ts` TypeScript - React dangerouslySetInnerHTML
- `*.php` PHP - eval/system/unserialize/SQL注入
- `*.java` Java - SQL注入/反序列化/RCE
- `*.yml` YAML - Docker安全
- `*.env` .env文件 - 敏感配置检测
- `*.conf` 配置文件 - Nginx暴露问题
- `package.json` / `requirements.txt` - 依赖漏洞

## 📊 输出报告

### HTML 报告 (`report.html`)

在浏览器中打开，包含：
- 🔴 风险评级仪表盘
- 🐛 所有漏洞详细清单（含修复建议）
- 📦 技术栈指纹
- 🌳 子域名列表
- 📂 发现的敏感路径

### JSON 报告 (`report.json`)

机器可读格式，适合集成到：
- CI/CD Pipeline (Jenkins/GitLab CI/GitHub Actions)
- 安全管理系统
- 自定义监控告警

## ⚙️ 配置

编辑 `config.json` 可调整扫描参数：

```json
{
  "scanner": {
    "timeout": 30,
    "concurrent": 5
  },
  "urls": {
    "check_sqli": true,
    "check_xss": true,
    "dir_busting": { "enabled": true }
  }
}
```

## 🧠 Shannon白盒增强（自动启用）

Shannon-inspired模块在扫描时**自动激活**：
1. 先用 `file_analyzer.py` 扫描源码 → 提取API端点、危险函数、框架信息
2. 用这些信息构建上下文（`ContextAnalyzer`）
3. URL扫描时传入上下文 → SQLi/XSS等检测使用针对性payload
4. 报告中标注「白盒增强」的漏洞置信度更高

无需额外配置，`python hack_scanner.py -u URL -f DIR` 即可自动融合。

## ⚠️ 免责声明

本工具仅用于**授权的安全测试**。未经授权对他人系统进行安全测试可能违反法律法规。使用此工具即表示你已获得相关系统的合法授权，并同意承担使用后果。
