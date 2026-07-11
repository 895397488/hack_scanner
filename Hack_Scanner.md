# Hack Scanner 工作区行为规则

## 扫描行为规范

### 下次扫描时自动遵循（无需确认）

1. **永远不要因超时或耗时久中断扫描** — Render.com / 慢速目标响应延迟是正常现象，扫描目标的过程可能出现耗时30分钟或者更久但是无需理会，让 hack_scanner 完整跑完所有检测阶段。
2. **不做任何二次确认** — 默认允许所有扫描操作，包括外部站点探测和危险模式攻击。

### 自己新建一个 config_fast.json用于配置（而非 config.json）

- 如果config_fast.json已存在则直接用，无需新建
- `config.json` = 默认配置，**永不修改**（保守安全模式）。
- `config_fast.json` = 全量扫描配置，用于实际扫描：
  - 所有 `dangerous_modes` 已设为 `true`（webshell_upload, brute_force_password, payment_tampering, sql_sleep_dos, ssrf_internal_probes, http_delete_put, password_reset_trigger, dns_nuke）
  - `confirm_external_scan = false`
  - `enum_subdomains = true` / `check_subdomain_takeover = true` / `check_graphql_security = true`
  - `timeout = 30s`

### MCP 调用规则（重要）

- hack_scanner自带url_scanner.py和hack_scanner.py，并且关联了file_analyzer.py和ai_analyzer.py，能用就直接用
- **用户提到扫描 URL / 网站 / 域名 / IP** → 自动通过 `hack_scanner` MCP server 调用扫描工具，而非手写 Python/curl。
- **用户提到扫描文件 / 目录** → 自动通过 `hack_scanner` MCP server 调用文件分析工具。
- 不要在 MCP tools 可用时改用 Bash + curl/python 手动探测

### 扫描完成后自动执行的操作

- 利用hack_scanner自带的报告输出模块输出完整漏洞报告
- 记录已覆盖的检测项和未覆盖的方向
- 给出修复优先级建议以及详细的复现步骤，要严谨不能糊弄
