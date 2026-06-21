# Hack Scanner - Shannon-Inspired Enhancement Plan

> 目标是让 hack scanner 像 Shannon 一样强大，但保持简单的一键启动。

## Shannon 的核心能力（已分析）

1. **White-box + Black-box Fusion**: 先读源码定位攻击面→再用动态测试验证
2. **Context-Aware Payload Generation**: 从源码变量名自动构造注入payload
3. **Authentication Bypass Testing**: 登录表单探测、JWT伪造、session管理
4. **API Endpoint Discovery & Fuzzing**: 从代码/API文档发现端点→自动化fuzzing
5. **Browser-Based Validation**: 用真实浏览器执行exploit并截图证明
6. **Data Flow Tracing (Source → Sink)**: Python/PHP/JS的数据流追踪
7. **Automated Exploit Generation**: 生成可复制的PoC脚本

## 改进优先级

### Phase 1: Source-Guided Dynamic Testing (P0)
**核心思路**: 文件分析发现的路径/变量/API端点 → 注入到URL扫描的payload中

实施文件: `url_scanner.py` + `file_analyzer.py`

具体改动:
- FileAnalyzer输出增加 `api_endpoints`, `query_params`, `dynamic_routes` 字段
- URLScanner接受一个 `context_data` 参数，包含文件分析的结果
- SQLiDetector根据上下文动态生成payload（例如发现变量名 $id → 测试数字注入）
- XSSDetector根据上下文发现的事件处理器自动生成对应payload

### Phase 2: Context-Aware Payload Generation (P0)
**具体改动**:
- 当发现 PHP `$_GET['id']` → SQLi payload自动针对数字/字符串两种类型
- 当发现 JS `innerHTML = data` → XSS payload增强（特定编码绕过）
- 当发现 Python `cursor.execute(f"...{var}")` → SQLi payload针对性测试

### Phase 3: API Endpoint Discovery (P1)
**具体改动**: 新增 `api_discovery.py`
- 从源码中抽取API路由定义 (Express routes, Flask blueprints, Django urls, Spring @RequestMapping)
- 对每个发现的端点执行OWASP TOP10测试
- 支持 OpenAPI/Swagger 文档解析

### Phase 4: Auth Bypass Testing (P1)
**具体改动**: 新增 `auth_tester.py`
- 登录表单探测（从源码找login/register路由）
- JWT伪造测试（发现JWT Secret → 尝试签名篡改）
- Session固定/管理漏洞检测

### Phase 5: Data Flow Tracing (P2)
**具体改动**: 增强 `file_analyzer.py`
- Python: 追踪函数参数从HTTP入口到数据库/命令执行的完整路径
- PHP: 追踪 $_GET/$_POST 到危险函数的传播链
- JavaScript: 追踪用户输入到innerHTML/eval/dangerouslySetInnerHTML

### Phase 6: PoC Exploit Generation (P2)
**具体改动**: 增强 `ReportGenerator`
- 每个高严重性漏洞自动生成Python/JavaScript PoC脚本
- SQLi → curl命令+sqlmap一键测试命令
- XSS → JavaScript控制台可执行的PoC
- SSRF → curl gopher协议PoC

## Shannon 借鉴的技术细节

从 Shannon dist 中学到的:
1. **Source tracing**: Shannon用抽象语法树(AST)追踪数据流，我们先用正则做轻量版
2. **Dynamic worker spawning**: Shannon用Docker隔离扫描进程，我们用Python threading替代
3. **Parallel processing**: 并发执行多个扫描模块
4. **Config-driven**: TOML/JSON配置所有行为，支持profile切换

## 不采用 Shannon 的部分（因过于复杂）
- Docker容器编排（需要Docker Desktop）
- Temporal工作流引擎
- Claude/AI模型依赖
- Anthropic API密钥
- Node.js运行环境

我们用纯Python实现，pip install即可跑。
