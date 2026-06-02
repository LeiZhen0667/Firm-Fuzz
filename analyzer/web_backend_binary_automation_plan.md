# 后端二进制自动化分析方案

## 1. 背景与目标

当前系统已经完成 Web 前端、Web server 配置、后端可读源码三层可读文件分析，但 GPL 包中仍存在不可直接阅读的后端二进制文件，例如：

```text
collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us/httpd
```

根据 `Overall-System-Process.md` 的系统定位，GPL 分析阶段的核心目标不是证明漏洞，而是离线提取 Web 服务相关知识，并将其转化为后续黑盒 HTTP fuzzing 可使用的结构化输入：URL、handler、参数、约束、sink、响应字符串、认证线索和状态改变线索。

因此，后端二进制分析模块的目标应定义为：

```text
把 GPL 中不可读的 Web 后端二进制，自动转化为可融合、可追溯、可供 seed/fuzzer/feedback/oracle 使用的结构化 artifacts。
```

它不负责 payload 生成，不直接判断漏洞，不连接真实设备，不进行运行时插桩；它只在离线阶段补齐可读源码分析无法覆盖的后端事实。

## 2. 当前 IDA MCP 自动化状态判断

已验证当前 MCP 状态：

```text
mcp__idapromcp.list_instances -> []
mcp__idapromcp.open_file(httpd, autonomous=true) -> 失败
错误原因：No running IDA instance is available to launch a new file. Start one instance first or specify --ida-rpc explicitly.
```

这个结果说明：

- `idapromcp` 已经具备 `open_file` 工具，理论上可以由 Codex/MCP 自动打开二进制并切换到新 IDA 实例。
- 失败点不是二进制不能自动分析，而是 MCP 代理当前没有可用的 IDA 启动锚点。
- 要做到完全自动化，需要解决“如何让 MCP 能启动或连接 IDA”的问题。
- 如果该问题短期解决不了，仍然可以用 IDA 命令行批处理先生成中间结果，再由 Codex 对中间结果进行二次分析。

## 3. 推荐总体方案

推荐采用“双轨架构”：

```text
二进制候选发现
  ↓
优先路径 A：Codex -> IDA MCP -> 自动打开二进制 -> IDA 脚本抽取 artifacts
  ↓ 若 A 不可用
降级路径 B：IDA headless/batch -> 预处理 artifacts -> Codex 分析 artifacts
  ↓
web_backend_binary_artifacts.json
  ↓
与 frontend/config/readable-backend artifacts 融合
  ↓
URL -> handler -> 参数 -> 约束 -> sink -> 风险标签
  ↓
seed/fuzzer/feedback/oracle
```

路径 A 适合交互式深挖、函数级增量查询、遇到复杂 dispatch 表时让 Codex 继续通过 MCP 请求 IDA 上下文。

路径 B 适合批量扫描大量 GPL 包，稳定、可复现、无需每个文件都让 Codex 驱动 IDA GUI。

实际工程上建议同时实现，但 MVP 优先顺序应是：

1. 先实现路径 B 的 IDA 批处理预处理器，因为它最稳定，能马上批量产出 artifacts。
2. 再补齐路径 A 的 MCP 自动打开能力，用于复杂样本的交互式增强分析。

## 4. 路径 A：Codex 自动连接 IDA MCP 并打开二进制

### 4.1 适用条件

路径 A 成立需要满足任一条件：

- 存在一个已经注册到 `idapromcp` 的运行中 IDA 实例。
- `idapromcp` 代理配置了显式 `--ida-rpc`，可以自行启动或定位 IDA。
- 有一个常驻的 IDA launcher/daemon，负责接收 MCP 的 open request 并拉起 IDA。

当前环境的失败信息表明，缺少的是这个启动锚点。

### 4.2 推荐修复方式

推荐把“手动打开 IDA”替换成“自动启动一个空 IDA 锚点或显式配置 IDA RPC”。

可行方式如下：

```text
Codex/MCP session start
  ↓
启动一个空 IDA Pro 实例，并加载 idapromcp 插件
  ↓
idapromcp.list_instances 能看到实例
  ↓
Codex 调用 mcp__idapromcp.open_file(file_path, autonomous=true, switch=true)
  ↓
IDA 自动打开目标二进制并完成初始 auto-analysis
  ↓
Codex 通过 MCP 调用 IDA 查询函数、字符串、交叉引用、伪代码和反汇编
```

如果 `idapromcp` 支持 `--ida-rpc`，更好的方式是在 MCP server 配置中写入 IDA 可执行文件或 RPC endpoint，使 `open_file` 无需依赖已有 GUI 实例。

### 4.3 自动化流程

建议新增一个二进制分析 orchestrator：

```text
analyzer/web_backend_binary_analyzer/
  web_backend_binary_analyzer.py
  ida_mcp_driver.py
  ida_batch_driver.py
  ida_scripts/
    extract_web_facts.py
  README-web-backend-binary-analyzer.md
```

路径 A 的 orchestrator 逻辑：

```text
1. 读取 unreadable_files/web_backend_sources 下的二进制候选。
2. 调用 mcp__idapromcp.list_instances。
3. 如果实例为空，尝试通过已配置 launcher 启动 IDA 锚点。
4. 调用 mcp__idapromcp.open_file(binary, autonomous=true, switch=true)。
5. 等待 IDA auto-analysis 完成。
6. 运行 IDA Python 抽取脚本或通过 MCP 分批查询：
   - imported/exported symbols
   - strings
   - functions
   - xrefs to strings
   - xrefs to sink imports
   - handler registration tables
   - candidate HTTP parameter readers
   - config API calls
   - auth/state hints
7. 保存 `web_backend_binary_artifacts.json`。
```

### 4.4 路径 A 的优点与风险

优点：

- Codex 可以按需追问 IDA，适合复杂样本。
- 可以针对某个函数、字符串、sink 做增量分析。
- 能把 LLM 的语义理解与 IDA 的精确反汇编上下文结合。

风险：

- 依赖 IDA GUI/RPC 启动状态。
- 批量处理大量二进制时稳定性不如 headless batch。
- IDA license、插件路径、Python 环境、MCP 端口都可能成为自动化脆弱点。

因此路径 A 不应作为唯一方案，应与路径 B 共存。

## 5. 路径 B：IDA 批处理预处理 + Codex 分析 artifacts

### 5.1 设计原则

如果无法彻底解决“Codex 自动打开 IDA”的问题，仍可以实现自动化目标：不要让 Codex 直接操作 IDA GUI，而是让 IDA 在批处理模式中预处理二进制，输出 Codex 可读的 JSON。

```text
IDA batch/headless analysis
  ↓
extract_web_facts.py
  ↓
二进制结构化 artifacts
  ↓
Codex/普通 Python parser/fusion 继续分析
```

这条路径仍然符合系统目标，因为 IDA 只发生在 GPL 离线分析阶段，输出的是静态知识，不引入真实设备运行时能力。

### 5.2 批处理命令形态

Windows 下可以采用类似命令：

```powershell
ida64.exe -A -S"G:\GPLFuzz\analyzer\web_backend_binary_analyzer\ida_scripts\extract_web_facts.py --output G:\GPLFuzz\analyzer\web_backend_binary_analyzer\output\Linksys_e1200_v1.0.04.001_us.httpd.web_backend_binary_artifacts.json" "G:\GPLFuzz\collector\output\unreadable_files\web_backend_sources\Linksys_e1200_v1.0.04.001_us\httpd"
```

32 位 IDA 或不同架构样本可切换为 `ida.exe` / `ida64.exe`，具体由二进制格式识别结果决定。

建议 orchestrator 不直接硬编码 IDA 路径，而从配置文件读取：

```json
{
  "ida_path": "C:/Program Files/IDA Pro 9.0/ida64.exe",
  "ida32_path": "C:/Program Files/IDA Pro 9.0/ida.exe",
  "analysis_timeout_seconds": 900,
  "output_dir": "analyzer/web_backend_binary_analyzer/output"
}
```

### 5.3 IDA Python 抽取内容

`extract_web_facts.py` 应尽量输出事实而非判断。建议第一版抽取以下内容：

- 文件元数据：路径、hash、大小、架构、endian、入口点、segments。
- imports/exports：尤其是 `system`、`popen`、`exec*`、`strcpy`、`sprintf`、`memcpy`、`fopen`、`open`、`unlink`、`nvram_*`、`uci_*`、`apmib_*`、`websGetVar` 等。
- strings：URL-like、CGI-like、ASP-like、HTML/JS 片段、参数名候选、配置 key、错误字符串、认证/状态关键词。
- functions：函数名、地址、大小、调用数量、被调用数量。
- string xrefs：每个关键字符串被哪些函数引用。
- sink xrefs：哪些函数调用或引用危险 sink。
- parameter reader xrefs：哪些函数调用 `websGetVar`、`cgiFormString`、`getenv` 等参数读取 API。
- config access xrefs：哪些函数访问 `nvram_get/set`、`uci_get/set`、`apmib_get/set`。
- candidate handler mappings：从字符串和函数指针邻近关系中提取 `{ route/action/form, handler }` 候选。
- pseudo-code snippets：可选。对高价值函数导出短伪代码片段，但不要把整份反编译结果塞进 JSON。

### 5.4 Codex 二次分析内容

Codex 或普通 Python parser 读取 IDA artifacts 后做二次融合：

```text
1. 把 URL-like 字符串与 frontend/config artifacts 对齐。
2. 把 route/action/form 字符串与附近函数 xref 绑定为 handler 候选。
3. 把参数名候选与参数读取函数 xref 绑定。
4. 把 sink xref 与 handler 函数、调用图距离绑定。
5. 把响应字符串作为 feedback 伪覆盖信号。
6. 输出统一 `web_backend_binary_artifacts.json`。
```

注意：二次分析可以给 confidence，但不要在 analyzer 阶段丢弃低置信事实。后续 evaluator/fusion/seed/fuzzer 再负责筛选和排序。

## 6. 输出 JSON Schema 建议

建议新增 artifact 类型：`web_backend_binary`。

顶层结构：

```json
{
  "version": "1.0",
  "artifact_type": "web_backend_binary",
  "input_type": "unreadable_web_backend_binary",
  "binary": {
    "source_file": "...",
    "sha256": "...",
    "size": 0,
    "format": "ELF",
    "arch": "mips",
    "bits": 32,
    "endian": "little",
    "entry": "0x..."
  },
  "routes": [],
  "handlers": [],
  "route_mappings": [],
  "params": [],
  "constraints": [],
  "config_accesses": [],
  "sinks": [],
  "auth_hints": [],
  "state_hints": [],
  "strings": [],
  "functions": [],
  "xrefs": [],
  "callgraph_edges": [],
  "analysis_warnings": [],
  "summary": {}
}
```

关键对象应保留 evidence：

```json
{
  "source_file": "...",
  "tool": "ida",
  "parser": "string_xref|sink_xref|handler_table|param_reader",
  "address": "0x...",
  "function": "sub_401234",
  "snippet": "...",
  "confidence": "low|medium|high"
}
```

## 7. 面向 Web 后端的二进制启发式规则

第一版不需要完整 taint，先做轻量、可复用的规则。

### 7.1 Route/handler 候选

高价值字符串模式：

```text
/goform/...
/cgi-bin/...
/HNAP1/...
*.cgi
*.asp
*.htm
*.html
apply.cgi
setup.cgi
login.cgi
```

映射启发式：

- URL 字符串和函数指针出现在同一个只读数据表附近。
- URL/action 字符串被某个函数引用，该函数又调用参数读取 API。
- `websFormDefine`、`websUrlHandlerDefine`、`cgi_register`、`ejRegister`、`asp_register` 附近的字符串和函数指针。

### 7.2 参数候选

参数名来源：

- `websGetVar(wp, "name", ...)` 的字符串参数。
- `cgiFormString("name", ...)` / `cgiFormInteger("name", ...)`。
- `get_cgi("name")`、`getVar("name")`、`get_single("name")`、`GetValue("name")`。
- 与 `QUERY_STRING`、`CONTENT_LENGTH`、`HTTP_COOKIE` 邻近的 split/parse 逻辑。
- frontend artifacts 中出现、且在 binary strings 中复现的名字。

### 7.3 约束候选

约束来源：

- 参数读取后附近出现 `atoi`、`strtol`、`inet_addr`、`sscanf`。
- 参数变量附近出现 `strlen` 和数字比较。
- 参数变量附近出现 `strcmp/strncmp/strcasecmp` 和固定字符串。
- 参数字符串被复制到固定大小栈/全局 buffer 前的长度检查。

### 7.4 Sink 候选

sink 分类：

```text
command: system, popen, execl, execv, spawn, doSystem
memory: strcpy, strcat, sprintf, vsprintf, memcpy, gets
file: fopen, open, unlink, remove, rename, chmod, chown
config: nvram_set, nvram_commit, uci_set, uci_commit, apmib_set
state: reboot, restart, kill, service restart, firmware upgrade, restore
network: socket, connect, send, recv
```

MVP 只需要记录 sink 与函数、字符串、参数读取点之间的近似距离：

```text
handler/function -> param reader -> same function sink
handler/function -> calls helper -> sink
handler/function -> config key -> state sink
```

## 8. 与现有三层 artifacts 的融合

二进制 artifacts 不应替代已有三层结果，而应补齐缺口。

融合策略：

- frontend 发现 URL，binary 发现同名 URL 或 handler xref：提高 route 置信度。
- config 发现 CGI alias，binary 发现 CGI handler：建立 URL 到二进制入口的映射。
- readable backend 发现参数，binary 中同名字符串出现：补充参数证据。
- binary 发现 sink，frontend/config/readable backend 发现对应入口：标记 seed 的 sink proximity。
- binary 发现响应/error 字符串：进入 feedback 伪覆盖词典。

融合后的核心关系仍然遵循系统目标：

```text
URL -> handler -> 参数 -> 类型/约束 -> 数据流/近似距离 -> sink -> 风险标签
```

## 9. MVP 实施路线

### 阶段 1：批处理预处理器

目标：先跑通路径 B。

交付物：

```text
analyzer/web_backend_binary_analyzer/web_backend_binary_analyzer.py
analyzer/web_backend_binary_analyzer/ida_scripts/extract_web_facts.py
analyzer/web_backend_binary_analyzer/README-web-backend-binary-analyzer.md
analyzer/web_backend_binary_analyzer/output/*.web_backend_binary_artifacts.json
```

能力：

- 扫描 `collector/output/unreadable_files/web_backend_sources`。
- 识别二进制候选。
- 调用 IDA batch/headless。
- 输出 JSON。
- 不要求 Codex 直接连接 IDA。

### 阶段 2：MCP 自动打开能力

目标：解决“必须手动打开 IDA”的问题。

交付物：

```text
analyzer/web_backend_binary_analyzer/ida_mcp_driver.py
配置文档：如何启动 IDA 锚点或配置 --ida-rpc
健康检查命令：list_instances/open_file/select_instance
```

验收标准：

```text
mcp__idapromcp.list_instances 能看到至少一个实例
mcp__idapromcp.open_file(binary, autonomous=true, switch=true) 成功
Codex 能继续通过 MCP 查询当前 IDA 数据库
```

### 阶段 3：二次融合与 seed 输入

目标：把 binary artifacts 接入后续 seed/fuzzer。

交付物：

```text
analyzer/artifact_fusion/ 或 seed/fusion 模块
统一 intermediate representation
feedback 伪覆盖字符串词典
sink-aware seed metadata
```

## 10. 工程建议

建议不要把所有分析都放进 Codex 与 IDA 的交互循环里。更稳的结构是：

```text
IDA 负责精确机械抽取
Codex 负责解释、归纳、补全和生成下一步规则
普通 Python 负责批量、去重、融合、schema 校验
```

原因：

- IDA 批处理适合大量样本，失败可重试，产物可缓存。
- Codex MCP 适合难样本深挖，但不适合作为每个文件的唯一入口。
- JSON artifacts 可以被版本化、复查、合并，也能避免反复打开大型二进制。

## 11. 结论

手动打开 IDA 的问题可以解决，但需要把当前 MCP 配置补成以下任一模式：

```text
模式 A：启动常驻 IDA 锚点，让 idapromcp.list_instances 非空，再由 open_file 自动打开目标二进制。
模式 B：在 idapromcp 中配置显式 --ida-rpc/IDA 路径，让 MCP 代理可以自行启动 IDA。
```

在该配置完成后，可以直接实现 Codex -> IDA MCP -> 自动打开二进制 -> 自动抽取 artifacts 的路径。

如果短期不能完成该配置，系统仍然可以通过 IDA batch/headless 先自动预处理二进制，再让 Codex 分析预处理 JSON。这个降级方案更适合作为 MVP，因为它稳定、批量友好，并且完全符合 `Overall-System-Process.md` 中“GPL 离线知识提取，引导黑盒 fuzzing”的系统边界。
