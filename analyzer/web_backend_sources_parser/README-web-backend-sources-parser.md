# Web Backend Sources Parser

## 1. 模块定位

`web_backend_sources_parser` 是 GPL-assisted black-box Web 服务模糊测试系统中的后端源码可读文件解析模块。

系统整体目标是在离线阶段从 GPL 包中提取 Web 服务相关知识，再将这些知识用于后续 HTTP 种子模板、参数约束、sink 风险信息和调度依据的构建。该模块位于 “Web 服务相关文件识别” 之后、“接口—参数—约束—sink 知识图谱构建” 之前，负责从可读后端源码或后端配置式源码文件中抽取后端侧事实。

该模块只解析 GPL 中已经被上游识别为 `web_backend_sources` 的可读文件。它不访问真实设备，不生成 payload，不判断漏洞，不执行动态探测。

## 2. 子模块目标

该模块的目标是从 Web 后端可读文件中稳定提取与 Web 接口、参数、约束和 sink 相关的事实，包括但不限于：

- handler / route / endpoint 注册信息；
- URL 到后端函数、CGI handler、回调函数的映射；
- HTTP 参数读取点；
- query/body/cookie/header/env 等参数来源；
- 参数默认值、类型线索、长度检查、格式检查、枚举判断；
- 配置读写行为，例如 nvram、uci、config_get、config_set；
- 文件、命令、网络、内存相关 sink；
- 响应字符串、错误字符串、日志字符串；
- 认证、会话、权限检查相关线索；
- 状态修改行为，例如 apply、save、reboot、restart、reset、upgrade；
- 每个提取结果对应的 evidence。

该模块输出的是后端源码层面的结构化事实，用于后续与 frontend parser、web server config parser、binary/string parser 和 seed builder 进行融合。

## 3. 输入

输入固定为上游生成的 JSON 文件，类型为 `web_backend_sources`。

执行脚本不应依赖原始 GPL 工作树，也不应要求重新扫描文件系统。它只读取 JSON 中的 `files[].source_file` 和 `files[].content`。

输入文件结构：

```json
{
  "version": "1.0",
  "input_type": "web_backend_sources",
  "files": [
    {
      "source_file": "...",
      "content": "..."
    }
  ]
}
```

其中：

- `version` 表示输入格式版本；
- `input_type` 应为 `web_backend_sources`；
- `files` 是可读后端候选文件列表；
- `source_file` 是原始 GPL 文件路径，仅作为来源标识和 evidence；
- `content` 是该文件的文本内容。

## 4. 输出

输出为 JSON 文件，由命令行 `-o` 指定保存路径。

建议输出路径：

```text
artifacts/web_backend_sources_artifacts.json
```

输出应包含按文件或全局汇总的后端解析结果。推荐顶层结构：

```json
{
  "version": "1.0",
  "input_type": "web_backend_sources",
  "artifact_type": "web_backend_sources",
  "source_count": 0,
  "files": [],
  "handlers": [],
  "routes": [],
  "params": [],
  "constraints": [],
  "config_accesses": [],
  "sinks": [],
  "auth_hints": [],
  "state_hints": [],
  "strings": [],
  "references": [],
  "parse_warnings": [],
  "summary": {}
}
```

每个提取对象应尽量保留 evidence：

```json
{
  "source_file": "...",
  "parser": "...",
  "pattern": "...",
  "line": 0,
  "snippet": "..."
}
```

## 5. 建议目录结构

```text
analyzer/web_backend_sources_parser/
├── web_backend_sources_parser.py
├── schema.py
├── rules.py
├── parsers/
│   ├── handler_parser.py
│   ├── route_parser.py
│   ├── param_read_parser.py
│   ├── constraint_parser.py
│   ├── config_access_parser.py
│   ├── sink_parser.py
│   ├── auth_state_parser.py
│   └── string_reference_parser.py
└── README.md
```

该目录结构是模块组织建议。实际实现可以从单文件脚本开始，再随着规则增加逐步拆分。

## 6. 基础解析脚本

统一执行入口：

```bash
python3 analyzer/web_backend_sources_parser/web_backend_sources_parser.py <input_json> -o <output_json>
```

脚本职责：

1. 读取 `web_backend_sources` JSON；
2. 遍历 `files[]`；
3. 对每个 `content` 执行后端源码文本解析；
4. 提取 handler、route、params、constraints、config_accesses、sinks、auth/state hints、strings、references；
5. 为每条结果保留 evidence；
6. 输出 JSON 到 `-o` 指定路径。

脚本不负责：

- 判断漏洞；
- 生成 fuzzing payload；
- 过滤低价值结果；
- 评估 endpoint 是否值得 fuzz；
- 连接真实设备；
- 运行编译器或执行 GPL 代码。

## 7. 主要解析能力

### 7.1 handler / route 解析

识别后端中常见的接口注册、handler 表、URL 映射和回调函数绑定。

关注内容包括：

- URL 字符串；
- handler 函数名；
- route 到函数的映射；
- CGI 名称；
- dispatch table；
- method 线索；
- module/action/cmd 类分发字段。

### 7.2 参数读取解析

识别后端从 HTTP 请求中读取参数的代码模式。

关注内容包括：

- `websGetVar`、`websGetVar2`；
- `getenv("QUERY_STRING")`、`getenv("CONTENT_LENGTH")`；
- `cgiFormString`、`cgiFormInteger`；
- `get_cgi`、`getVar`、`get_single`、`GetValue` 等通用命名模式；
- cookie/header/env 读取；
- query string 或 form body 解析逻辑。

### 7.3 约束解析

识别参数附近的类型转换、比较、长度检查和格式检查。

关注内容包括：

- `atoi`、`strtol`、`atol`；
- `strlen`、`sizeof`、长度比较；
- `strcmp`、`strncmp`、枚举分支；
- `sscanf`、`inet_addr`、IP/MAC/路径格式线索；
- null check、empty check；
- min/max 边界判断。

### 7.4 配置读写解析

识别后端代码对运行时配置的读取和写入。

关注内容包括：

- `nvram_get`、`nvram_set`、`nvram_commit`；
- `uci_get`、`uci_set`、`uci_commit`；
- `config_get`、`config_set`；
- `apmib_get`、`apmib_set`；
- key 名、默认值、关联参数。

### 7.5 sink 解析

识别参数或配置可能流向的敏感操作点。

关注内容包括：

- 命令执行：`system`、`popen`、`exec*`；
- 文件操作：`fopen`、`open`、`unlink`、`rename`；
- 内存操作：`strcpy`、`strcat`、`sprintf`、`memcpy`；
- 网络操作：socket/connect/send；
- 配置提交与服务重启；
- 固件升级、恢复出厂、重启等状态修改操作。

### 7.6 auth/state/string 线索解析

识别认证、会话、权限、状态修改和响应文本线索。

关注内容包括：

- login/logout/session/cookie/token/password；
- privilege/admin/auth/check；
- apply/save/reboot/restart/reset/restore/upgrade；
- error message、success message、日志字符串；
- 与前端或设备响应可对齐的提示字符串。

## 8. 与系统其他模块的关系

`web_backend_sources_parser` 的输出会与其他模块结果融合：

- 与 `web_frontend_analyzer` 融合，用前端 route/param 补充后端 handler 和约束；
- 与 `web_server_config_parser` 融合，用配置中的 CGI alias、document root、handler 映射定位后端入口；
- 与 binary/string parser 融合，用字符串和符号补充无源码 handler；
- 输出给 seed builder，用于构造带参数、约束、sink 标签和 evidence 的 HTTP seed template；
- 输出给后续 evaluator / fusion 模块，由它们负责过滤、排序、置信度融合和 fuzz 优先级判断。

## 9. MVP 边界

本节描述该模块的第一阶段实现范围，不代表长期全部目标。

第一阶段优先做到：

```text
能读取 web_backend_sources JSON
能识别 handler / route / CGI 名称
能识别常见 HTTP 参数读取点
能识别参数附近的类型转换、长度检查、strcmp 枚举
能识别 nvram/uci/config/apmib 配置读写
能识别 system/popen/exec、strcpy/sprintf、fopen/unlink 等 sink
能识别 auth/state 关键词线索
能输出 evidence
能生成 JSON 和 summary
```

暂不要求：

```text
完整 C/C++ AST 解析
跨函数数据流分析
复杂宏展开
完整预处理器求值
复杂指针别名分析
精确 taint analysis
漏洞判断
payload 生成
真实设备探测
结果筛选或优先级排序
```
