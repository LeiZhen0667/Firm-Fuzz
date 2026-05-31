# Web Server Config Parser README

## 1. 子模块定位

`web_server_config_parser` 是 GPL-assisted black-box Web 服务模糊测试系统中的 Web server 配置层解析模块。

系统整体目标是在测试前离线分析 GPL 包中的可读材料，提取 Web 服务知识，并将这些知识用于后续 HTTP seed template 构建、参数约束补全、handler 映射和调度权重生成。该模块位于前端页面解析与后端 CGI/服务端代码解析之间，主要负责从可读 Web server 配置与启动相关文本中提取服务部署事实。

该模块不负责漏洞判断、payload 生成、真实设备探测或结果筛选。它只输出可复用的配置事实和对应 evidence。

## 2. 子模块目标

`web_server_config_parser` 的目标是从给定 JSON 中包含的 Web server 相关可读文件内容里提取：

- Web server 类型，例如 `boa`、`httpd`、`goahead`、`lighttpd`、`nginx`、`busybox httpd`、厂商自定义 httpd 线索；
- 监听地址与端口；
- document root / web root / server root；
- CGI alias、ScriptAlias、cgi-bin、CGI handler、`*.cgi` 映射；
- URL alias、static directory、index file；
- 认证目录、realm、password file、access control 线索；
- 启动脚本中的 Web server 启动命令、参数、配置文件路径；
- include/config reference 等配置引用；
- 每个结论对应的 source file、parser、pattern、line/snippet evidence。

这些信息用于帮助后续模块建立：

```text
URL / prefix / alias → filesystem path → CGI handler / web root → auth requirement → seed template context
```

## 3. 输入

本模块输入固定为一个 JSON 文件，即 Web server 配置候选文件集合。

输入 JSON 的顶层结构建议保持为：

```json
{
  "version": "1.0",
  "input_type": "web_server_config_sources",
  "files": [
    {
      "source_file": "...",
      "content": "..."
    }
  ]
}
```

字段含义：

- `version`：输入格式版本；
- `input_type`：应为 `web_server_config_sources`；
- `files`：待解析文件列表；
- `files[].source_file`：原始 GPL 文件路径；
- `files[].content`：该文件的可读文本内容。

解析器只应依赖该 JSON 中的 `source_file` 和 `content`，不应假设原始 GPL 工作树仍然存在。

## 4. 输出

输出为 JSON 文件，保存到命令行 `-o` 指定路径。推荐默认输出名：

```text
web_server_config_artifacts.json
```

输出应保持结构化、可被后续 seed builder 和 evidence fusion 消费。建议顶层结构为：

```json
{
  "version": "1.0",
  "artifact_type": "web_server_config",
  "source_input": "...",
  "servers": [],
  "listeners": [],
  "document_roots": [],
  "aliases": [],
  "cgi_mappings": [],
  "auth_rules": [],
  "startup_commands": [],
  "config_references": [],
  "routes": [],
  "references": [],
  "parse_warnings": [],
  "summary": {}
}
```

核心字段说明：

- `servers`：识别到的 Web server 类型和版本线索；
- `listeners`：监听地址、端口、协议线索；
- `document_roots`：Web root、server root、static root；
- `aliases`：URL prefix 到文件系统路径的映射；
- `cgi_mappings`：CGI alias、ScriptAlias、cgi-bin、扩展名 handler；
- `auth_rules`：认证目录、realm、密码文件、访问控制规则；
- `startup_commands`：启动脚本中的 httpd/boa/goahead/lighttpd/nginx 命令及参数；
- `config_references`：include、配置文件路径、额外引用；
- `routes`：从配置中可直接推导的 URL 或 route prefix；
- `references`：暂不能归入核心对象但有交叉验证价值的路径、文件名或配置引用；
- `parse_warnings`：解析异常、编码问题、无法分类但值得复核的问题；
- `summary`：面向人工快速查看的数量统计。

每条对象都应尽量包含 evidence：

```json
{
  "source_file": "...",
  "parser": "web_server_config_parser",
  "pattern": "...",
  "line": 0,
  "snippet": "..."
}
```

## 5. 建议目录结构

推荐放在 analyzer 目录下：

```text
analyzer/
└── web_server_config_parser/
    ├── web_server_config_parser.py
    ├── parsers/
    │   ├── server_type_parser.py
    │   ├── listener_parser.py
    │   ├── root_alias_parser.py
    │   ├── cgi_mapping_parser.py
    │   ├── auth_rule_parser.py
    │   └── startup_command_parser.py
    ├── rules/
    │   └── web_server_config_rules.yaml
    └── README.md
```

目录职责：

- `web_server_config_parser.py`：统一入口，读取输入 JSON、调度子 parser、写出 artifacts；
- `parsers/server_type_parser.py`：识别 Web server 类型；
- `parsers/listener_parser.py`：提取端口、监听地址、协议；
- `parsers/root_alias_parser.py`：提取 document root、alias、static root；
- `parsers/cgi_mapping_parser.py`：提取 CGI alias、ScriptAlias、cgi-bin、扩展名 handler；
- `parsers/auth_rule_parser.py`：提取认证目录、realm、password file、access control；
- `parsers/startup_command_parser.py`：提取启动脚本中的 Web server 命令和参数；
- `rules/web_server_config_rules.yaml`：存放可迁移的通用规则与正则。

## 6. 基础解析脚本

统一执行入口建议为：

```bash
python3 analyzer/web_server_config_parser/web_server_config_parser.py \
  web_server_config_sources.readable.json \
  -o web_server_config_artifacts.json
```

脚本基础职责：

1. 读取输入 JSON；
2. 遍历 `files[]`；
3. 对每个 `content` 执行通用规则匹配；
4. 提取 Web server 类型、监听端口、root/alias、CGI 映射、认证规则、启动命令；
5. 为每条提取结果保留 evidence；
6. 合并重复对象，但不做价值筛选；
7. 写出 JSON artifacts；
8. 生成 `summary` 统计字段。

## 7. 与其他模块的关系

该模块输出主要被以下后续模块使用：

- `web_frontend_analyzer`：将前端发现的 route 与配置中的 alias/root/cgi-bin 映射交叉验证；
- `c_cgi_parser` / `binary_string_parser`：把 URL prefix 或 CGI 文件路径关联到 handler、参数读取和 sink；
- `seed_template_builder`：利用 document root、CGI alias、auth rule 和 startup command 补全 HTTP template；
- `evidence_fusion`：融合前端、配置、源码、二进制中的 route/handler evidence。

## 8. 第一阶段边界

这里的第一阶段是该子模块的 MVP 实现范围，不是长期全部目标。

第一阶段优先做到：

```text
能识别 Web server 类型
能识别监听端口和 document root
能识别 CGI alias / ScriptAlias / cgi-bin / *.cgi
能识别认证目录和密码文件
能识别启动脚本中的 httpd/boa/goahead/lighttpd/nginx 命令
能输出 evidence
能生成 JSON 和 summary
```

暂不要求：

```text
完整配置语法解析器
跨文件 include 解析闭包
精确 URL rewrite 求值
复杂变量展开
完整 C 源码数据流分析
漏洞判断
payload 生成
真实设备探测
```

## 9. 设计原则

- 只提取事实，不判断漏洞；
- 不生成 payload；
- 不执行真实设备请求；
- 不根据“是否有价值”过滤结果；
- 不写厂商、型号、样本路径硬编码；
- 优先使用通用规则；
- 每条结果必须尽量保留 evidence；
- 输出保持完整，后续 evaluator 再负责筛选、排序和打分。
