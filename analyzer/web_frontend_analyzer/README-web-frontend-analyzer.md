# Web Frontend Analyzer README（对子模块）

## 1. 子模块目标（对齐系统总目标）

`web_frontend_analyzer` 的目标是把 Web 前端文件中的可用接口知识提取成结构化 JSON，供后续 HTTP/CGI 黑盒 fuzzing 使用。

本模块仅做信息提取，不做漏洞判断，不生成 fuzz payload，不做破坏性请求。

提取范围：

- route / URL / endpoint
- HTTP method
- 参数名、参数位置、默认值、枚举值
- 约束（`maxlength`、`pattern`、`required`、`readonly`、`disabled`、`enctype` 等）
- 认证线索（`token/csrf/nonce/session/cookie/login/logout/password`）
- 状态线索（`apply/save/reboot/restart/reset/restore/upgrade`）
- UI 语义上下文（`title/heading/label/button/menu/page filename`）
- references（页面跳转、资源中的 route 线索）

## 2. 当前目录结构

```text
analyzer/web_frontend_analyzer/
├── web_frontend_analyzer.py      # 主入口
├── web_frontend_parser.py        # 核心提取实现（通用规则）
├── input_adapter.py              # 输入适配（路径/目录/JSON）
├── html_form_parser.py
├── js_api_parser.py
├── template_parser.py
├── regex_route_miner.py
├── param_name_miner.py
├── ui_context_parser.py
├── auth_token_parser.py
├── dynamic_probe_adapter.py      # 可选，GET/HEAD 安全探测
└── evidence_fusion.py            # 去重融合
```

说明：模块化脚本已补齐，当前运行入口统一为 `web_frontend_analyzer.py`。

## 3. 执行方式

输入支持三种：

1. 单文件路径
2. 目录路径（递归识别前端文件）
3. JSON 输入文件（用于接前一子模块输出）

命令：

```bash
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py <input_path> -o frontend_artifacts.json
```

如果不传 `-o`，输出默认写入：

```text
analyzer/web_frontend_analyzer/output/<input_stem>.artifacts.json
```

指定 JSON 输入：

```bash
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py input.json --input-format json -o frontend_artifacts.json
```

打印输入 JSON 标准模板：

```bash
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py dummy --print-input-template
```

## 5. 输出 JSON 结构

每个输入文件对应一个 artifact：

```json
{
  "source_file": "...",
  "artifact_type": "html",
  "routes": [],
  "params": [],
  "constraints": [],
  "auth_hints": [],
  "state_hints": [],
  "ui_context": [],
  "template_vars": [],
  "sinks": [],
  "references": []
}
```

说明：当前输出保留 `source/confidence/evidence` 字段作为溯源信息，不影响上游使用；你当前流程可忽略置信度，只消费提取事实。
