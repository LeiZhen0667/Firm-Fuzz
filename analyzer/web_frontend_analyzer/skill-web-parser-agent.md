# Skill: Web Frontend Parser Agent（子模块迭代指南）

## 1. 目的

该 skill 用于指导 Codex 对 `web_frontend_analyzer` 做增量迭代，让脚本逐步具备更强通用提取能力。

本 skill 不做漏洞判断、不生成 payload、不进行破坏性请求。

## 2. 当前子模块目标

围绕真实 Web 前端输入，稳定提取：

- routes / methods
- params（name/location/default/options）
- constraints（长度、格式、required/readonly/disabled/enctype）
- auth_hints / state_hints
- ui_context / template_vars / references

## 3. 输入与执行

统一入口：

```bash
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py <input> -o frontend_artifacts.json
```

输入支持：

- 文件路径
- 目录路径
- JSON 输入文件（`--input-format json`）

## 4. 每轮操作流程（按此执行）

1. 运行当前脚本提取结果（先跑，不先改）。
2. 对比“输入文件内容”与“提取输出”。
3. 归纳漏掉的通用模式。
4. 判断该模式对应模块：
   - `html_form_parser`
   - `js_api_parser`
   - `template_parser`
   - `regex_route_miner`
   - `param_name_miner`
   - `ui_context_parser`
   - `auth_token_parser`
   - `evidence_fusion`
5. 优先改规则/正则；规则无法表达时再改代码。
6. 做最小 patch，不改无关模块。
7. 运行轻量自检并确认 JSON 可解析。
8. 输出本轮新增模式和剩余缺口。

## 5. 约束

- 不重写框架，只做增量改进。
- 禁止厂商/型号/样本路径硬编码。
- 禁止只服务单页面的特化逻辑。
- 当前阶段不要求置信度评估流程。
- 当前阶段不要求样例测试流程。
- 默认输入是实际 Web 内容，不依赖额外测试样本。

## 6. 自检命令

```bash
python3 -m py_compile analyzer/web_frontend_analyzer/*.py
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py <input> -o /tmp/frontend_artifacts.json
python3 -m json.tool /tmp/frontend_artifacts.json > /dev/null
```

## 7. 变更输出要求

每轮改动后需要给出：

1. 修改了哪些文件（脚本/规则）。
2. 新增了哪些通用提取模式。
3. 对应提升了哪些字段提取质量。
4. 当前仍未覆盖的模式列表（下一轮待补）。
