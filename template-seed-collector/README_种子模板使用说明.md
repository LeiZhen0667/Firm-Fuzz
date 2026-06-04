# Web 管理界面种子模板使用说明

## 1. 文档目的

本文档用于说明“自动遍历 Web 管理界面并经 Burp 抓包”产出的结果应该如何被后续模糊测试模块使用。

目标不是直接把这些模板当成最终请求发送，而是把它们作为“接口骨架”和“参数变异起点”，再结合真实有效的 HTTP 请求上下文，构造可重放、可变异、可自动化执行的 fuzz 种子。

## 2. 当前输出结果

当前种子模板生成阶段的主要输出目录如下：

- `device_seed_output/`

目录内核心文件如下：

- `crawl_summary.json`
- `seed_templates.json`
- `seed_templates.jsonl`
- `snapshots/`
- `README_seeds.txt`

## 3. 核心定位

这一步的输出不是“最终 fuzz 请求”，而是后续构建 fuzz 请求时的中间表示。

建议理解为三类资产：

- 接口字典
- 参数字典
- 初始值字典

## 4. `seed_templates.json` 的作用

每个条目表示一个表单模板，主要包含：

- `target`
- `method`
- `risky`
- `source_page`
- `form_id`
- `seed_values`

其中 `seed_values` 表示后续 fuzz 时应重点考虑变异的字段。

## 5. 标准使用方式

后续 fuzz 模块的推荐流程如下：

1. 读取 `seed_templates.json`
2. 为每个模板匹配一条真实 baseline 请求
3. 保留 baseline 请求的必要请求头和上下文
4. 使用模板中的字段作为变异点
5. 生成 baseline seed
6. 基于 baseline seed 执行变异和重放

## 6. 请求头处理原则

模板不默认固化完整请求头。

后续模块应优先从真实请求继承：

- `Host`
- `Content-Type`
- `Origin`
- `Referer`
- `Cookie`
- 认证或 CSRF 相关头

而 `Content-Length` 等字段可由发送器自动计算。

## 7. 示例

例如以下模板：

```json
{
  "kind": "form_template",
  "target": "http://192.168.2.1/goform/formSetLanguage",
  "method": "POST",
  "risky": true,
  "source_page": "http://192.168.2.1/000-dashboard.asp",
  "form_id": "dashboard_ChLang",
  "seed_values": {
    "langtype": "",
    "webpage": ""
  }
}
```

后续模块应：

- 用真实请求补齐头部和真实参数值
- 将 `langtype` 和 `webpage` 作为变异目标
- 直接重放该 HTTP 请求，而不是重新点击页面按钮

## 8. 总结

模板负责说明“改什么”，baseline 请求负责说明“怎么发才有效”。

后续模块必须将两者结合，才能构建真正可自动化执行的 fuzz seeds。
