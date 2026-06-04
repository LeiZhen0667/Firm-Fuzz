# Seeds Template 模块

本目录用于保存 Web 管理界面“种子模板爬取模块”及其相关文档，供后续模糊测试模块直接复用。

## 目录结构

- `burp_seed_crawler.py`
  - 通用种子模板爬取脚本
- `crawler_config.example.json`
  - 示例配置文件
- `README.md`
  - 本模块入口说明
- `README_种子模板爬取模块.md`
  - 模块设计和配置说明
- `README_种子模板使用说明.md`
  - 输出结果如何给后续 fuzz 模块使用

## 快速开始

使用命令行参数运行：

```bash
python3 burp_seed_crawler.py \
  --base-url http://192.168.2.1/ \
  --proxy-url http://127.0.0.1:8080 \
  --output-dir ./device_seed_output \
  --use-selenium
```

使用配置文件运行：

```bash
python3 burp_seed_crawler.py --config ./crawler_config.example.json
```

## 模块定位

本模块负责：

- 自动遍历目标 Web 管理界面
- 经 Burp 抓取请求流量
- 发现页面、表单、端点和字段
- 生成标准化的种子模板输出

本模块不负责：

- 登录态管理
- 最终请求重放
- 参数变异执行
- 崩溃检测

这些工作应由后续 fuzz 模块完成。

## 推荐工作流

1. 启动固件仿真和 Web 服务
2. 启动 Burp 并确认代理可用
3. 运行本模块进行模板爬取
4. 读取 `device_seed_output/` 中的模板结果
5. 结合 Burp 中抓到的真实 baseline 请求构建 fuzz seeds

## 输出结果

默认输出目录中将包含：

- `crawl_summary.json`
- `seed_templates.json`
- `seed_templates.jsonl`
- `README_seeds.txt`
- `snapshots/`

更详细的说明请查看：

- `README_种子模板爬取模块.md`
- `README_种子模板使用说明.md`
