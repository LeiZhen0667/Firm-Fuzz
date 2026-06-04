# 种子模板爬取模块说明

## 1. 模块定位

`burp_seed_crawler.py` 是一个面向 Web 管理界面的通用化种子模板爬取模块。

该模块的职责是：

- 自动访问目标设备 Web 管理界面
- 通过 Burp 代理转发所有请求
- 抓取页面、表单、链接和提交目标
- 生成后续模糊测试可消费的“种子模板”

这个模块不负责真正执行模糊测试，也不负责大规模发送变异请求。

它的定位是 fuzz 流水线中的“前置资产采集器”，用于为后续 fuzz 模块提供：

- 页面级快照
- 接口级目录
- 表单级参数模板
- 变异目标字段集合

## 2. 模块文件

当前模块主文件为：

- `burp_seed_crawler.py`

建议后续在远端工作目录中也保留同名文件，例如：

- `~/Fuzz-seeds/burp_seed_crawler.py`

## 3. 模块功能概述

该脚本具备以下能力：

- 支持通过 HTTP 代理访问目标设备
- 默认以相对安全的方式遍历页面
- 提取同主机下的链接、脚本、表单和端点
- 自动为表单生成 `seed_templates.json`
- 自动为全局页面与端点生成 `crawl_summary.json`
- 支持可选的 Selenium 浏览器模式
- 支持对前端跳转或简单 JS 渲染页面进行补抓

## 4. 配置方式

支持两种配置方式：

1. 命令行参数
2. JSON 配置文件

优先级为：

1. 命令行参数
2. 配置文件
3. 脚本默认值

## 5. 示例配置

可参考：

- `crawler_config.example.json`

示例：

```json
{
  "base_url": "http://192.168.2.1/",
  "proxy_url": "http://127.0.0.1:8080",
  "output_dir": "./device_seed_output",
  "max_pages": 80,
  "timeout": 10,
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) BurpSeedCrawler/1.0 Chrome/104 Safari/537.36",
  "use_selenium": true
}
```

## 6. 运行方式

命令行方式：

```bash
python3 burp_seed_crawler.py \
  --base-url http://192.168.2.1/ \
  --proxy-url http://127.0.0.1:8080 \
  --output-dir ./device_seed_output \
  --use-selenium
```

配置文件方式：

```bash
python3 burp_seed_crawler.py --config ./crawler_config.example.json
```

## 7. 输出文件

输出目录通常包含：

- `crawl_summary.json`
- `seed_templates.json`
- `seed_templates.jsonl`
- `README_seeds.txt`
- `snapshots/`

## 8. 用途边界

本模块负责“发现接口和参数”，不负责“发送最终 fuzz 请求”。

后续模块应结合 Burp 中抓到的真实 baseline 请求，补全请求头、Cookie、token 和其他上下文后，再执行变异和重放。
