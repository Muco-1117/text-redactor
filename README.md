# Text Redactor

给别人发日志、导出表格或配置示例之前，批量替换邮箱、手机号、IP、凭据等内容。所有处理在本机完成，生成新副本，保留原文件。

适用于排查问题时分享日志、准备脱敏测试数据、向外部协作者发送配置片段等日常工作。不依赖大模型 API，不上传文档，不保存原文到替换关系表。

## 快速开始

需要 Python 3.11+，无需安装第三方依赖。在项目目录运行：

```powershell
# 只查看命中数量，不输出脱敏文件
python text_redactor.py "D:\exports\support.log" --check

# 输出新文件，原文件保持不变
python text_redactor.py "D:\exports\support.log" --output "D:\exports\support.sanitized.log"

# 批量处理整个目录，输出目录必须在输入目录之外且尚不存在
python text_redactor.py "D:\exports\raw" --output "D:\exports\sanitized"
```

同一批次相同邮箱会被稳定替换为同一标记，如 `[EMAIL_001]`，便于继续追踪一条日志里的关联关系。不同批次的标记编号不保证相同。

## 能处理什么

| 类型 | 处理方式 |
| --- | --- |
| 邮箱 | 替换匹配的邮箱地址 |
| 中国大陆手机号 | 识别连续 11 位号码及可选 `+86` 前缀 |
| 中国居民身份证格式 | 识别 18 位格式候选，不验证行政区划和校验位 |
| IPv4 | 验证每段范围后替换 |
| 已知 Key 与私钥 | 部分 GitHub、模型 API、AWS Key 前缀及完整 PEM 私钥块 |
| 凭据赋值 | 常见 `api_key`、`password`、`token` 等配置赋值 |
| JSON / CSV 敏感字段 | 根据字段名替换密码、Token、凭据等值，包括短值 |
| 自定义内容 | 按本地词表中的原文精确匹配 |

需要额外隐藏姓名、项目名或内部域名时，将其写入本地 UTF-8 词表，一行一项：

```powershell
python text_redactor.py "D:\exports\raw" --output "D:\exports\sanitized" --terms-file "D:\private\terms.txt"
```

词表按字面匹配，不执行正则。词表自身应保存在私有位置。

## 格式与输出

- 支持 UTF-8/UTF-8 BOM。目录模式处理 `.txt`、`.md`、`.log`、`.json`、`.csv`、`.yaml`、`.yml`、`.ini`、`.conf`、`.env` 及 `.env.*`。
- JSON 按结构处理并重新格式化；数字和布尔值在非敏感字段中保持原类型。遇到重复 JSON 键拒绝处理，避免静默丢数据。
- CSV 按单元格处理，支持引号、逗号、跨行内容，输出仍可被 CSV 解析器读取。
- YAML 等其他文件按文本处理，不承诺保留其结构语义；这些格式需要人工复核。
- 目录输出先暂存整批结果，某个文件解析失败时不发布输出目录。
- 输出必须是新路径，不覆盖已有文件或目录；跳过符号链接和常见依赖目录，单文件上限 10 MB。
- 终端只输出文件数量和各类替换次数，不输出原文或替换关系。

## 使用边界

这是规则脱敏工具，不能保证识别所有隐私或秘密。它不自动识别人名、地址、图片、PDF、Word、IPv6、所有国家的电话号码或所有服务商的 Token。手机号和身份证需要以文本形式出现；JSON 普通数值字段不会被猜测为个人标识。

正则可能把版本号等内容当作 IP，或漏掉拆分、混淆和编码后的信息。输出文件的名称、目录名称不会脱敏，文件名也可能包含个人信息。分享前请检查结果；对严肃场景应使用自定义词表与人工复核。

## 验证

```powershell
python -m unittest discover -s tests -v
python -m py_compile text_redactor.py
```

测试覆盖稳定替换、嵌套 JSON、跨行 CSV、目录失败时不发布结果、只读检查和输出路径保护。GitHub Actions 在 Windows/Linux 与 Python 3.11/3.13 上运行。

退出码：`0` 成功（或检查无命中）；`1` `--check` 发现命中；`2` 参数、编码、格式或文件操作失败。
