# 03 · 资源层（res / ARSC / assets / raw）

## 解码

```bash
apktool d -s -f target.apk -o apktool/        # -s 只解资源，不动 dex
aapt2 dump resources target.apk > res.txt     # 全量资源表（ID → 值）
aapt2 dump xmltree target.apk res/xml/network_security_config.xml
```

**apktool 会重命名资源目录**：`drawable-xhdpi-v4` → `drawable-xhdpi`，并丢弃 ≤minSdk 的
`-vN` 后缀。做“解码覆盖率”统计时必须按 (类型, 密度, 版本) 三元组归一，否则会误报大量缺失。

## 高价值区域（按经验排序）

| 区域 | 常见收获 |
|---|---|
| `res/raw/` | OAuth `client_secret`、推送通道参数、链接拦截页、H5 注入脚本、JSAPI 白名单 |
| `res/xml/` | `network_security_config`、provider 路径、快捷方式、备份规则 |
| `assets/config/*.json` | 客户端默认开关（几百到几千个 key），是“改行为最省力”的入口 |
| `assets/**/js/*.js` | 注入到每个 H5 页面的脚本（调试开关、埋点、桥接） |
| `values-*/strings.xml` | 品牌替换范围、调试文案、隐藏入口、错误码文案 |
| 多语言差异 | 某语言漏替换 = 白标/OEM 痕迹，可反推构建流水线 |

## 覆盖率与统计

```python
# AXML 是否为二进制：前 4 字节 0x03 0x00 0x08 0x00
# 解码成功率 = 成功 XML 数 / (成功 + 失败)
```

`resources.arsc` 展开后统计：`values` 目录数、`strings` 条数、`public.xml` 的 ID 数。
注意不同口径（locale 展开 vs 默认包）不可直接比较，报告里要写清口径。

## 多语言与品牌

- 默认 `values/` 往往是**英文基底**，中文在 `values-zh`；
- 逐 locale 统计品牌词（原品牌 vs 白标词）可判断“白标是否完整”；
- 空壳 locale（几十条）说明是机翻占位，不是目标市场。

## 调试/隐藏入口的资源线索

- 布局文件名含 `dev`/`debug`/`mock`/`test` → 直接列出；
- 一个布局里几十个 `btn_*`/`et_*` id、但 strings 里搜不到文案 → 说明文案是代码 `setText`
  硬编码，**必须读代码**才能知道每个控件干嘛；
- `h5_bugme_*`、`*_js_debug`、`chrome` 端口号之类字符串，常是 WebView 调试入口。

## assets 里的“可被外部影响”的配置

`default_config.json` / `custom_config.json` 这类文件是**出厂默认值**，运行时可被
服务端下发覆盖。要做行为对照，先记录默认值，再对比运行时的实际值（DevSetting/日志）。

## 坑

- `resources.arsc` 在 zip 里常是 **stored**（不压缩），重建时不要改压缩方式；
- 直接编辑二进制 AXML 只能改**已有属性的值**（比如 `exported` 的布尔位），
  增删属性/元素需要重编码（apktool）或自写 AXML 生成器；
- 改资源同样破坏 v2/v3 签名，必须重签。
