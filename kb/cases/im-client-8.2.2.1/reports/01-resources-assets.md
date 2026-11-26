# 01 · 资源层与 assets 全解 — IM / IM 8.2.2.1（`<PKG>`）

> 分析员：res-analyst（task-1）｜工作目录 `D:\Deepseek-Harness-workspace\re\base_apk3\`
> 目标：`target.apk`，299,485,058 字节，SHA-256 `2433588b58436a0e55270f2a66c286f0fe7bc41618d7f5e069fc6ef99d609195`（只读，未修改）
> 标记约定：**【观察】**= 文件/命令直接可见；**【推断】**= 基于观察的判断，可被后续证伪；**【未知】**= 当前证据不足。
> 中间产物：`scan/res/`（脚本 `scan/res/gen_artifacts.py` 可重跑）；解码产物：`apktool/`。

---

## 0. 结论摘要（TL;DR）

| # | 结论 | 依据 |
|---|---|---|
| 1 | **资源解码 100% 覆盖**：13,088 个二进制 AXML 全部解成可读 XML，6,256 个二进制资源原样保留，**失败 0**；`resources.arsc` 展开为 64 个 `values*` 目录 / 102 个 XML，entries 总数见 §2 | §2、`scan/res/decode-coverage.tsv` |
| 2 | res 树 **86 个目录 / 19,344 文件 / 52.9 MB**；drawable 家族占 32.18 MB（60.8%），layout 家族 7,574 文件 / 16.58 MB | §3、`scan/res/res-tree.tsv` |
| 3 | **25 个 locale**（aapt2 给出 24 个 `application-label-*` + 默认）；但真正的"语言策略"是 **default=英文基底 25,381 条**，`values-zh` 17,587 条（中文主包），其余 23 个语言多为 17.0–18.4k 条的"同构翻译包"，`es/pt/sr/mk` 是 36–55 条的**空壳 locale** | §5、`scan/res/locale-strategy.tsv` |
| 4 | **品牌已被替换为 IM / IM**：默认包 582 条、zh 632 条、ru 685 条、fr 685 条含 IM；`app_name` = `IM`(0x7f11050d，默认/zh) / `IM`(en)。**但德语 `values-de` 一条都没替换，仍保留 591 条 "IM"** —— 这是全包唯一异常语言 | §6、`scan/res/brand-scan.tsv` |
| 5 | APK **v1+v2 签名均通过**，证书 `CN=alibaba,OU=alibaba,O=alibaba,L=hangzhou,ST=zhejiang,C=86`，有效期 **2014-08-01 → 2124-02-06**（100 年），`resources.arsc` 与 `AndroidManifest.xml` 均在 `MANIFEST.MF` 内 → **文件自签名以来未被改动**；因此 IM 品牌是**构建期**产物（厂商 OEM/白标），不是本地改包 | §1.3 |
| 6 | **主题链**：`DtTheme.Normal`(0x7f120183, 23 项) → `DtTheme.Base`(29 项) → `Theme.AppCompat.DayNight.DarkActionBar` → … → `android:Theme.Material.Light.NoActionBar`；全包 1,342 个 style，`DtTheme.*` 62 个 | §7、`scan/res/theme-chain.txt` |
| 7 | **assets 1,148 文件 / 36.6 MB**，16 类；最大三类：flutter_assets(13.07MB)、lottie 动画(4.95MB)、小程序离线包 miniapp(3.84MB) | §8、`scan/res/assets-inventory.tsv` |
| 8 | **调试/开发入口资源极其丰富**：123 个 dev/debug/mock/test 相关 layout；`dev_setting.xml`(0x7f0d07e4) 一个文件里 93 个控件 id（含 `bt_mock_scan`、`btn_exclusive_debug_license`、`btn_automator_debug`、`btn_ut_debug_key_gen`）；`h5_bugme_setting.xml`(0x7f15000d) 明写 **"Chrome 不插线调试(默认端口:9983)"** | §11 |
| 9 | **客户端配置面很大且可被服务端/本地覆盖**：`assets/config/default_config.json` 1,637 个 key、`custom_config.json` 29 个 key（含 H5 上传/保存白名单、ariver appid 白名单） | §10、`scan/res/client-config-keys.tsv` |
| 10 | 与既往报告（`re/imclient_mod/report/manifest-res.md`）**核对一致**的：组件计数、NSC 全明文+信任 user CA、`dev_setting`/`developer_options_settings` 存在、`研发者专用版本`文案；**口径不一致**的：字符串总数与 IM 计数（见 §12） | §12 |
| 11 | **`res/raw/` 是被忽略的高价值目录**（101 文件 / 2.53 MB，仅 38 个是音频）：明文 OAuth `client_secret`（`ali_oauth_config.json`，`<REDACTED_CLIENT_SECRET>…`）、`alipay_push_prop` 里 **`SSL_USED=0`** 的 XMPP 网关、`security_link/white_link/redirect_link` 三道链接拦截页、8 个 H5 注入脚本（含 `h5_debug_console_sw.js`、`h5_bugme_hookappx.js`、`h5_dev_vorlon.js`）、小程序 JSAPI 白名单 `available_modules.json` | §9.4 |
| 12 | **mock 能力的物证**：`raw/{ada_amock1,fr_mock1..4,ga_mock}.xml` 是 `tools:keep` 保活清单，指向的 mock 本体已被裁掉 | §9.4(f) |

---

## 1. 方法、工具与完整性

### 1.1 工具链（本机可用项）

| 工具 | 版本/路径 | 用途 |
|---|---|---|
| apktool | **2.11.1**，`C:\Users\ROG STRIX\AppData\Local\Temp\opencode\apktool.jar`（复制到 `/tmp/apktool.jar`） | 解 manifest / 全量 res / values |
| aapt2 | build-tools 36.0.0 | `dump badging`（locale 标签取证） |
| aapt(1) | 2.20-13193326 | 备用 |
| java | `D:\Android-studio\jbr`（JDK 25） | 跑 apktool |
| python | 3.12 + androguard 4.1.4 / lxml | 统计、AXML 交叉验证 |
| apksigner / keytool | build-tools 36.0.0 / jbr | 签名与证书 |

**【观察】** 任务书写"apktool 若不存在改用 aapt2+androguard 自建脚本"。实际本机 **没有 apktool 安装**，但在 Temp 目录存在 **apktool.jar 2.11.1**，直接可用，因此采用 apktool 为主、androguard/aapt2 为交叉验证。为避开 30 个 dex（220 MB）与 152 个 .so（244 MB）的复制，先抽了一个**只含 `AndroidManifest.xml + resources.arsc + res/ + assets/`** 的 72.7 MB 精简 APK（`scan/res/target_resources_only.apk`）再 `apktool d -s`，8 线程约 4 分钟完成，退出码 0。

### 1.2 关键决定：apktool 会重命名资源目录

**【观察】** `apktool` 会 (a) 丢弃 `<= minSdk(21)` 的 version qualifier，(b) 按 Android 规范重排 qualifier。于是 `drawable-xhdpi-v4 → drawable-xhdpi`、`anim-v21 → anim`、`color-night-v8 → color-night`、`drawable-en-night-xxhdpi-v8 → drawable-en-night-xxhdpi`。直接按路径比对会误判 6,116 个文件"丢失"。本报告的所有覆盖率统计均按 **`(type, 归一化qualifier集合, 文件名)` 三元组** 匹配，归一键见 `scan/res/gen_artifacts.py:norm_dir()`。

> **给回编译的同事**：`apktool/` 里的目录名是 apktool 规范化后的名字，**不能**直接 `apktool b` 回原 APK 的目录布局差异做二进制对比；要比对请用 `unpacked/res/res/`。

### 1.3 签名与"是否被改包"（对既往结论的复核）

```
$ apksigner verify --print-certs --verbose target.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme: false     ← 无 v3/密钥轮换
Signer #1 certificate DN: CN=alibaba, OU=alibaba, O=alibaba, L=hangzhou, ST=zhejiang, C=86
Signer #1 certificate SHA-256: a680d36e6014d4d7b5ec64dc79b576ebe96a48c6dca9121355c946c900e926f2
Signer #1 certificate SHA-1:   14cb01e5ec44af73e5e11deba452a68da114acb2
```

```
$ keytool -printcert -file scan/res/<pkg>.RSA
有效期: Fri Aug 01 20:01:27 CST 2014  →  Sun Feb 06 20:01:27 CST 2124
序列号: 53db8197  算法: SHA1withRSA  密钥: 2048-bit RSA
```

- **【观察】** `META-INF/MANIFEST.MF` 覆盖 **21,031** 条（zip 共 21,034 条，差 3 条 = `.SF/.RSA/MF` 自身），`resources.arsc` 与 `AndroidManifest.xml` 都在清单内；`resources.arsc` 以 **stored（未压缩）** 方式存放。
- **【观察】** `apktool/assets/assets/APK_VALID.txt` = `fb3882f62f5bfdd7c486127db9c8bc85`（32 hex = MD5 形态），而 `md5(target.apk)` = `740dd2363f55adfc6e8aa7e97024667b`，**不相等**；`appSize.txt` = `299,247,164`，实际文件 `299,485,058`，**差 +237,894 字节**。
- **【推断】** `APK_VALID.txt`/`appSize.txt` 记录的是**签名/对齐之前**的产物状态（或另一个渠道产物），差值 = v2 签名块 + zipalign 填充 + 可能的渠道信息写入，不能据此判定"改包"。真正的判据是 v1+v2 双通过。
- **【推断】** 因此：**"IM 品牌"是构建期烘焙进去的**（厂商侧 OEM/白标外壳），本地没有改包痕迹。这与既往报告"Alibaba 证书 v1+v2 通过"一致，但既往报告未点明"品牌替换在构建期完成"这一推论。
- **【未知】** `CN=alibaba` 属"真实IM签名证书"还是"仿名证书"，需要跟线上IM官方 APK 的证书 SHA-1 做一次离线比对才能定论；本机无该样本，留待 task-3（安全栈）。

---

## 2. 解码覆盖率（成功/失败统计）

产物：`apktool/AndroidManifest.xml`（911,960 字节，明文）、`apktool/res/**`（19,446 文件）、`apktool/res/values*/`（102 个 XML）。

### 2.1 AXML / 二进制资源

| 资源类型 | AXML 源文件 | 解码成功 | 二进制资源 | 原样保留 |
|---|---:|---:|---:|---:|
| drawable | 4,680 | 4,680 | 6,093 | 6,093 |
| layout | 7,574 | 7,574 | 0 | 0 |
| color | 352 | 352 | 0 | 0 |
| anim | 389 | 389 | 0 | 0 |
| raw | 0 | 0 | 117 | 117 |
| xml | 39 | 39 | 0 | 0 |
| animator | 36 | 36 | 0 | 0 |
| mipmap | 2 | 2 | 46 | 46 |
| interpolator | 11 | 11 | 0 | 0 |
| menu | 3 | 3 | 0 | 0 |
| transition | 2 | 2 | 0 | 0 |
| **合计** | **13,088** | **13,088（100%）** | **6,256** | **6,256（100%）** |

- **【观察】** **失败 0 个**（`scan/res/decode-failures.tsv` 只有表头）。所有 13,088 个输出文件均以 `<?xml` 开头（逐字节校验，非"部分解码"）。
- **【观察】** 文件后缀分布（源）：`.xml 13,095`、`.png 5,600`、`.webp 509`、`.mp3 38`、`.js 24`、`.json 23`、`.gif 17`、`.jpg 13`、`.txt 12`、`.html 10`、`.properties 1`、`.ogg 1`、无后缀 1。
  - `.xml` 13,095 与 AXML 13,088 差 7：其中 7 个 `.xml` 是**纯文本**（不是 AXML），已原样保留。
- **【观察】** 交叉验证：同一份 manifest 用 androguard `AXMLPrinter` 也能完整解出（756,484 字节 UTF-8），与 apktool 结果在 `package/versionCode/versionName/theme/label` 上一致。

### 2.2 values（resources.arsc 展开）

| 类别 | 文件数 | entries 合计 | 说明 |
|---|---:|---:|---|
| `strings.xml` | **31** | **358,961** | 默认 + 24 语言 + night 变体（locale 展开总数） |
| `public.xml` | 1 | **72,130** | 资源 ID 映射（权威清单） |
| `ids.xml` | 1 | 18,110 | 纯 `<item type="id">` |
| `attrs.xml` | 1 | 2,684 | 自定义属性 |
| `colors.xml` | 4 | 3,440 | default / land / night / night-v29 |
| `dimens.xml` | **27** | 3,778 | 含 `sw240dp…sw720dp`、`w330dp…w1240dp`、`h566dp/h720dp`、`mdpi…xxxhdpi`、`xlarge/large` |
| `styles.xml` | **16** | 1,406 | v22,v23,v24,v25,v26,v28,v29,night,night-v23,land,large,sw600dp,hdpi,watch,ldltr |
| `arrays.xml` | 5 | 165 | en / zh / zh-HK / zh-TW / night |
| `plurals.xml` | 8 | 20 | in/ja/th/vi/zh/zh-HK/zh-TW + default |
| `integers.xml` | 3 | 41 | default / en / sw600dp |
| `bools.xml` | 4 | 12 | default / land / large / port / ldrtl |
| `drawables.xml` | 1 | 43 | 纯色/别名 drawable |
| **合计** | **102** | — | `scan/res/values-coverage.tsv` 有逐文件 entries 数 |

> **口径提示**：`public.xml` 的 string 25,381 是"资源键数"，而 358,961 是"键 × locale 配置 展开后的 `<string>` 元素数"，两者相差 14 倍属正常。既往报告里的"304,270 条字符串"应属第三种口径（见 §12）。

**【观察】** `values/public.xml` 共 **72,130** 条 `<public>`，即资源表条目数（不含 AOSP 库资源）：string 25,381 / id 18,493 / drawable 9,623 / layout 6,868 / dimen 3,593 / color 3,320 / attr 2,684 / style 1,342 / anim 389 / array 161 / raw 101 / integer 39 / mipmap 38 / animator 36 / xml 34 / interpolator 11 / bool 9 / menu 3 / plurals 3 / transition 2。

---

## 3. res 目录树规模与类型分布

**【观察】** `unpacked/res/res/` 共 **86 个目录 / 19,344 文件 / 52.9 MB**。（注：`unpacked/res/res` 是解包工具多套的一层，`apktool/res` 对应同一内容。）完整表见 `scan/res/res-tree.tsv`，摘录 top 20：

| 目录 | 文件 | MB | 目录 | 文件 | MB |
|---|---:|---:|---|---:|---:|
| drawable-xxhdpi-v4 | 1,647 | 15.48 | drawable-xxxhdpi-v4 | 262 | 1.98 |
| layout | 6,861 | 14.38 | drawable-night-xxhdpi-v8 | 170 | 1.26 |
| drawable-xhdpi-v4 | 2,066 | 5.40 | drawable-nodpi-v4 | 891 | 1.15 |
| drawable | 4,624 | 3.86 | drawable-zh-xxhdpi-v4 | 36 | 0.86 |
| raw | 101 | 2.41 | drawable-night-xhdpi-v8 | 146 | 0.55 |
| layout-v22 | 693 | 2.15 | raw-zh / raw-zh-rTW | 4 / 3 | 0.32 / 0.32 |

按资源类型聚合：

| 类型 | 文件 | MB | 占比 |
|---|---:|---:|---:|
| drawable*（含 30 个 qualifier 变体目录） | 10,773 | 32.18 | **60.8%** |
| layout*（layout / -v21 / -v22 / -v28 / -land / -watch / -sw600dp） | 7,574 | 16.58 | 31.3% |
| raw*（含 raw-zh/ja/vi/zh-rTW/night） | 117 | 3.52 | 6.7% |
| anim 389 / color 352 / mipmap 48 / xml 39 / animator 36 / interpolator 11 / menu 3 / transition 2 | 880 | 0.56 | 1.1% |

**【观察】** drawable 家族共 **51 个目录**（1 个无 qualifier + 22 个密度/尺寸变体 + 18 个 `*night*` + 6 个语言维度 `-en/-ja/-zh/-zh-rTW` 与密度交叉 + 5 个 `ldrtl` + 4 个 `sw*dp` + `anydpi/nodpi/watch/land/v21..v23`），除常规密度外还出现 **`-zh` / `-zh-rTW` / `-ja` / `-en` 语言维度** 与 **`-night`** 维度交叉（18 个 `drawable-*night*`），说明**图片也做了多语言本地化 + 暗色适配**，不是纯图标包。

---

## 4. layout 规模与 Top

- **【观察】** `layout/` 6,868 个文件（`public.xml` 计 6,868 条 layout 资源；磁盘 6,861 个，差 7 个是 `layout-v22` 等变体计入同名资源）。
- **【观察】** 解码后最大的 6 个 layout（按 XML 字节数）：
  1. `activity_conversation_owner_manager_v8.xml` 55,300 B
  2. `activity_conversation_owner_manager_v3.xml` 53,292 B
  3. `activity_manage_staff.xml` 41,188 B
  4. `fragment_tele_video_conf_running_bottom_info_mozi_v3.xml` 30,384 B
  5. `alm_cmail_fragment_mail_settings.xml` 29,820 B
  6. `activity_manage_external.xml` 28,434 B ／ **7. `dev_setting.xml` 28,314 B**（见 §11）
- **【观察】** 命名前缀 Top（反映模块切分）：`layout_* 1109`、`activity_* 709`、`item_* 630`、`fragment_* 478`、`view_* 323`、`im_* 212`、`chatting_* 211`、`flash_* 141`、`dialog_* 128`、`alm_* 125`、`calendar_* 120`、`taopai_* 114`、`live_* 98`、`teleconf_* 98`、`cmail_* 85`、`au_* 81`、`ding_* 80`、`circle_* 73`、`feed_* 63`、`con_* 59`、`app_* 48`、`dt_* 45`、`cspace_* 36`、`tele_* 35`、`imclient_* 34`、`session_* 34`、`user_* 34`。
  - **【推断】** 前缀即模块边界：IM(`im_/chatting_/session_`)、日历、淘拍、直播、会议(mozi/teleconf)、邮件(alm_/cmail_)、圈子、动态(feed)、协同空间(cspace)、端智能/端侧(app_/ai_)。

**【观察】** 5 个 layout 内含 `mock` 字样，含 `calendar_activity_local_mock.xml`(0x7f0d04ea)、`ll_dev_realm_config_*`、`im_debug_*`（详见 §11）。

---

## 5. 25 个 locale 的字符串策略

### 5.1 locale 集合（aapt2 badging 实证，25 条 label）

```
默认 IM ｜ de IM ｜ en IM ｜ es IM ｜ es-US IM ｜ fr IM ｜ hi IM
hu IM ｜ in IM ｜ it IM ｜ ja IM ｜ ko IM ｜ mk IM ｜ ms IM
pl IM ｜ pt IM ｜ pt-BR IM ｜ ru IM ｜ sr IM ｜ th IM ｜ tr IM
vi IM ｜ zh IM ｜ zh-HK IM ｜ zh-TW IM
```
（`scan/res/aapt2-badging.txt`）

### 5.2 默认语言到底是什么？——**default = 英文基底，不是中文**

**【观察】** `values/strings.xml` 25,381 条，按值分类：

| 类别 | 条数 | 说明 |
|---|---:|---|
| 图标字体码点（PUA `\ue000-\uf8ff` 或 `tl_\ue…`）或空值 | **2,968** | 如 `IMAI_L_outlined=\uee07`、`TL_AI_20=tl_\ue986` |
| 含 CJK | **2,216** | 中文条目（含一批漏在默认池里的中文） |
| 拉丁/其它文本 | **20,197** | 英文基底（AOSP/AndroidX + IM 英文） |

**【推断】** 这是一个**英文为 default、中文为 `values-zh` 覆盖**的构建（国际版形态），与"IM国内版 default=中文"的常识相反。对照证据：`abc_action_bar_home_description='Navigate home'`（AndroidX 英文）出现在 default，而 `values-zh` 的 `accelerate_efficiency_score='提升效率值'`。

### 5.3 翻译完整度

| locale | 条目数 | 覆盖 default 键 % | locale | 条目数 | 覆盖 % |
|---|---:|---:|---|---:|---:|
| **zh** | 17,587 | 69.29 | **zh-HK** | 18,363 | 72.35 |
| **zh-TW** | 18,345 | 72.28 | ja | 17,664 | 69.60 |
| ko | 17,536 | 69.09 | vi | 17,592 | 69.31 |
| in | 17,591 | 69.31 | th | 17,523 | 69.04 |
| ru | 17,428 | 68.67 | fr | 17,370 | 68.44 |
| hi | 17,453 | 68.76 | tr | 17,402 | 68.56 |
| **de** | 17,172 | 67.66 | it | 17,180 | 67.69 |
| pl | 17,163 | 67.62 | ms | 17,177 | 67.68 |
| hu | 17,012 | 67.03 | pt-BR | 17,181 | 67.69 |
| es-US | 17,540 | 69.11 | **en** | **1,076** | **4.24** |
| **es** | **55** | 0.22 | **pt** | **36** | 0.14 |
| **mk** | **54** | 0.21 | **sr** | **49** | 0.19 |
| night 变体（en/zh/zh-HK/zh-TW） | 11/2/2/2 | ≈0 | sw600dp-land | 1 | ≈0 |

（完整表 `scan/res/locale-strategy.tsv`）

- **【观察】** 那 ~31% 的"未覆盖"差额主要是 **2,968 条图标码点 + 仅存在于英文基底的内部/调试文案**，不是翻译缺失。换算：17,587 / (25,381 − 2,968 − 2,216) ≈ **78.5%** 的真实文案已中文化。
- **【观察***】** `values-en` 只有 1,076 条 —— 因为英文就是 default，这份文件只做**差异覆盖**（多为修正文案）。
- **【观察】** `es / pt / sr / mk` 是 36–55 条的**空壳 locale**（几乎全部回落到英文），属于"占位声明语言支持"。**【推断】** 用于应用商店语言声明与合规清单，不是真翻译。

---

## 6. 品牌替换范围（IM / IM / IM / IM）

### 6.1 逐 locale 计数（`scan/res/brand-scan.tsv`）

| values 目录 | 含 `IM` | 含 `IM` | 含 `IM` | 含 `IM` |
|---|---:|---:|---:|---:|
| values（default） | 582 | 2 | 8 | **4** |
| values-zh | 632 | **632（全为 IM）** | 14 | 3 |
| values-zh-rHK | 673 | 673 | 1 | 0 |
| values-zh-rTW | 649 | 649 | 1 | 0 |
| values-ja | 588 | 3 | 0 | 0 |
| values-ko | 621 | 1 | 0 | 0 |
| values-ru | 682 | 0 | 0 | 0 |
| values-fr | 685 | 0 | 0 | 0 |
| values-vi | 488 | 0 | 0 | 0 |
| values-th | 521 | 1 | 0 | 0 |
| values-in | 619 | 1 | 0 | 0 |
| **values-de** | **0** | **0** | **591** | 7 |
| values-en | 1 | 0 | 0 | 0 |
| **全 locale 展开合计** | **9,362** | — | **2,648** | — |

（`scan/res/brand-samples.tsv` 存了 zh/de/en/ja 的全部命中行）

### 6.2 关键观察

1. **【观察】** `app_name`：default/zh/zh-HK/zh-TW = **`IM`**（0x7f11050d）；`values-en` = **`IM`**。同一品牌两种写法并存（连字符/无连字符）。
2. **【观察】** 中文包里品牌**全部**写成带连字符的 `IM`（632/632），英文 default 里几乎全是 `IM`（580/582）。**【推断】** 两条不同的替换脚本/词表分别作用于中英文。
3. **【观察 · 最强的单点证据】** **`values-de` 一条 IM 都没有，却保留 591 条 `IM` 和 7 条 `IM`**。德语是唯一"没被品牌替换"的语言包。但 `application-label-de` 仍显示 `IM` —— 因为 `values-de` 没有定义 `app_name`，回落到 default。**【推断】** 品牌替换是**构建期脚本化批处理**，德语被漏掉（或德语包来自更早的、未替换的翻译快照）。
4. **【观察】** 残留 `IM` 的中文（全包仅 4 条，都在 default 池）：
   - `dt_dev_realm_config_activity_lable = 专属IM调试工具`（0x7f1128b1）
   - `im_custom_file_view_holder_tips = 请通过政务IM桌面端下载查看`
   - `taopai_demo_app_name = 淘拍IM测试`
   - `video_record_permission_desc = 我们希望你授权IM将运动视频用于「橙狮体育（北京）有限公司」…`
   - **【推断】** 前两条是**故意保留**（"专属IM调试工具"是内部工具名），后两条是漏网。
5. **【观察】** 品牌渗透到**组件/功能名**，不只是营销文案：
   - `dt_contact_org_customization = 专属IM`（原"专属IM"）
   - `dt_alpha_user_guide_title = 了解IM一键连网&专属上网密码`
   - `dt_device_quick_connect_and_bind_tips = IM智能办公网络`
   - `alilang_title = IM Alibaba Edition`
   - `dt_conf_create_team_info_tip = …100,000 minutes of IM Call per month`
6. **【观察 · 品牌替换的"漏网面"】** 用户可点击的 URL 仍指向IM：
   - `enable_webview_debuggable_notification`（0x7f114d28）里写 **"请从官网，wwww.<host> 下载"**（原文就有 4 个 w 的拼写错误）
   - `privacy_url_zh = https://h5.<host>/privacy-policy/zh.html`、`protocol_url_zh = https://tms.<host>/markets/imclient/service-terms-zh`
   - **【推断】** 品牌替换只做了"字符串值层面的名词替换"，**域名/URL 未做白标**。这是 OEM 外壳的典型特征，也是"这仍是IM内核"的直接证据。
7. **【推断 · 总结】** 该包 = **IM 8.2.2.1 内核 + IM 白标外壳（OEM/专属版）**，与既往报告"丁Talk 内核 + IM 国际品牌"的判断一致；但既往报告把 de 的异常解释为 locale 抽样（未提），本报告将其列为**可复现的构建缺陷**。

---

## 7. 主题 / 样式继承链

- **【观察】** 全包 **1,342 个 style**（`values` 1,294 / `values-hdpi` 1 / `values-land` 4 / `values-large` 5 / `values-sw600dp` 6 / `values-v22..v29` 各 1–8 / `values-night-v23` 1 / `values-ldltr` 1 / `values-watch` 1）。`DtTheme.*` 家族 **62 个**。
- **【观察】** manifest 的 `<application android:theme="@style/DtTheme.Normal">`（0x7f120183）。完整链（`scan/res/theme-chain.txt`）：

```
DtTheme.Normal                    23 items   [values]
 └ DtTheme.Base                   29 items
    └ Theme.AppCompat.DayNight.DarkActionBar   (library, 0 items 本地覆盖)
       └ Theme.AppCompat.Light.DarkActionBar
          └ Base.Theme.AppCompat.Light.DarkActionBar   6 items
             └ Base.Theme.AppCompat.Light
                └ Base.V21.Theme.AppCompat.Light      32 items
                   └ Base.V7.Theme.AppCompat.Light    120 items
                      └ Platform.AppCompat.Light
                         └ Platform.V21.AppCompat.Light  6 items
                            └ android:Theme.Material.Light.NoActionBar  (框架)
```

- **【观察】** 一级子主题（`parent=@style/DtTheme.Normal`）覆盖了主要场景：`NoTitle`、`Transparent`、`Fullscreen`、`Overlay`、`Splash`、`LaunchHome`、`LaunchPrivacyPolicy`、`PayCode`、`Redpackets`、`BadgeTab`、`FernGuide`、`Album/AlbumPreview`、`AllCustom(+.Dark)`、`Normal.8_0`、`Normal.Light.z1`、`Normal.GrayBg`。
- **【观察】** 深色模式走**两套机制**：(a) `values-night/styles.xml` + `values-night-v23/styles.xml` 覆盖；(b) `DtTheme.*.Dark` 显式变体（`AllCustom.Dark`、`NoTitle.Dark`、`Overlay.Dark`、`Transparent.Dark`、`Transparent.HasImmersiveStatusBar.Dark`…）。**【推断】** (a) 为主、(b) 供 Flutter/自定义容器的强制暗色场景。
- **【观察】** `AppTheme` / `AppThemeNew` / `AppTheme.com_alipay_mobile_*` 是**第三方 SDK 的宿主主题**（`beephoto`、`beevideo`、`nebulauc`、`nebula`、`nebulainside`、`nebulaintegration`），说明 WebView(UC/Nebula) 与拍摄 SDK 需要独立主题入口 —— 与 assets 里的 `nebulaPreset/`、`libnebula*` 呼应。

---

## 8. assets 全量清点与分类（1,148 文件 / 36.6 MB）

完整清单：`scan/res/assets-inventory.tsv`（path / bytes / bucket / magic）；分类汇总：`scan/res/assets-buckets.tsv`。

| # | 分类 | 文件 | MB | 代表内容 |
|---|---|---:|---:|---|
| 1 | flutter_assets | 310 | 13.07 | `packages/dingui_flutter/`、`imclient_calendar_module/`、`imclient_user_module/`（含 `region*/regions_*.txt` 国家区号表）、`MaterialIcons-Regular.otf`(1.57MB)、`iconfont.ttf`×3 |
| 2 | lottie 动画 | 144 | 4.95 | `lottie_clap_atmosphere.json`(876KB)、`lottie_flash_detail_tab_loading_*`(471/387KB)、`celebrate.json`(244KB)、`live_treat_grab_anim.json`(216KB)、`leaderOfGroup.json`(169KB)、`fireworks.json` |
| 3 | 小程序离线包 | 16 | 3.84 | `miniapp/*.amr` + `*.appinfo.json`；`992024022811121067.amr`(2.0MB)、`992024082216405545.amr`(0.52MB) |
| 4 | 端侧模型 | 15 | 3.63 | `nn_denoiser/model/tc.nn`(0.84MB)、`qr_detect_model`(528KB)、`dt.toyger.face.dat`/`toyger.face.dat`(各 0.64MB)、`fdmodel.bin`(96KB)+`fdmodel2.bin`、`ldmodel.bin`(87KB)+`ldClassifier.bin`、`faceModel3D.dat`、`MNN.zip`(34KB)、`python27.zip`(176KB)、`zoneinfo.zip`(280KB)、`taopai/face3d/*.bin` |
| 5 | 地图 | 112 | 2.77 | `map_assets/`、`map_custom/skybox/{left,right}.png`(0.36MB)、`cities/cities_2017Q4.txt`+`overseaCity.txt`、`offlinemapv4.png`、`amap_*`、`location_*`/`marker_*`/`zoom*` 控件图 |
| 6 | 配置 | 238 | 2.13 | `config/{default_config,custom_config,agent_nvwa_config_0_0_1,family_account_config}`、`easygo.json`/`easygo_hw.json`、`channel.config`、`metainfo.xml`、`template.info`、`imclientttid`、`appSize.txt`、`APK_VALID.txt`、`zoloz_*`、`grs_*`、`mcs_config.json`、`arengine_conf_*`、`nebulaPreset/{66666692,68687209}`、`ae/{GNaviConfig.xml,res.zip}`、`one_res/*`、`race_res/`(3D 引擎 shader 129 个)、`template/dd_mini_widget/`(73 个 `.dx`) |
| 7 | 字体 | 17 | 1.70 | `iconfont.ttf`(587KB)、`iconfont_dingicons.ttf`(673KB)、`iconfont_tl.ttf`(110KB)、`pissarro_iconfont.ttf`、`AlipayNumber.ttf`、`custom/{BEBAS,Kingsoft Confetti,Kingsoft Extra,Kingsoft Sign}.ttf`、flutter 内 4 个 |
| 8 | 支付模板 | 49 | 1.35 | `QUICKPAY@cashier-home-flex`(392KB) 等 13 个收银台模板、`MOBILEIC@*` 19 个(网商/身份核验页面)、`OPENBOX@deduct-channel-select*`、`BANK_AP_*` 6 个图标、8 个纯色 `AZURE/BLUE/CYAN/GREEN/MAGENTA/ORANGE/RED/ROSE/VIOLET/YELLOW.png` |
| 9 | 隐私政策 | 19 | 0.95 | `privacy_policy/{zh,tw,en,eu}.html` + `policy/` + `law/` + `service/` + `imclient-promise-lwp.js`(46KB) + `version.html`（= `0.0.8.1801042138`） |
| 10 | WebView/JS 内核资产 | 27 | 0.89 | `main.js`(193KB)、`weex-main-jsfm.js`(183KB)、`weex-rax-api.js`(119KB)、`weex-rax-extra-api.js`(111KB)、`amc.js`(42KB)+`amc.i18n*`、`mic.js`/`mic.css`/`mic.i18n{,.en_US,.zh_HK,.zh_TW}`、`msc`、`h5_bridge.js`、`behavior.js`、`workerjs_*`、`windmill.{rax,vue}.worker.js`、`vi-amc.js`(25KB) |
| 11 | lightapp 容器页 | 14 | 0.27 | `errorpage/{error_page,network_error_page,ssl_error_page}.html`、`basejs/imclient-promise-lwp.js`(91KB)、`imclienti18n.min.js`(56KB)、`js/{automator_bridge_android,automator_bridge_android_240222,detector,guard,nuva22_0707}.js` |
| 12 | 密钥/证书 | 11 | 0.11 | `grs_sp.bks`、`hmsincas.bks`、`hmsrootcas.bks`（华为根 CA）、`bid-log-key-public{,_b,_t}.key`、`ft-bid-log-key-public.key`、4 个 `libwbsafeedit*`（16–18KB，**非 ELF**，疑似微博分享 SDK 的数据桩） |
| 13 | emoji/表情 | 6 | 0.08 | `emoji`（`emoji_N.png,[中文名]` 文本映射表）、`emotion_entry{,_dark}.json`、`facebeauty{,config}.json`、`tpfacebeauty*` |
| 14 | 音频 | 15 | 0.13 | `SFX_knock_3.mp3`、`open_red_packet.mp3`、`giving_big_red_packet.mp3`、`treasure_chest.mp3`、`sent_message.mp3`、`dtf/audio/dtf_*.mp3`（10 个人脸取景语音提示） |
| 15 | 其它图像 | 60 | 0.29 | `images/{______,_______0,img_0,img_1,img_2}.png`（****名字被打码的占位图**，见 §9.5）、`hud.png`、`eagle_eye_{day,night}.png`、`h5_qr_back.png` 等 |
| 16 | 其它 | 95 | 0.42 | `FilePath.txt`(16.7KB)、`entities.properties`(24KB)、`3DFly.{flb,loc,tmc}`、`ap.data`/`ap1.data`、`ab_d.bin`/`ab_r.bin`、`fghijklmnopqr`/`mb`/`qb`/`stuvwxyz01234567`、`dtf_code_config.json`、`lego_bundles_multiscreen.json`、`face_meta_offline_info` |

### 8.1 几个容易误判的"非典型文件"（逐个定性）

| 文件 | 大小 | 真实身份 | 证据 |
|---|---:|---|---|
| `fghijklmnopqr`、`mb`、`qb`、`stuvwxyz01234567` | 262–282 B | **10×10 PNG**（`\x89PNG` 头，带 pHYs/gAMA/cHRM） | 文件名对应字符集片段（f–p / m–b / q–b / s–z0–7），**用途未确证 → 【未知】**，疑为九宫格/字符贴图占位 |
| `ap.data`、`ap1.data` | 1.65 KB | **160×40 调色板 PNG**（`PLTE`），非数据文件 | 疑似 "apm/apollo" 占位图 |
| `ab_d.bin`、`ab_r.bin` | 245 B | 二进制，头 `01 00 02 00 01 00 02 00 80 00` 后接高熵字节 | **【推断】** A/B 实验的默认(d)/rollback(r) 配置密文 |
| `libwbsafeedit*` | 17.6–18.3 KB | **不是 ELF**（无 `\x7fELF`），4 个 ABI 各一份且体积相近 | **【推断】** 微博分享 SDK 的资源桩/签名数据，不是可执行库 |
| `ARENGINE_CONF_NEW/OLD` | 1.9/2.1 KB | **DER 证书**（`30 82 03 ab …`，CN=Huawei, O=Huawei, L=Shenzhen, ST=Shenzhen, C=CN） | 华为 AR Engine 的信任链配置。**【推断】** 与 libarengine 配对 |
| `3DFly.tmc` | 104 B | 魔数 `0CMT`，版本 1，含时间戳样序列 | **【未知】**（疑 Taobao 3D 引擎的材质缓存头） |
| `FilePath.txt` | 16.7 KB | 逐行 JSON：`{"ret":1,"path":"databases","regex":"*","root":"IR","id":-1470486623}` | **【推断】** 打包工具导出的路径注册表，可看出应用关注的沙箱目录（`databases/lib/files/cache`） |

---

## 9. 关键 JSON / 配置的字段级解读

### 9.1 `easygo.json`（7,987 B）vs `easygo_hw.json`（7,975 B）—— 多窗口/折叠屏适配清单

**字段级**：

| 字段 | 值 | 含义 |
|---|---|---|
| `easyGoVersion` | `1.0` | 协议版本 |
| `client` | `<PKG>`（easygo.json）／ `<PKG>`（easygo_hw.json） | **关键差异**：hw 版还是未加后缀的母包名，说明 `easygo_hw.json` 是**上游遗留文件**，`easygo.json` 才是为本包重生成的 |
| `logicEntities[0].head.function` | `magicwindow` | "魔法窗口"/平行视界（华为 App Multiplier 同族机制） |
| `body.mode` | `1` | 双窗口模式 |
| `body.defaultDualActivities.mainPages` | `…<pkg>.biz.LaunchHomeForEasyGoActivity` | 双窗主页面 |
| `body.defaultDualActivities.relatedPage` | `…<pkg>.biz.fold.DefaultDualActivity` | 折叠屏关联页 |
| `body.activityPairs` | 2 条：`LaunchHomeActivity→*`、`LaunchHomeForEasyGoActivity→*` | 分屏配对规则 |
| `body.Activities` | **47 条**，均 `defaultFullScreen:"true"`（`taopai` 那条另加 `isSupportTaskSplitScreen:"false"`） | 必须全屏的 Activity 白名单：视频播放、直播、空间预览、拍图、登录/注册、隐私政策、扫码(`com.taobao.ma.ui.ScanActivity2`)、`MultiTaskRecentActivity`、`BokuiActivity` 相关 |
| `body.transActivities` | `["<PKG>"]` | 路由中转页参与转场 |
| `body.UX.windowsRatio` | `FOLD:1056|1138`、`PAD:900|1654` | 折叠屏/平板窗口比例 |
| `body.UX.draggingToFreeForm` | `"app"` | 允许拖拽进自由窗口 |
| `body.UX.isDraggable` | `"false"` | 但默认不可拖 |
| `body.defSwitch` | `"full"` | 默认全屏 |
| `body.supportLock` | `"true"` | 支持窗口锁定 |

- **【推断】** `easygo*` = **华为/荣耀侧"平行视界"（EasyGo）** 的白名单配置；`easygo_hw` 是华为渠道专用版（`client` 未带后缀）。它与 `res/xml/main_split_config.xml`(0x7f150012，`window:alwaysExpand="true"` 的 `ActivityFilter` 列表) 是**同一份适配名单的两种载体**（一份给 HMS 系统读 assets，一份给系统窗口管理器读 XML）。
- **【可被外部影响】** 若系统侧（HMS）或 OTA 覆盖 assets，可改变分屏行为 —— 属低风险但**可观测**的面。

### 9.2 隐私政策（`privacy_policy/`，19 文件 / 0.95 MB）

| 文件 | 大小 | 说明 |
|---|---:|---|
| `policy/zh.html` | 158,069 B | **中文隐私政策全文（最长）** |
| `service/zh.html` | 107,665 B | 服务协议 |
| `policy/en.html` 80,401 ／ `policy/eu.html` 83,277 ／ `policy/tw.html` 65,830 | | 英/欧/繁 |
| `law/zh.html` 10,616 ／ `law/en.html` 11,740 ／ `law/tw.html` 10,516 | | 法律条款摘要 |
| `zh.html` 40,846 ／ `tw.html` 40,917 ／ `en.html` 49,143 ／ `eu.html` 83,922 | | 首屏摘要页 |
| `imclient-promise-lwp.js` | 46,468 B | 隐私承诺页（LWP = LightWeight Page）脚本 |
| `version.html` | **`0.0.8.1801042138`** | 本地政策版本号（2018-01-04 起沿用） |

- **【观察】** 另有根级 `privacy.html`(5,573 B) —— 一个**带完整 CSS 的精简富文本渲染页**，与上面 4 语言版本不是一套。
- **【推断】** 本地 HTML 只是**离线兜底**；线上版本由 `values/strings.xml` 的 URL 决定（`privacy_policy_url_zh_cn` → `terms.alicdn.com/.../20240423113418444/`、`privacy_url_zh` → `h5.<host>/privacy-policy/zh.html`、`new_dingding_privacy_url` → `.../20231103142915365/`）。**【观察】** 本地版本 `0.0.8.1801042138` 与线上 2024 版 URL **严重不同步**。
- **【推断】** 若离线状态触发本地政策页，用户看到的可能是**2018 年的旧政策**——合规风险点（这不是代码漏洞，是产品证据）。

### 9.3 渠道 / 环境 / 身份类小配置

| 文件 | 内容 | 解读 |
|---|---|---|
| `channel.config` | `release_type=release` | **release 构建**（非 debug） |
| `imclientttid` | `exclusive_imclient_405272002` | **ttid 渠道标识 = 专属IM + 组织 ID 405272002**。**【推断】** 这是"专属版/私有化"实例号，可作为**归属判定**的关键常量 |
| `appSize.txt` | `299247164` | 见 §1.3 |
| `APK_VALID.txt` | `fb3882f62f5bfdd7c486127db9c8bc85` | 见 §1.3 |
| `metainfo.xml` | 24 个 `<plugin key=… value=com.alipay.*>` | **支付宝「Alipay Inside」插件注册表**（收银台 phone_cashier、扫码 scan/barcode、乘车码 offlinecode、借呗 jiebei、IoT 支付 iotpay/iotcashier、授权 login_external/onceauth_v2 …） |
| `alipay_inside_channel.config` | `insideModel=DINGDING`、`productName=ALIPAY_INSIDE`、`productID=ALIPAY_INSIDE_DINGDING_AND`、`channel=dingding`、`insideChannel=merchant`、`barcodeDegrade=false` | **品牌替换 0 覆盖区**：这里的 `dingding/dingding` 全是原始值 | 
| `alipay_inside_inner.config` | `productVersion=3.8.1.17434243`、`innerVersion=20250331203257029`、注释 `Mon Mar 31 20:33:15 CST 2025` | **构建时间证据：2025-03-31** |
| `com.tencent.open.config.json` | `{"Common_ta_enable":1,"Common_frequency":24}` | QQ 开放 SDK 埋点开关 |
| `template.info` | `TemplateVersion 5.9.5` + 49 个模板的 `tplId/tplVersion/time/publishVersion`，全部 `publishVersion:150924` | **支付页模板版本清单**（`150924` = 2015-09-24，模板体系 10 年未变） |
| `zoloz_framework.json` | `framework_version 3.28.5`，挂 `zoloz_bioauth.json`（`bundle_name: com.alipay.zoloz.cloud`、`dynamic:false`） | 活体/人脸框架版本 + 4 个 `local_services` 实现类绑定 |
| `ai_support_language.json` | 13 种语言（zh_CN/en_US/ja_JP/ko_KR/vi_VN/id_ID/th_TH/ru_RU/es_ES/fr_FR/tr_TR/ar_AE/it_IT） | **AI 助手支持的语种清单**（与 UI 的 25 locale 不同，AI 只支持 13 种） |
| `mcs_config.json` | `subscribeConfig.camera.{lecture,fluid,uniqueGrid,nineGrid}.{preferLevel,maxResolution,maxFrameRate}` + `screencast.preferLevel` | **视频会议订阅码流策略**：`fluid.activeStreams_25 → 180P@12fps`、`activeStreams_9 → 180P@12fps`、`activeStreams_4 → 360P`、`activeStreams_2 → max`（按参会人数自适应降级） |
| `grs_sdk_server_config.json` | 5 个 `grs.dbankcloud.*` 域名 + `/grs/1.0/%1$s/router`、`/grs/2.0/router`，timeout 2s | **华为 GRS 路由服务** |
| `arengine_conf_new/old` | DER 证书（CN=Huawei） | 华为 AR Engine 信任链 |
| `face_meta_offline_info` | `{"downloadInfoValid":true,"liveModelVersion":"2","liveScoreThreshold":40,"matchScoreThreshold":0.5,"md5":"9015fa94…"}` | **离线人脸模型的阈值与一致性校验** |
| `dtf_code_config.json` | 30+ 条 `Z1000→其他异常 / Z1001-Android→人脸识别算法初始化失败 / Z1002→无法启动相机…` | **DTF(人脸取景)错误码字典** |
| `config/agent_nvwa_config_0_0_1.json` | `root.entries[].data.{guiUrl,luiUrl,i18nName{es_LA,it_IT,…,zh_CN},guiAvatar,isFixed,entryId,entryType}`；含 `dd_mini_app_id=992025121710385075` | **首页「ONE / assistant」AI 入口的 tabBar 配置**（nvwa=阿里女娲配置中心），21 语种显示名 |
| `config/default_config.json` | **1,637 个 `{key,value}`** | 客户端默认开关表（详见 §10.1） |
| `config/custom_config.json` | **29 个 `{key,value}`** | 渠道/宿主定制表（详见 §10.2） |
| `one_res/{value,value2,version8Token}.json` | 17,347 / 17,347 / 36,404 B | **设计 token 表**：`{"mob":{"white":{"im_chat_bg_color":"#FFFFFF", "common_border_radius_s":4 …}}}`，`value` 与 `value2` 内容完全相同（17,347 B，疑重复投放） |
| `emoji` | `emoji_1.png,[开心]` 逐行 | 表情包中文名映射 |
| `lego_bundles_multiscreen.json` | `{"<PKG>":["com.yunos.tvhelper.support.api.SupportApiBu", …]}` | 多屏(yunos) 兼容包白名单 |

---

### 9.4 `res/raw/` —— 最被低估的资源目录（硬编码 OAuth 凭据、明文推送、链接拦截页、注入 JS）

**【观察】** `raw/` 家族共 117 个文件（`raw/` 101 + `raw-zh` 4 + `raw-zh-rTW` 3 + `raw-ja` 2 + `raw-vi` 1 + `raw-night-v8` 6），其中 **`raw/` 本体 2.53 MB / 101 文件，只有 38 个是音频**，其余 63 个是配置、注入脚本、错误页、地区表。这是全包**信息密度最高的资源目录**。

#### (a) 硬编码 OAuth 凭据（🟥 明文 client_secret）

`res/raw/ali_oauth_config.json`（224 B，资源 id `0x7f090001` 系列中的 raw 条目）：

```json
{ "client_id": "dingmail_android_oauth",
  "client_secret": "<REDACTED_CLIENT_SECRET>",
  "redirect_uri": "alimailclientandroid://oauthCallback" }
```

- **【观察】** `client_secret` 以**明文 UUID** 直接放在资源里。**【推断】** 这是阿里邮箱（dingmail）Android 客户端的 OAuth 凭据，属"公开客户端不应持有 secret"的经典反模式；任何拿到 APK 的人都能提取。
- **【观察】** 另有 3 个同类文件：

| 文件 | client_id | redirect_uri / scope |
|---|---|---|
| `eas_internal_oauth_config.json` | `57d30c6c-e42d-4de7-a266-d24dbb94fc94` | `imclient://imclientclient/page/oauthcallback_azure`，scope `https://partner.outlook.cn/full_access_as_user offline_access`（**世纪互联版 Exchange**） |
| `eas_international_oauth_config.json` | `f2b39ee3-9f5d-475c-b66d-4aeddeb1122d` | 同 redirect，scope `https://outlook.office365.com/EAS.AccessAsUser.All offline_access`（**国际版 Office365**） |
| `gmail_auth_config.json` | `674387763378-co7188pvnpen8sj0l346q0e85m23p37k.apps.googleusercontent.com` | `http://localhost`，scope 含 `https://mail.google.com/`、`gmail feed/atom`；`https_required: true` |
| `micro_auth_config.json` | `{}`（空对象，占位） | — |

- **【推断】** 这 4 个文件 = **邮箱客户端的"第三方邮箱账号接入"凭据集**（Exchange ActiveSync ×2 + Gmail + 阿里邮箱）。它们能直接支撑 task-5 的"登录与会话"章节。

#### (b) 明文 XMPP 推送配置

`res/raw/alipay_push_prop`（98 B）：

```
XMPP_HOST=mcometgw.alipay.com
XMPP_PORT=443
PROTOCOL_VERSION=3
SSL_USED=0      ← 关闭 TLS
ZIP_FLAG=0
RETRY_TIMES=1
```

**【观察】** `SSL_USED=0` 明确关闭 TLS；`mcometgw.alipay.com` 是支付宝 mPaaS 推送网关。**【推断】** 这是支付宝推送通道的"兜底参数文件"，与 manifest 的 `usesCleartextTraffic=true` 叠加后，该通道存在明文风险（具体是否被实际使用属 task-5）。

#### (c) 链接拦截 / 安全提示页（3 个 HTML）

| 文件 | 大小 | 用途（据文件名与内容） |
|---|---:|---|
| `security_link.html` | 2,707 B | 命中**安全策略**时的拦截提示页（"提示"标题页） |
| `white_link.html` | 3,442 B | 命中**白名单**时的过渡提示页 |
| `redirect_link.html` | 3,638 B | 跳转中转页 |
| `h5_page_error.html` / `h5_trans_page_error.html` / `h5_whitescreen_errorpage.html` / `h5_lottie_errorpage.html` | 11,352 / 5,854 / 2,689 / 7,243 B | H5 各类错误页（含白屏检测页 `h5_whitescreen_errorpage`） |

**【推断】** 三件套（`security_/white_/redirect_`）说明 URL 打开走了 **"白名单 + 安全策略"双闸**；错误页支持"白屏检测"，是容器质量兜底机制的物证。

#### (d) 注入到 H5 的调试/桥接脚本（8 个）

| 文件 | 大小 | 作用（据代码） |
|---|---:|---|
| `h5_debug_console_sw.js` | 966 B | **替换 `console.log/info/error/debug/warn`**，把 Error 对象摊平成 `Error <prop>:<val>`，对象 `JSON.stringify`，**统一截断到 4,096 字符** —— 为"远程调试/日志回传"做的序列化层 |
| `h5_bugme_hookappx.js` | 2,522 B | `console.log('BugMe: loading appx dev hook...')`，用 `var e='%@'` 模板占位，钩住 appx（小程序包）的开发期方法；参数序列化上限 `4096*4` |
| `h5_dev_vorlon.js` | 697 B | vorlon.js DOM 调试客户端注入 |
| `h5_jsinterface_bridge.js` | 4,219 B | JS↔Native 接口桥 |
| `h5_bridge.js` | 1,876 B | 通用 H5 桥 |
| `h5_performance.js` | 5,256 B | 性能采集 |
| `h5_scan.js` | 2,560 B | 扫码桥 |
| `h5_startparam.js` | 350 B | 启动参数解析 |
| `rvtools_inject_js.js` | 2,710 B | **`window.g_RvToolsFetchResourceJsInjectStatus` 幂等注入**，等 `AlipayJSBridgeReady` 后注入资源抓取脚本（RvTools = 远程可视化工具） |
| `zhifubao_alipay_msp_h5_bridge.js` | 2,356 B | 支付宝 msp 专用桥 |
| `workerjs{,_v8,_worker}.js`、`worker.html`、`create_worker.html` | 5,664 / 7,657 / 1,022 / 170 / 159 B | WebView Worker 引导 |

- **【推断】** `h5_debug_console_sw.js` + `h5_bugme_hookappx.js` + `h5_dev_vorlon.js` 三个文件**只在调试开关打开时才注入**（对应 §11.3 的 `h5_bug_me_debug_switch` / `h5_bug_me_dom_debug` / `h5_bug_me_js_injector`）。**这给出了"JS 注入能力的实体"**——不是抽象能力声明，是包内可见的脚本资产。

#### (e) 小程序 JSAPI 白名单

`res/raw/available_modules.json`（1,819 B）—— **小程序容器暴露给 JS 的模块/方法白名单**，可直接作为 API 面的权威清单：

```
miniApp: setAppShareInfo, hideLauncherLoading
network: request        mtop: request
storage: length,setItem,getItem,removeItem      memoryStorage: setItem,getItem
navigator: push,pop,openMessagePage,reloadPage,getBackStack,popToHome
user: login,logout,info
modal: alert,confirm,toast
navigatorBar: show,hide,setTitle,setRightItem,setStyle,setDrawer,setActionSheet,
              hasIndexBadge,scaleIndexBadge,resetIndexBadge,getHeight,
              openDrawer,isDrawerOpened,closeDrawer,setLeftItem,showMenu,hideMenu,getStatusBarHeight…
```

**【推断】** 白名单里 **`network.request` 与 `mtop.request` 都直接放给 JS**，且 `user.login/logout/info` 也在列 —— 小程序容器的权限模型是"白名单内即授权"，越权风险取决于这些方法的服务端校验（task-2/task-5）。

#### (f) 其它 `raw/` 资产

| 文件 | 大小 | 说明 |
|---|---:|---|
| `regions_v2.txt` / `regions.txt` / `region_code.txt` / `phone_district.json` | 204,400 / 105,827 / 7,215 / 4,066 B | **国家/地区与电话区号全量表**（与 flutter 侧 `regions_*.txt` 重复投放 4 套） |
| `alipay_hw_buildmodle.properties` | 5,175 B | **厂商 ROM 适配白名单**：`HUAWEI-Z100=huaweiold_VALUES`、`HUAWEI-PLK100=huawei_VALUES`、`YUNOS-CM810=yunos_VALUES`、`OPPO-N5207`、`MEIZU-M76/M85`、`HTC-*`、`VIVO-Xplay5`、`LENOVO-MTK`、`GiONEE-GN9008`、`Coolpad-*`、`ZTE-A2015`、`ShenQi-Z1221`、`OnePlus-ONE-A2001`… |
| `keep.xml` / `ada_amock1.xml` / `fr_mock1..4.xml` / `ga_mock.xml` | 134–144 B × 7 | **`tools:keep` 保活清单**：`keep.xml` 保 `@drawable/yw_1222`；其余 6 个分别保 `@raw/ada_amock1`、`@raw/fr_mock1..4`、`@raw/ga_mock` |
| `tab_animation_{message,contact,work,cooperation,mine,more}.json` | 4.3–14.1 KB ×6 | 底部 6 个 tab 的切换动画（Lottie） |
| `images.js` / `share_new_min.js` / `ogp_meta_tool.js` / `mini_app_dom_{size,structure}.js` / `add_to_launcher_cb.js` / `single_image.js` | 0.2–6.7 KB | 图片处理、分享、OGP 元信息、小程序 DOM 结构采集、桌面图标回调 |
| `tinydemo.html` | 387 B | 小程序 demo 页 |
| `beep.ogg` + 37 个 `.mp3` | 8.4 KB + 2.4 MB | 提示音（来电/去电/挂断/忙音/签到/人脸取景/红包/敲一敲…）；`raw-zh/raw-ja/raw-vi/raw-zh-rTW/raw-night-v8` 是**本地化提示音**（例如中文语音播报） |

- **【观察 · 关键推论】** `ada_amock1.xml` / `fr_mock1..4.xml` / `ga_mock.xml` **本身只是 `tools:keep` 声明文件**，它们指向的 `@raw/ada_amock1`、`@raw/fr_mock1`… **在 APK 里已不存在**。**【推断】** 曾经有一批 **mock 数据文件**（ada = 埋点/ADA，fr/ga = 可能是功能/灰度 mock）被加到 `raw/`，并用 `tools:keep` 防止 R8/aapt 裁掉；打包时本体被移除或从未进入该 flavor，只留下**保活清单**——这是"mock 能力存在过"的直接物证，且暴露了构建期的资源保活配置。

---

## 10. 可被外部影响的配置面（重点）


> 判据：**运行时是否会被服务端下发 / 本地文件 / 外部 App / Web 内容覆盖或改写**。分级：🟥高（可直接改行为且无校验）/ 🟧中（需要前置条件）/ 🟩低（仅 UI 适配）。

### 10.1 🟥 `assets/config/default_config.json` —— 1,637 个客户端开关的"出厂默认值"

- **【观察】** 结构极简：`[{"key":"config_storage_usage_upload_rate","value":"1000"}, {"key":"KEY_TRACE_IMAGE_SWITCH","value":"TRUE"}, …]`，共 1,637 组。全量导出：`scan/res/client-config-keys.tsv`。
- **【推断】** 这是**端侧配置中心（realm/配置表）的本地默认值**。真正生效值来自服务端下发（与 §11 的"专属IM调试工具"能实时改同一张表相印证）。因此：**这 1,637 个 key 的取值，最终由服务端 + 组织的 realm 配置决定**。
- **【推断】** 只要拿到一个有权限的组织身份，就能通过"配置模拟"改写这些 key 的本地值（见 §11.2），**无需改包**。这是本 APK 最直接的"外部可影响行为面"。

### 10.2 🟥 `assets/config/custom_config.json` —— 29 个"宿主注入"配置（含安全相关白名单）

逐条列出高价值项（原文值见 `scan/res/client-config-keys.tsv`）：

| key | value 摘要 | 为什么重要 |
|---|---|---|
| `ta_saveFile_whiteList` | `["<PKG>/h5/download/temp","<PKG>/files/multimedia","<PKG>/cache","<PKG>/files/h5container/image/temp"]` | **H5 保存文件的目录白名单**（相对沙箱根）。**推断**：这是 H5 侧可写入路径的边界，白名单外的写入应被拒 |
| `h5_uploadFile_whiteList` | 同上 4 条 | **H5 上传可读路径白名单**。若实现有缺陷/被下发覆盖，等于放开沙箱读 |
| `ariver_platform_ap_appid` | `["20000196","20000202","66666692","68687209","68687360"]` | **小程序(Ariver)宿主的 appId 白名单**。与 `assets/nebulaPreset/{66666692,68687209}` 一一对应（本地预置包） |
| `h5_preRenderConfig` | `{"shouldUsePreRender":"NO","prerenderPage":""}` | H5 预渲染开关（默认关） |
| `h5_ucCoreMultiProcess_30` | `{"mode":0}` | UC 内核多进程模式（0=关）。**推断**：改成 1 会改变 WebView 进程模型与攻击面 |
| `ta_tinyappUseNewMenu` | `all` | 小程序新菜单全量 |
| `ta_load_global_appxng` | `true` | 全局加载 appxng（小程序包格式） |
| `permission_guide_path_list` | `[{"device":"default","appPath":"package:${appPackage}#Intent;action=android.settings.APPLICATION_DETAILS_SETTINGS;end", …}]` | **权限引导跳转的 Intent URI 模板**（直接拼给 startActivity） |
| `h5_preConnectInSetup` / `poi_search_by_sdk` 等 | — | 性能/搜索策略 |

- **【推断】** `custom_config.json` 是"宿主（渠道/AOSP 集成方）覆盖层"，`default_config.json` 是"底座默认层"。两层叠加后由 realm 配置再覆盖 → **三层配置链**。

### 10.3 🟧 `easygo.json` / `easygo_hw.json` / `res/xml/main_split_config*.xml` —— 系统级窗口策略

见 §9.1。由 HMS/系统窗口管理器读取，**应用本身无法校验**其完整性。

### 10.4 🟧 `assets/lightapp/js/*.js` —— 注入到每个 H5 页面的脚本

| 文件 | 行为 | 证据 |
|---|---|---|
| `lightapp/js/guard.js` | **patch `window.open`**：把第一个参数里的 `\u0000` / `\x00` 去掉后透传 | 见代码，**这是针对 `javascript:` / 空字节绕过的一层加固** |
| `lightapp/js/detector.js` | patch `history.pushState/replaceState`，监听 `hashchange/popstate`，每次 URL 变化调 `nuva.require("runtime.monitor").pageRedirect({url})` | **H5 路由变更上报** |
| `lightapp/js/automator_bridge_android{,_240222}.js` | 自动化测试桥（两版并存） | **推断**：`_240222` 是 2024-02-22 的新版，说明**测试桥一直在包里** |
| `lightapp/basejs/imclient-promise-lwp.js`(91KB) / `imclienti18n.min.js`(56KB) | 错误页基础库 | — |

- **【推断】** 这层 JS 会被注入到所有 WebView 页面（含第三方 H5）。`guard.js` 的 null-byte 过滤暗示**曾有 `javascript:` URL 绕过**被修过。**【未知】** 注入是否对所有域生效、是否有 CSP 配合 —— 留给 task-3。

### 10.5 🟥 `res/xml/network_security_config.xml`（0x7f150014）—— 明文 + 信任用户 CA

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
</network-security-config>
```

- **【观察】** **无任何 `domain-config`**，即**全域名**继承 base-config；manifest 另有 `android:usesCleartextTraffic="true"`。
- **【推断】** 全局允许明文 HTTP（可被降级/劫持）+ 信任用户安装的 CA（MITM 友好）。这与"证书 pinning 在代码/so 层另做"并不矛盾 —— **NSC 层是放开的，pinning 必须另有实现**（留给 task-3/task-5 验证）。与既往报告 §0-3 的判断**完全一致**（该报告称"与任务书假设不同"，我独立复核后确认）。

### 10.6 🟧 其它外部面

| 面 | 位置 | 外部影响方式 |
|---|---|---|
| 小程序远程包 | `miniapp/*.appinfo.json`：`packageUrl: https://minipkg.<host>/yaoyy_<appId>/afts/file/A*…`、`vhost: https://<appId>.eco.imclientapps.com` | 服务端下发新版本即替换本地包 |
| 支付页模板 | `QUICKPAY@*` / `MOBILEIC@*` 49 个 + `template.info` 版本表 | 运行时按 `tplVersion` 从服务端拉新模板，本地只是兜底 |
| 预置小程序 | `nebulaPreset/{66666692,68687209}`（PK→内含 `.tar`） | 与 `ariver_platform_ap_appid` 白名单绑定 |
| 首页 AI 入口 | `config/agent_nvwa_config_0_0_1.json` 里的 `guiUrl`（`https://n.<host>/dingding/one_cover_page/index.html?...&dd_mini_app_id=992025121710385075`） | 服务端改 config 即换入口 URL |
| 隐私政策 | `values/strings.xml` 的 `privacy_*_url` / `new_dingding_privacy_*` | 服务端下发 H5 地址 |
| 图片资源 | `drawable-*` 里 `huawei_xpn_guide_step1..5.png`、`xiaomi_xpn_guide_step1..5.png` | 厂商渠道专属引导图（10 张，1.0 MB），只对特定 ROM 生效 |

### 10.7 🟥 `res/raw/` 里的静态凭据与推送参数（可被"外部影响"的另一面：**外部可直接读取**）

| 面 | 位置 | 说明 |
|---|---|---|
| **OAuth client_secret（明文）** | `res/raw/ali_oauth_config.json` | `dingmail_android_oauth` / `<REDACTED_CLIENT_SECRET>`。任何解包者都能取走；若该 secret 在服务端被信任，等于公开 |
| Exchange/Gmail OAuth 客户端 | `res/raw/eas_{internal,international}_oauth_config.json`、`gmail_auth_config.json` | 3 个 client_id + scope（含 `mail.google.com`、`EAS.AccessAsUser.All`） |
| **明文 XMPP** | `res/raw/alipay_push_prop` | `XMPP_HOST=mcometgw.alipay.com:443`，**`SSL_USED=0`** |
| 调试脚本 | `res/raw/h5_{debug_console_sw,bugme_hookappx,dev_vorlon,jsinterface_bridge}.js` | 由 §11.3 的开关触发注入；脚本本体常驻 APK，可离线审计 |
| JSAPI 白名单 | `res/raw/available_modules.json` | 小程序可调 API 的权威清单（含 `network.request`/`mtop.request`/`user.login`） |

**【推断】** 这些不是"被外部影响"的面，而是**对外泄面**：内容一旦写出即永久公开，服务端无法回收。对 task-3/task-5 直接有用。

---

## 11. 资源侧的调试 / 开发 / 隐藏入口证据

### 11.1 三大"开发者选项"入口（三条不同路径，互不替代）

| # | 载体 | 资源 ID | 内容 |
|---|---|---|---|
| A | `res/layout/developer_options_settings.xml` | layout **0x7f0d07e5** | 极简 3 项：`setting_developer_options_debugging`（微应用调试开关）、`setting_developer_options_cache`（禁用 WebView 缓存）、`setting_developer_options_thread`（打印 Doraemon 线程堆栈）。文案 `enable_webview_debuggable_notification`(0x7f114d28) = **"注意: 只要打开，将处于调试模式，在这里的数据不再特别安全，这个版本是开发者专用版本，如果你不是一个开发者，请从官网，wwww.<host> 下载一个新版本，以保障你的数据安全"**；标题 `enable_webview_debuggable_title`(0x7f114d29)=「微应用调试」 |
| B | `res/layout/dev_setting.xml` | layout **0x7f0d07e4**（28,314 B，**93 个控件 id**） | 巨型调试面板，见 §11.2 |
| C | `res/xml/h5_bugme_setting.xml` | xml **0x7f15000d** | `PreferenceScreen`，**明文中文硬编码**（未走 strings.xml），见 §11.3 |

**【观察】** `settings_developer_txt` = 「开发者选项」= **0x7f115f01**；`dt_conf_debug` = 「调试工具」= **0x7f111ec3**。

### 11.2 `dev_setting.xml` 的 93 个控件 id（按能力归类）——本报告最有价值的一张表

| 能力域 | 控件 id |
|---|---|
| **Mock / 伪造** | `bt_mock_scan`、`btn_mock_msg_db`、`et_mock_rate`、`constant_key_check_switch`、`constant_key_check_dialog` |
| **环境切换** | `btn_facebox_env`、`btn_facebox_gray`、`vip_master_addr`、`vip_slaver_addr`、`spinner_lang`、`btn_set_lang` |
| **专属版授权** | **`btn_exclusive_debug_license`**、**`et_exclusive_debug_license`** ← 直接对应"专属IM调试工具"的 license 注入 |
| **自动化/插桩** | **`btn_automator_debug`**、`dev_aladdin`、`ll_dev_aladdin`、`btn_dump`、`btn_hprof_analyze`、`btn_strict_mode` |
| **WebView / UC 内核** | `btn_ariver_on/off`、`enable_uc_preload`/`disable_uc_preload`、`enable_uc_proxy`/`disable_uc_proxy`、`enable_webview_cache`/`forbid_webview_cache`、`tv_uc_preload`、`tv_uc_proxy`、`disable_uc_preload`、`tv_status_webview_debug` |
| **网络** | `btn_gaea_config`、`btn_dr_httpdns`、`et_download_protocol`、`et_upload_protocol`、`upload_download_switch`、`tv_xpn`、`btn_xpn` |
| **性能** | `enable_perf_window`/`disable_perf_window`、`btn_debug_fps`、`layout_ariver_debug`/`title_ariver_debug`、`btn_beacon_diagnostics` |
| **埋点/统计** | `btn_debug_statistics`、`btn_debug_search_stat`、`btn_debug_personal_info`、`btn_get_advertising_id`/`tv_advertising_id`、**`btn_ut_debug_key_gen`/`et_ut_debug_key`**（UT 埋点调试密钥生成） |
| **数据面** | `tv_msg_db_size`/`btn_get_msg_db_size`、`push_history`、`rpc_history`（对应文案「下行消息历史」0x7f11xx / 「RPC请求历史」） |
| **杂项** | `bt_dso_test`、`btn_test_activity`、`btn_test_layout`、`btn_test_proguard`、`btn_test_provider`、`btn_ai`、`btn_apm_activity_on`、`btn_apm_fragment_on`、`debug_hpm`/`no_hpm`/`release_hpm`、`btn_dev_healthkit`、`btn_dr_thread`、`btn_dr_img_download`、`tv_cur_uid`/`et_uid`、`btn_submit_config_data`、`btn_encrypt`、`create_chat`、`dev_dingui_demo`、`dev_power_test_demo`、`dev_getting_vipinfo`、`close_js`/`open_js`、`mail_reader_debug`、`et_mail_reader_remote`、`btn_mail_*`(5 个) |
| 布局容器 | `ll_dev_setting`、`ll_dev_healthkit`、`ll_dev_vipinfo`、`ll_apm_sample_setting`、`tv_status_core`、`tv_status_hpm_debug`、`core_system`、`core_uc`、`push_history`、`rpc_history` |

- **【观察】** 该布局仅引用 3 个 string（`dt_dev_setting_push_history`、`dt_dev_setting_rpc_history`、`switch_string`）——**其余 label 全部是代码里 `setText()` 硬编码**，所以**不能只靠字符串搜索找到全部入口**。这是一条重要的方法论提示（对 task-2/task-3 同样适用）。
- **【推断】** `btn_exclusive_debug_license` + `et_exclusive_debug_license` 说明**专属版 license 可以在运行时手工填写**。这可能是"激活专属版能力"的入口，也可能是"调试 license"专用（名字里带 debug）。

### 11.3 `h5_bugme_setting.xml`（0x7f15000d）——明文中文的 H5 调试面板

```xml
<PreferenceCategory android:title="Hybrid调试设置">
  CheckBox "启用Hybrid调试"          key=h5_bug_me_debug_switch      summary="修改后立即生效"
<PreferenceCategory android:title="辅助功能">
  CheckBox "启用Js Injector"         key=h5_bug_me_js_injector
  CheckBox "启用vorlon的Dom调试"     key=h5_bug_me_dom_debug         summary="依赖vorlon，可能影响页面性能"
<PreferenceCategory android:title="实验室功能">
  CheckBox "Chrome不插线调试(默认端口:9983)"  key=h5_enable_ri_wired_debug   summary="立刻生效"
  CheckBox "禁止UC托管网络"           key=h5_disable_alipay_network
  CheckBox "禁止UC预创建webview"      key=h5_disable_uc_precreate
  CheckBox "禁止预下载在线页面主文档"  key=h5_disable_uc_predownload
  CheckBox "强制关闭Bugme Dump"       key=h5_bug_me_force_no_dump   summary="修改后杀进程生效"
  CheckBox "Jet 系统专用"             key=h5_bug_me_debug_switch_keep summary="Jet 专用，后果自负"
  CheckBox "启用H5Trace"              key=h5_trace_debug_switch
```

- **【观察】** **"Chrome 不插线调试（默认端口 9983）"** 是一行硬证据：打开后 WebView 在 **localhost:9983** 开 devtools socket，**无需 adb 转发**即可被局域网/本机 Chrome 接管。
- **【观察】** "启用 Js Injector" + "vorlon DOM 调试" → 可向任意页面注入 JS。
- **【观察】** "Jet 系统专用 / 后果自负" 说明存在一个内部代号 **Jet** 的宿主环境分支。
- **【推断】** 这些开关**不走 strings.xml**（硬编码中文），而且**没有品牌替换**，是原始IM内部工具留下的。

### 11.4 专属IM调试工具（realm 配置编辑器）—— `dt_dev_realm_config_*` 家族

**【观察】** 26 条以 `dt_dev_realm_config_` 开头的字符串（其中 24 条**只存在于英文 default 池**，中文小包里缺失）：

| 字符串 | 中文/含义 | res id |
|---|---|---|
| `dt_dev_realm_config_activity_lable` | **专属IM调试工具** | 0x7f1128b1 |
| `dt_dev_realm_config_environment_title` | 运行环境 | **0x7f1128b5** |
| `dt_dev_realm_config_environment_dev` / `_pre` / `_online` | 日常 / 预发 / 线上 | — |
| `dt_dev_realm_config_key_mock` | **配置模拟** | **0x7f1128b7** |
| `dt_dev_realm_config_key_search` / `_search_result` | 搜索配置 / 搜索结果： | — |
| `dt_dev_realm_config_list_title` / `_key` / `_type` / `_value` / `_not_found` | 全量配置列表：/key/type/value/not found | — |
| `dt_dev_realm_config_org_title` | **生效组织** | **0x7f1128bf** |
| `dt_dev_realm_config_exhibition` / `_tool` | 配置列表 / 调试工具 | — |

配套 layout：`activity_dev_realm_config_exhibition.xml`(**0x7f0d014d**)、`ll_dev_realm_config_functions.xml`、`ll_dev_realm_config_list.xml`、`item_dev_realm_config_cell.xml`、`radio_button_dev_config_type.xml`。

- **【推断】** 这是一个**运行时配置表（realm config）就地编辑器**：可选"运行环境（日常/预发/线上）"、按"生效组织"筛选、搜索 key、**"配置模拟"改写 value**、查看"全量配置列表"。它直接操作 §10.1 那 1,637 个 key 所在的同一张表。
- **【推断】** 若该 Activity 可达（未导出也可通过内部路由 `imclient://…` 或 `BokuiActivity` 跳转），等于**给了任何登录用户一个"改本机全部客户端开关"的界面** —— 这是本次资源分析里**风险最高的一条**。可达性判定留给 task-3。

### 11.5 环境 / 预发常量（可用于判定实例归属）

| 字符串 | 值 | res id |
|---|---|---|
| `daily_env` | 日常 / Daily | 0x7f110905 |
| `pre_env` | 预发 / preEnv | 0x7f115cfa |
| `dt_daily_env_unit_nt` | 南通日常 | — |
| `dt_pre_env_unit_nt` | 南通预发 | — |
| `dt_pre_env_unit_singapore` | 新加坡预发 | 0x7f1143cd |
| `and_show_realm_login_menu_realm_login` | （realm 登录菜单） | 0x7f1104d9 |

**【推断】** 至少 3 套环境（日常/预发/线上）× 2 个机房（南通/新加坡），与 manifest 里的 `pre-alidocs.<host>`、`dev-alidocs.<host>`、**`doc.imclient.test`** 等 host 对应。

### 11.6 其它调试/测试残留（partial list，完整见 `scan/res/dev-layouts.tsv` 123 条）

| layout | res id | 说明 |
|---|---|---|
| `activity_debug_config` | 0x7f0d0147 | 通用调试配置页 |
| `h5_offline_debug_panel` | 0x7f0d0ce7 | H5 离线包调试面板 |
| `remote_debug_modal` | 0x7f0d16de | **小程序远程调试**弹窗（配 `tiny_remote_debug_*` 10 条字符串：连接中断/已连接/连接中/命中断点/确定退出远程调试） |
| `trace_debug_modal` | 0x7f0d18e4 | **无线性能调试**（`tiny_trace_debug`=0x7f116120「无线性能调试」，含 network/experience 两种子模式） |
| `calendar_activity_local_mock` | 0x7f0d04ea | 日历本地 Mock 页 |
| `activity_aiball_debug` / `layout_ai_ball_debug_dialog_view` / `layout_ai_ball_debug_prompt_item` | — | **AI 球调试**（可改 prompt） |
| `activity_automator_debug` / `activity_plugin_test` / `activity_rpc_dev{,_detail,_detail_info,_detail_json}` / `activity_push_dev_detail` / `activity_update_test` / `activity_live_player_test` / `activity_test_video` / `activity_youku_player_test` / `activity_video_preview_test_activity` / `activity_trans_device` / `teleconf_fragment_debug` / `im_debug_kv_layout` / `im_debug_message_info_layout` / `feed_dialog_debug` / `layout_chat_msg_page_debug` / `telesaascore_layout_dev_performance_info` / `video_conf_dev_stream_info` / `dummyautotestingforwukong` | — | 20+ 个按模块划分的调试页 |

**【观察】** `hide` 型隐藏入口线索：
- `uc_core_debug_key` = **0x7f1161e3**，值 `J1x9FmKk10alLx5k6eFZU51v4DL5gq9NbFS2s5yjPiQnZkmx5yLW/ZvdQYRXQC+YBQOR4u` —— **硬编码的 UC 内核调试密钥**（44 字符 base64 形态）。**【推断】** 这是"输入密钥解锁 UC 调试能力"的口令，属可被外部输入的**硬编码凭据**。
- `dt_robot_developer` = 「开发者」= 0x7f1145c2（机器人开发者身份标签）
- `search_debug_input_tip_title` = 「是否允许本次调试」0x7f115e6e / `_detail` = "点击允许，则本次的搜索信息会上传至服务端" —— **搜索调试 = 上传搜索内容**
- `dt_mail_enable_imap_debug_tips` = 「是否开启 IMAP Debug 模式」0x7f113c73
- `debuggable_biztype_message` = 0x7f110927：提示 `getLocation` 在 **debuggable 包**下不返回定位 —— **说明存在"按包 debuggable 状态分流"的代码分支**
- `dd_mini_check_permission_deny_debug_confirm` = 「你还未被设置为开发人员，无法体验此版本」/ "only for internal testing use, you are not in the test group" —— **小程序开发版白名单机制**的提示文案
- `flutter_enable_debug_mode` —— Flutter 调试模式开关字符串（值在 zh 侧为空）

### 11.7 深链 / scheme 常量（资源侧）

**【观察】** manifest 里 `<data android:scheme>` 共 7 个：`imclient`、`http`、`https`、`content`、`file`、`smsto`、`@string/qq_scheme`。
**【观察】** `<data android:host>` 共 27 个，其中**测试/预发 host 直接进包**：

```
开发/测试：doc.imclient.test、dev-alidocs.<host>、pre-alidocs.<host>、pre-alivideolive.taobao.com、localhost
生产：     <host>、m.<host>、applink.<host>、qr.<host>、ddurl.to、dinger.<host>、
           live.<host>、alidocs.<host>、android.imclientmail.com、h5.m.taobao.com、alivideolive.taobao.com、
           m.laiwang.com、platformapi、mybank.cn
内部路由：imclientclient、oauthCallback、alipayAccount、merchantpay、processpaymentresult、nfc、
           <PKG>
```

**【观察】** 字符串里用户可点的 URL 共 13 条（`values/strings.xml`），全部指向 `<host>` / `alicdn.com` / `taobao.com` / `unsplash.com`；**没有一条指向 IM 域名** → 再次印证"品牌替换只改文案不改基础设施"。

---

## 12. 与既往报告（`re/imclient_mod/report/manifest-res.md`）的核对

| 既往结论 | 我的复核 | 判定 |
|---|---|---|
| 包名/版本 8.2.2.1 / 689 / label IM | 完全一致（`apktool/AndroidManifest.xml` + aapt2 badging） | ✅ 一致 |
| activity 1052 / alias 5 / service 125 / receiver 43 / provider 27 | **独立复算完全一致**（我用 apktool 解码后的 manifest 重新遍历） | ✅ 一致 |
| `exported=true` 共 **79** 个 | **一致**：activity 35 + receiver 23 + service 15 + alias 4 + provider 2 = 79 | ✅ 一致 |
| NSC 无 domain-config、base cleartext=true、信任 system+user CA | **一致**（§10.5 原文） | ✅ 一致 |
| `res/layout/developer_options_settings.xml` 存在 | **一致**（0x7f0d07e5），并补出同族的 `dev_setting.xml`(0x7f0d07e4) 与 `h5_bugme_setting.xml`(0x7f15000d) | ✅ 一致 + 补充 |
| 「这个版本是开发者专用版本」文案 | **一致**（`enable_webview_debuggable_notification` = 0x7f114d28） | ✅ 一致 |
| `res_arsc` 共 **304,270 条字符串**，其中 **6,773 条含 IM** | 我按"每个 `values-*/strings.xml` 的 `<string>` 逐条累加"得 **358,961** 条，含 IM/IM **9,362** 条、含 IM **2,648** 条 | ⚠️ **口径差异**（非矛盾）：既往应是用 aapt `dump --values` 的去重/单配置口径；我的是"locale 展开总数"。两者不能直接比较，**建议引用时注明口径** |
| 「IM 国际品牌」 | **更精确**：不是"国际品牌"而是**全语言替换（德语除外）**，且替换只到文案不到域名（§6.2-6） | 🔧 **修正/细化** |
| 打包完整性：MANIFEST.MF 覆盖 21,031 条，无未签名普通条目 | **一致**（21,034 − 3 签名文件） | ✅ 一致 |
| 时间戳集中在 2026-01-28 | 未复核（属 zip 元数据，不在本任务范围） | ⏸ 未做 |

**新发现、既往报告未覆盖**（本报告新增）：

1. **`values-de` 品牌替换缺失**（591 条 IM / 0 条 IM）→ 指向"构建期批处理漏项"。
2. **`dev_setting.xml` 93 个调试控件 id**，含 `btn_exclusive_debug_license`、`btn_automator_debug`、`btn_ut_debug_key_gen`、`bt_mock_scan`。
3. **`h5_bugme_setting.xml` 的"Chrome 不插线调试 9983"** 与 Js Injector / vorlon / H5Trace。
4. **`dt_dev_realm_config_*` = 运行时配置表编辑器**（环境切换 + 配置模拟 + 生效组织 + 全量列表）。
5. **`uc_core_debug_key` 硬编码调试密钥**（0x7f1161e3）。
6. **`assets/config/default_config.json` 1,637 key + `custom_config.json` 29 key**（含 H5 上传/保存白名单）——可被服务端/本地覆盖的配置面。
7. **`APK_VALID.txt` / `appSize.txt` 与实际文件不一致**（+237,894 B），并用签名证据排除了改包。
8. **`easygo_hw.json` 的 `client` 仍是母包名** `<PKG>` → 上游遗留文件。
9. **本地隐私政策版本 `0.0.8.1801042138`（2018）** 与线上 2024 版 URL 严重不同步。

---

## 13. 未解项（【未知】，建议交给其它 task）

| # | 未知 | 归属 |
|---|---|---|
| 1 | `CN=alibaba` 证书是否与线上官方IM一致（需官方 APK 比对） | task-3 |
| 2 | `dev_setting` / `dt_dev_realm_config` 这些 Activity **实际可达性**（是否 exported、有无权限、路由能否触发） | task-2 / task-3 |
| 3 | `values-de` 未替换是"厂商构建缺陷"还是"德语包来自未替换的上游"（需要 arsc 字符串池顺序/时间戳证据） | task-3（可与签名分析合并） |
| 4 | `uc_core_debug_key`（0x7f1161e3）的解密/校验逻辑与消费点 | task-2 |
| 5 | `fghijklmnopqr`/`mb`/`qb`/`stuvwxyz01234567` 四个 10×10 PNG 的真实用途 | 需运行期验证 |
| 6 | `ab_d.bin`/`ab_r.bin` 的加密格式与读取方 | task-2 |
| 7 | `FilePaths`/`FilePath.txt` 的 `IR` root 语义、`id:-1470486623` 的生成规则 | 低优先级 |
| 8 | 49 个 `QUICKPAY@*` / `MOBILEIC@*` 模板的内部格式（是否加密 zip / 是否含可执行 JS） | task-3（支付面） |
| 9 | `nebulaPreset/{66666692,68687209}` 内层 `.tar` 的小程序代码内容 | task-2（小程序容器） |
| 10 | `lightapp/js/*.js` 注入面是否覆盖第三方 H5 域、有无 CSP | task-3 / task-5 |

---

## 附录 A · 产物索引（`scan/res/`）

| 文件 | 内容 |
|---|---|
| `gen_artifacts.py` | 本报告全部统计的可重跑脚本 |
| `res-tree.tsv` | 86 个 res 目录 × (type, files, bytes) |
| `decode-coverage.tsv` / `decode-failures.tsv` | AXML 解码覆盖（按 type）+ 失败清单（空） |
| `values-coverage.tsv` | 102 个 values XML × (bytes, entries) |
| `assets-inventory.tsv` | 1,148 个 assets × (path, bytes, bucket, magic) |
| `assets-buckets.tsv` | 16 类汇总 |
| `locale-strategy.tsv` / `strings-base-classes.tsv` | 每 locale 条目数与覆盖度 / 默认池三类构成 |
| `brand-scan.tsv` / `brand-samples.tsv` | 品牌逐 locale 计数 / 逐条命中样本 |
| `dev-string-index.tsv` | 178 条 dev/debug/mock/环境相关字符串（key, zh, default） |
| `dev-layouts.tsv` | 123 个 dev/debug/mock 相关 layout × (bytes, id 数, id 列表) |
| `key-res-ids.tsv` | 15 个关键资源的 `0x7f…` ID |
| `theme-chain.txt` | 1,342 个 style 的清单 + `DtTheme.Normal` 完整继承链 |
| `client-config-keys.tsv` | `default_config.json`(1,637) + `custom_config.json`(29) 全量 key/value |
| `aapt2-badging.txt` | aapt2 badging 原文（25 个 locale label 取证） |
| `<pkg>.RSA` / `<pkg>.SF` | 签名块副本（证书取证） |
| `apktool_decode.log` | apktool 2.11.1 全量解码日志（EXIT=0） |
| `target_resources_only.apk` | 精简 APK（72.7MB，仅供 apktool 复现，可删） |

## 附录 B · 关键路径速查

```
apktool/AndroidManifest.xml                    明文 manifest（911,960 B）
apktool/res/values/public.xml                  72,130 条资源 ID 映射
apktool/res/values/strings.xml                 25,381 条默认(英文)字符串
apktool/res/values-zh/strings.xml              17,587 条中文
apktool/res/values-de/strings.xml              ⚠ 唯一未做品牌替换的语言包
apktool/res/layout/dev_setting.xml             ⚠ 93 个调试控件
apktool/res/layout/developer_options_settings.xml
apktool/res/xml/h5_bugme_setting.xml           ⚠ 9983 端口 / Js Injector
apktool/res/xml/network_security_config.xml    ⚠ 全明文 + 信任 user CA
unpacked/assets/assets/config/default_config.json   1,637 个客户端开关
unpacked/assets/assets/config/custom_config.json    29 个（含 H5 文件白名单）
unpacked/assets/assets/easygo{,_hw}.json       多窗口适配名单
unpacked/assets/assets/imclientttid            exclusive_imclient_405272002
apktool/res/raw/ali_oauth_config.json          ⚠ 明文 OAuth client_secret
apktool/res/raw/alipay_push_prop               ⚠ XMPP SSL_USED=0
apktool/res/raw/{security,white,redirect}_link.html   链接拦截三件套
apktool/res/raw/h5_debug_console_sw.js + h5_bugme_hookappx.js + h5_dev_vorlon.js   调试注入脚本
apktool/res/raw/available_modules.json         小程序 JSAPI 白名单
apktool/res/raw/{ada_amock1,fr_mock1..4,ga_mock,keep}.xml   tools:keep 保活清单（mock 残留）
```
