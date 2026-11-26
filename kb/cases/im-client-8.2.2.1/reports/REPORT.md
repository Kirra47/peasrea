# IM 8.2.2.1「专属IM / IM」全量逆向总报告

> 目标文件：`base.apk(3).1`（299,485,058 B，SHA-256 `2433588b58436a0e55270f2a66c286f0fe7bc41618d7f5e069fc6ef99d609195`）
> 工作目录：`D:\Deepseek-Harness-workspace\re\base_apk3\`｜生成时间：2026-10-27
> 取证口径：全部结论来自本机对 APK 的独立复算（aapt2 / apksigner / jadx 全量反编译 / apktool 解码 / ELF 静态分析 / dex 字符串表），不采信任何既往结论；与之冲突处已在各分报告注明。
> 标签：**〔观察〕**=可直接复现；**〔推断〕**=由证据推导；**〔未知〕**=静态证据不足。

---

## 0. 一页速览

| # | 问题 | 答案 |
|---|---|---|
| 1 | 这是什么 | 阿里巴巴官方签名的**「专属IM」OEM 客户端**（`FLAVOR=enterprise`、`UA_2ND_TYPE=exclusive`），品牌 IM/IM，内核IM **8.2.2.1（689）**，包名 `<PKG>` |
| 2 | 是不是改包/木马 | **不是**。v1+v2 签名均通过，证书 `CN=alibaba`（2014→2124），21,034 条目同一构建时间戳，`.w2534344268` 贯穿包名/自定义权限/authority/内部命名空间 → 构建期 applicationId 改名；未见注入器、外联 C2、隐私窃取代码 |
| 3 | 规模 | 30 dex / **180,864 类** / 1,233,999 方法 / 2,053,806 字符串；152 个 `.so`（244.8 MB）；19,344 个资源；1,148 个 assets；仅 arm64-v8a |
| 4 | 逆向到什么程度 | 全量反编译 **84,971 个 .java（598 MB）**，非 synthetic 顶层类覆盖 **99.37%**；资源解码 **13,088/13,088 失败 0**；152 个 .so 全部归类，5 个 SecurityGuard 库的**段表破坏已还原**可反汇编 |
| 5 | 最大的配置面风险 | NSC 全局 `cleartextTrafficPermitted=true` + **信任用户 CA**；1,252 组件 / **79 exported** / 68 个无权限保护 |
| 6 | 能不能抓包 | 主通道（MTOP/IM/QUIC）走 `libgaea → liblsquic`，**TLS 静态内嵌在 native**，不经过 Android TrustManager → NSC 放行 user CA 对主通道**无效**；Java 层**无 certificate pinning**（`w33` 连 `check()` 都没有）。能抓的只有平台栈流量（WebView/第三方 SDK/ANet-Java 层） |
| 7 | 开发者面板能不能开 | **不能靠改配置**：`ywm.a()` 恒 false 且全包零写入方；`Doraemon.getRunningMode()` 初值 4，包内唯一写点是 `1→2` 降级 → 两道锁只能靠**改包或运行时 hook**越过；门控失败是 `postDelayed(finish,1000)` 静默自杀 |
| 8 | 真正的攻击面 | ① `owt.conference.debugger.TracingBroadcastReceiver`（exported 无权限）→ 任意 App 一条广播即可让IM**全进程方法级 tracing**；② `ExternalProvider` 读权限是 `protectionLevel=normal` → 任意 App 可读「是否已登录 + 组织开通了哪些微应用」 |
| 9 | 防护栈 | 六层全是阿里自有 + 已知开源：SecurityGuard / SafeGuard / ByteHook / Zoloz-facedevice / 安恒 libsafechat / libzkfv_tj。**无第三方加固壳**（无梆梆/爱加密/维数），无 frida-gadget |
| 10 | 最值得继续攻的点 | **Surgeon `ISurgeon` 注入协议**——它是打开全部 dev 门控的钥匙，也是理解全包分支结构的钥匙（release 下 `$surgeonFlag` 恒 null） |

---

## 1. 目标身份

| 项 | 值 | 来源 |
|---|---|---|
| 包名 | `<PKG>` | badging / BuildConfig |
| versionName / Code | `8.2.2.1` / `689` | badging |
| 应用名 | `IM`（zh/zh-TW/fr/…）、`IM`（en/ja/ko/th/vi/…） | `application-label-*` |
| 入口 | `<PKG>` + 3 个 launcher alias + `LaunchHomeForEasyGoActivity` | manifest |
| Application | `<PKG>` | manifest |
| SDK | minSdk **21** / targetSdk **33** / compileSdk **35** | badging |
| ABI | 仅 `arm64-v8a` | badging |
| 语言 | 25 locale（`es/pt/sr/mk` 是 36–55 条的空壳） | badging + 01 报告 |
| 构建 | `BUILD_TYPE=release`、`DEBUG=false`、`BUILD_ID=PIS804274115090441216`、构建时间 2026-01-28 08:59:49 | BuildConfig |
| MTOP | `MTOP_APPKEY=21811227` | BuildConfig |

**签名**〔观察〕：v1 通过、**v2 通过**、无 v3/v3.1/v4、单签名者；证书 `CN=alibaba, OU=alibaba, O=alibaba, L=hangzhou, ST=zhejiang, C=86`，RSA-2048/SHA1withRSA，SHA-256 `a680d36e6014d4d7b5ec64dc79b576ebe96a48c6dca9121355c946c900e926f2`。

**[推断]** v2 覆盖整包 + 阿里证书 + 单一构建时间戳 + 27 个 provider authority 全部带 `.w2534344268` 后缀 + `assets/easygo.json` 的 `client` 字段同名 → **构建期 applicationId 改名，非二次打包**。任何本地修改都必须重签成自有证书，服务端是否据此拦截需动态确认（见 §10、§12）。

---

## 2. 容器与目录

| 分组 | 条目 | 解压 | 说明 |
|---|---|---|---|
| 根 | 72 | 242 MB | 30 个 dex（220.5 MB）+ `resources.arsc`（32.3 MB）+ `AndroidManifest.xml`（1.0 MB） |
| `lib/arm64-v8a/` | 152 | 244.8 MB | 138 ELF + 14 非 ELF（6 个签名迷你 APK、1 个伪 APK、1 个 7z、1 个 ZIP、3 个 `.ucb` 桩、3 个 `.version` 桩） |
| `res/` | 19,344 | 52.9 MB | layout 7,574；drawable 家族 32.18 MB（60.8%） |
| `assets/` | 1,148 | 36.6 MB | flutter_assets 13.07 MB、lottie 4.95 MB、miniapp 离线包 3.84 MB、端侧模型 3.63 MB |
| `META-INF/` | 175 | 4.8 MB | v1 签名 + `dt_plugin_config/*.xml`（插件配置）+ 116 个 `*-build_version.properties` |
| 其它（org/kotlin/com/okhttp3…） | 143 | 0.6 MB | 开源库自带资源 |

**异常扫描结果**〔观察〕：无路径穿越条目、无重名、无大小写冲突、无 MACOSX/Thumbs.db 垃圾；全部条目时间戳同一构建会话；`APK_VALID.txt`/`appSize.txt` 里的数字与实际不一致，属签名前口径，不构成改包证据。

---

## 3. 代码规模与反编译覆盖

| 指标 | 数值 |
|---|---|
| dex | 30（`classes.dex`…`classes30.dex`），220.5 MB |
| class_defs | 180,864（唯一 180,862） |
| 方法 / 字段 / 字符串 | 1,233,999 / 1,884,431 / 2,053,806 |
| 顶层包 Top | `com.alibaba` 70,696、`com.alipay` 21,769、`com.taobao` 6,885、`com.google` 4,102、`com.imclient` 1,391、`com.amap` 1,228、`com.huawei` 1,049、`org.webrtc` 815、`cn.wps` 769、`com.uc` 746 |

**反编译**：`jadx 1.5.6 -j 24 --no-res` 全量 → **84,971 个 .java / 598 MB**，方法级报错 283（不阻断）。
- 顶层类 90,131 → 命中 81,891（**90.86%**）
- 未命中 8,240 = 7,668 个 `ACC_SYNTHETIC`（编译器产物，jadx 默认跳过）+ 572 个非 synthetic（Windows 大小写不敏感同名覆盖 + 个别保存失败）
- 即 **非 synthetic 顶层类覆盖 99.37%**；要 100% 字节码级覆盖用 `dexdump -d` 或把 dex 拷到大小写敏感文件系统重跑（README 有命令）

**混淆形态**〔观察〕：R8 深度混淆（`a00`/`jln`/`e4l` 之类短名占多数）+ 阿里 **Surgeon** 插桩（`ISurgeon.surgeon$dispatch("<id>")`，8 个类）。但**框架/SDK 命名空间未混淆**（`<PKG>.*`、`mtopsdk.*`、`com.alipay.mobile.*` 全可读），功能面完全可还原。

---

## 4. 功能地图

按类数（`scan/dex-index/functional-groups.tsv`，共 180,862 类；"share" 是占全包比例）：

| 子系统 | 类数 | 主要命名空间 |
|---|---|---|
| 支付宝容器 / 支付 msp | 16,548 | `com.alipay.mobile`、`com.alipay.android` |
| RTC / 音视频 | 11,886 | `com.alibaba.android.teleconf`、`com.taobao.taopai`、`org.webrtc.mozi`、`com.aliyun.player`、`tv.danmaku.ijk` |
| IM 业务 | 8,562 | `com.alibaba.android.imclientim` |
| 三方通用库 | 8,483 | guava/glide/bouncycastle/gson |
| 组织 / 通讯录 / 用户 | 6,316 | `com.alibaba.android.user.*` |
| 会议 / 直播 / 圈 | 5,886 | `com.alibaba.android.teleconf`、`com.rokid.sdk` |
| 小程序运行时 | 5,610 | `com.alibaba.lightapp` |
| H5 容器 nebula/UC | 5,526 | `com.alipay.mobile.nebula*`、`com.uc.webview` |
| 邮箱 alimei | 5,344 | `com.alibaba.alimei` |
| 小程序容器 ariver | 3,380 | `com.alibaba.ariver` |
| 钉盘 / 文档 cspace | 2,181 | `com.alibaba.imclient.cspace`、`cn.wps` |
| 网络 MTOP/ANet/Gaea | 2,152 | `mtopsdk`、`anet`、`com.imclient.gaea` |
| 推送通道 | 2,006 | 华为/小米/OPPO/vivo/荣耀/FCM |
| 调试面板 Doraemon | 1,872 | `com.alibaba.doraemon` |
| IM 协议 laiwang/LWP | 1,769 | `com.alibaba.laiwang`、`com.laiwang.protocol` |
| IM 内核 wukong | 1,756 | `com.alibaba.wukong` |
| 人脸 / 风控 Zoloz | 1,598 | `com.alibaba.security`、`com.dtf.face`、`com.alipay.zoloz` |
| 地图 / 定位 | 1,452 | `com.amap.api`、`com.autonavi.*` |
| 日历 | 1,295 | `com.alibaba.android.calendar` |
| 数据层 bee/加密 SQLite | 578 | `com.alibaba.bee`、`com.sqlcrypto`、`com.j256.ormlite` |
| Flutter | 448 | `io.flutter`、`com.alibaba.imclient.flutter` |
| Nest / dtnest 新框架 | 385 | `com.imclient.nest` |
| 启动框架 | 119 | `com.alibaba.android.launcher`、`com.alibaba.imclient.startup` |
| Surgeon 插桩框架 | 8 | `com.alibaba.surgeon` |
| 其余（R8 短名，无法按包归属） | 50,294 | 混淆后的业务代码 |

> 详细架构与调用链见 `analysis/02-code-architecture.md`。

---

## 5. 多进程模型〔观察〕

1,252 个组件分布在 **22 个进程**（`scan/dex-index/processes.tsv`）：

| 进程 | 组件数 | 职责（由承载组件推断） |
|---|---|---|
| 默认 | 1,183 | 主 UI + IM 协议（`LWPService`）+ 网络（`NetworkService`/`XStateService`）+ 定位 |
| `:lite1`…`:lite5` | 各 7 | mPaaS/Nebula H5 多开容器（`H5Activity$H5ActivityN`、`LiteProcessService`） |
| `:push` / `:pushservice` | 4 / 4 | 长连接推送核心（`PushCoreService`）+ 厂商通道（HMS/XM） |
| `:mcs` | 3 | 会议（`OwtRemoteService`）+ tracing 接收器 |
| `:tools` | 4 | 日志开关、视频扩展、邮件详情截屏、Babysitter |
| `:reboot` / `:preload` / `:misinstall` | 3 / 3 / 1 | 重启恢复、预加载、静默安装引导 |
| `:normal_render_proc0` / `:isolate_render_proc0` / `:gpu_process` | 1 / 1 / 1 | 小程序沙箱渲染三进程 |
| `:channel` / `:rklite` / `:heap_analysis` / `:dex2oat` | 3 / 3 / 1 / 1 | 埋点通道、Rokid AR、Java OOM 分析、dex2oat |

**[推断]** 渲染/沙箱三进程（`normal_render_proc0`/`isolate_render_proc0`/`gpu_process`）+ 5 个 mPaaS lite 进程是小程序/H5 的隔离设计，也是动态分析时最容易漏掉的进程（hook 只挂主进程会看不到 WebView 行为）。

---

## 6. 资源与配置面

完整版见 `analysis/01-resources-assets.md`（803 行）。要点：

**解码覆盖**〔观察〕：13,088 个二进制 AXML **全部**解成可读 XML；6,256 个二进制资源原样保留；`resources.arsc` 展开为 64 个 `values*` 目录 / 102 个 XML；失败 **0**。

**语言策略**〔观察〕：default = **英文基底**（25,381 条，其中 PUA 图标 2,968 条），中文在 `values-zh`（17,587 条）；23 个语言是 17.0–18.4k 条的同构翻译包；`es/pt/sr/mk` 仅 36–55 条（空壳）。

**品牌替换**〔观察〕：default 582 条、zh 632 条含 "IM"；**`values-de` 一条未替换，仍 591 条 "IM"** —— 全包唯一漏项语言。URL 全部指向 `<host>` 未白标 → 确证「IM内核 + IM OEM 外壳」。

**`res/raw/` 是被低估的目录**（101 文件 / 2.53 MB，仅 38 个音频）〔观察〕：
- `ali_oauth_config.json`：**明文 OAuth client_secret**（`client_id=dingmail_android_oauth`，`client_secret=<REDACTED_CLIENT_SECRET>…-<REDACTED_CLIENT_SECRET>`，`redirect_uri=alimailclientandroid://oauthCallback`）
- `alipay_push_prop`：`XMPP_HOST=mcometgw.alipay.com` + **`SSL_USED=0`**
- `security_link` / `white_link` / `redirect_link`：三道链接拦截页
- 8 个 H5 注入脚本（`h5_debug_console_sw.js`、`h5_bugme_hookappx.js`、`h5_dev_vorlon.js`、`rvtools_inject_js.js`…）
- `available_modules.json`：小程序 JSAPI 白名单（含 `network.request`、`mtop.request`、`user.login`）

**客户端开关面**〔观察〕：`assets/config/default_config.json` **1,637 个 {key,value}**；`custom_config.json` 29 个（含 `ta_saveFile_whiteList`/`h5_uploadFile_whiteList` H5 沙箱目录白名单、`ariver_platform_ap_appid` 白名单）。这些是"出厂默认值"，可被服务端/realm 配置覆盖 → 动态分析时是改行为最省力的入口。

**调试资源**〔观察〕：123 个 dev/debug/mock 相关 layout；`dev_setting.xml`（0x7f0d07e4）一个文件 93 个控件 id（`bt_mock_scan`、`btn_exclusive_debug_license`、`btn_automator_debug`、`btn_ut_debug_key_gen`、`btn_gaea_config`…），label 全是代码 `setText` 硬编码 → **纯搜字符串找不到**；`h5_bugme_setting.xml`（0x7f15000d）明写「Chrome 不插线调试(默认端口:9983)」+ Js Injector + vorlon。

---

## 7. Native 层

完整版见 `analysis/04-native.md`（470 行）。要点：

**清点**〔观察〕：152 文件 = **138 ELF**（全 `ELF64/AArch64/DYN/PIE`，GNU_STACK 全 RW，无 textrel/RELR）+ **14 非 ELF**（6 个签名迷你 APK、1 个伪 APK、1 个 7z、1 个 ZIP、3 个 `.ucb` 数据桩、3 个 `.version` 文本桩）。唯一未 strip 的是 `libsafechat.so`（保留 2.88 MB DWARF，含源码路径）。

**JNI 面**〔观察〕：87 个库导出 `JNI_OnLoad`；70 个库共 **2,488 个 `Java_*` 导出**；**33 个库的 `JNINativeMethod` 表在 `.data.rel.ro` 明文**，解析出 **808 个 native 方法**（名称+签名+地址，见 `scan/native/jni_tables.tsv`）。

**SafetyGuard 段表破坏已还原**〔观察+已复现〕：5 个 `libsg*` ELF 的节头表被擦除（`sh_addr/sh_offset=0xffffffffffffffff`、`sh_name=0`、`sh_size=0x10`），但 `PT_LOAD`/`PT_DYNAMIC` 完好 → 用 `DT_SYMTAB/DT_STRTAB/DT_HASH` 重建后 `llvm-readelf -S` 零错误、`objdump -d` 正常（`scan/native/unpacked/*.shdr-repaired.so`）。

**关键库定性**：

| 库 | 定性 | 关键证据 |
|---|---|---|
| `libzkfv_tj.so` | **支付宝 `java2jni`（Java→native AOT）产物，只服务人脸链** | 水印 `…|java2jni-1.0.10.0-(20201217)|`；Java 侧 `defpackage.lus.a()` 打印 "java2jni java.library.path is:" 后 `loadLibrary("zkfv_tj")`；17 个 native 调用点全在 `com.dtf.face.*`/`com.dtf.toyger.*`/`faceverify.*` |
| `libsafechat.so` | 安恒 SM4 + wolfSSL 加解密，**无任何检测项** | 3,623 符号 + 2.88 MB DWARF 全查：frida/xposed/root/ptrace 命中 0；20 个 `DIJni` 入口含 VOIP 会话密钥 |
| `libfacedevice.so` | Zoloz 设备风控，**全包检测名单的真正所在** | hook 框架 20 项、root 系 12 项（KernelSU/APatch/Sukisu/Kitsune/zygisk…）、su/busybox 35 条、虚拟摄像头 14 项、模拟器 40+、`TracerPid`/`/proc/self/*` |
| `libsafeguard.so` | 服务端驱动 DLP + **inline-hook CRC 检测器** | `HookScanner::InlineHook::GetLibTextSectionCrcInFile`：对已加载库 `.text` 做 CRC；`CommandType` 38 条（沙箱/Office API hook/安全浏览器） |
| `libdalvikhack.so` | DalvikUtils（9 个 `RegisterNatives`） | `setClassVerifyMode`/`disableJitCompilation`/`dvmJdwpStartup`/`addBootClassPath`；只导入 `dlopen`/`dlsym` → ART 下多为降级 |
| `libcrashsdk.so` | 崩溃捕获 **+ root/hook 探测** | `/libsechook.so`、`has root: %s`、`Read self maps` |

**悬空依赖**〔观察〕：12 个库引用 5 个包内不存在的库（`libijkffmpeg.so`×7、`libv8uc.so`×2、`libjsi.so`、`libantplayer-2.0.so`、`libistylepdfengine.so`）→ 运行期由插件/容器装配，静态不可解。

---

## 8. 网络与协议

完整版见 `analysis/05-network-api.md`（388 行）+ `scan/net/protocol-notes.md`。

**端点面**〔观察〕：三路抽取（30 dex 字符串 + 1,148 assets + 152 .so）→ 10,303 命中 → 去噪 **3,713 条**（host 675 / url 2,977 / ip 61）、**1,078 个域名**、**180 个真实 MTOP api 名**。环境分布：线上 594 / 预发 30 / 日常 39 / 内网 12（含 `10.0.0.172` CMWAP 代理、`10.38.162.35`、`172.16/172.30`）。

**分层**〔观察+推断〕：

```
业务(MTOP api)   ── HTTP 语义，sign 在 SecurityGuard/AVMP
IM(LWP/wukong)   ── 自研二进制帧
        └── Gaea（native 本地代理出网）── HTTP/2 + LSQUIC(UDP/443) ── ANet/AMNet 会话与寻址
                                               └─ Bifrost / XCDN 内容分发
```

**MTOP 签名**〔观察，关键〕：sign base string 字段顺序完整还原（22 项）：
`utdid&uid&reqbiz-ext&appKey&urlencode(data)&t&api&v&sid&ttid&deviceId&lat&lng&[extdata]&x-features&routerId&placeId&open-biz&mini-appkey&req-appkey&accessToken&open-biz-data`；生产签名走 `SecurityGuard.signRequest(requestType=7)` / 中间件 `unifiedSign`（`x-sign` + `x-mini-wua`）/ AVMP `mwua`；Java 层只有 HMAC-SHA1 兜底（需 appSecret，**不在 Java 层**）。

**LWS 长连接**〔观察〕：**不是 WebSocket**。4 字节头 `[(type<<12)|len][(version<<14)|(attrCount<<8)|(cipher<<7)]` + TLV（1B id + 2B len）+ AEAD body；type `HELLO_REQ=1/HELLO_RESP=0/DATA=3/PING=4/PONG=5`；4040 字节分片 + seq/checksum 防重放；`REUSE_SID` 快重连；握手属性 `REUSE_SID0/CIPHER_SUITE1/SNI2/APP_PUB_KEY3/APP_NONCE4/SERVER_NONCE5/VIA129/VERSION131/UA132`。服务端公钥硬编码 7 个 SNI（test/default/cdn1..cdn5，各 32 B），可被 Gaea 配置轮换，也可被 URI `?pub-key=` 覆盖 → **既是"可轮换 pin"，也是注入点**。

**登录会话**〔观察〕：扫码（`WebLoginActivityV2` + `qr.<host>`）、密码/免密、第三方 OAuth（`com.ali.user.open.oauth`）、运营商一键登录（`rcs.cmpassport.com`）；**多端登录/设备绑定是服务端策略**，客户端只有 `MultiLoginActvity` + `KICKOUT` 展示。

---

## 9. 安全与对抗

完整版见 `analysis/03-security.md`（770 行，12 节）。下面只保留结论。

### 9.1 防护栈（六层，全部阿里自有 + 已知开源，无第三方加固壳）

| 能力 | 实现 | 默认是否构成阻力 |
|---|---|---|
| 反篡改 / 设备指纹（wua / securitybody） | SecurityGuard：5 个 ELF + 5 个签名迷你 APK + 5 个 `.ucb` 加密体 | 静态可逆；运行时 `RegisterNatives` 加密，需 hook 已注册方法；**服务端仍校验 wua** |
| DLP / 反 Hook / 安全浏览器 / 沙箱 | `libsafeguard.so`（38 条命令） | **默认关**：总闸 `AntiStrategyHandler.isGrayOpen_` 默认 false，需服务端下发 |
| PLT/GOT hook 框架 | `libbytehook.so`（14 个导出） | 双刃：既是防护，也可作为"对抗对抗"的工具 |
| 设备风控（人脸链） | `libfacedevice.so` + Zoloz/toyger | 只在前置人脸/活体链路触发 |
| 消息/文件加密 | `libsafechat.so`（安恒 SM4 + wolfSSL） | 无检测逻辑 |
| 人脸链混淆库 | `libzkfv_tj.so`（java2jni AOT） | 无独立检测，纯代码保护 |

**反调试现状**〔观察〕：Java 侧**不存在"检测到即退出"的路径**（`isDebuggerConnected` 9 处全是降噪用途；`TracerPid` 在 30 dex 中 0 命中）。真正会退出的只有 `libfacedevice`（人脸链）和号码认证 SDK 的 `SystemManager.checkEnvSafe`（转 -10003，只断一键登录）。

### 9.2 抓包：瓶颈不是 pinning，是 TLS 不在平台上

- NSC 发布态生效〔观察〕：`cleartextTrafficPermitted=true` + `trust-anchors{system,user}`，无 `domain-config`、无 `debug-overrides`。
- **决定性事实**：`libgaea.so → liblsquic.so`，而 `liblsquic.so` 的 `DT_NEEDED` 只有 `libz/libm/libdl/libc` —— **TLS 静态内嵌**。MTOP/IM/QUIC 不读 NSC，**用户 CA 对主通道无效**。
- **pinning 为零**〔观察〕：`w33`（OkHttp3 `CertificatePinner`）被裁得没有 `check()` 入口；`CertificatePinner.DEFAULT` 是空集；全包无 `add(host, pin)` 调用。
- 结论：普通 HTTP 代理只能看到**平台栈**流量（WebView、HttpsURLConnection、第三方 SDK、广告）；主业务要抓，得 hook native `SSL_read/SSL_write`，或从 `SSLKEYLOG`/上游透明代理入手。

### 9.3 开发者能力：6/6 门控全部闭合

| 门 | 机制 | 能否本地翻越 |
|---|---|---|
| `ywm.a()`（开发者选项整页开关） | 常量 **false**，全包**零写入方**（唯一路径 Surgeon id `1669440712`） | 否，需改包/hook |
| `Doraemon.getRunningMode()` | `sMode=4`；包内唯一写点 `if(mode==1) setRunningMode(2)`（`f6.java:489`、`AIBallPublisherHelper:195`）→ **只能 1→2 降级** | 否，需改包/hook |
| 服务端 `dev_setting` | `j35.e` → 本地 map + Gaea `general.dev_setting_for_gray_android`；但 `DevSettingActivity.v1` 初值 2 使 `e1()==0` 恒不成立 | 仅服务端可开 |
| WebView 远程调试（DevSetting 内） | `abg.b()`：先要 mode∈{1,2}，再查 SP `DevSettingActivity_WEBVIEW_DEBUG` 或 Gaea `ga_7100x_js_debug_android` | 否（但下面有例外） |
| `DevSettingActivity` endpoint 覆盖 | `L()`/`Y()` 的 12 项覆盖表（LWS/QUIC/SHORT/OAUTH/ALADDIN/MEDIA_ID/邮箱 6 项/ENV + `setAPSecurityEnv`）**全在 mode 门控内** | release 下整套是死的 |
| `HttpsTrustAllCertsTrustManager` | 仅服务 Doraemon TRACE artifact | 无实际风险 |

**两个反例（值得注意）**〔观察〕：
1. **邮件/文档模块有十余处硬编码 `setWebContentsDebuggingEnabled(true)`** —— 不走门控，直接可用（`chrome://inspect` 可连 WebView）。
2. 门控失败的行为是 `postDelayed(finish, 1000)` **静默自杀**（不设 contentView、无 toast）→ 动态分析时表现为"点了没反应"。

### 9.4 攻击面（79 exported 里真正可利用的两个）

1. **`owt.conference.debugger.TracingBroadcastReceiver`**（exported、无 permission）：任意 App 发一条 `imclient.mcs.start_tracing` / `stop_tracing` 广播即可让IM**全进程方法级 tracing**（DoS + `.trace` 落盘可提取）。同族 `TracingBroadcastReceiverMcsProcess` 在 `:mcs` 进程。
2. **`<PKG>`**：`readPermission` 的 `protectionLevel=normal` → **任意 App 声明该权限即自动获得**；云控键 `f_base_external_provider_enabled` 默认 true → 可读出「是否已登录 + 组织是否开通考勤/审批微应用」两个布尔（**登录态预言机**）。
3. 降级项（复核后不再是风险）：华为 `PushProvider` 实为 `signature` 级；`Bokui*` 的 `phone/password-from-Intent` 路径被 `q01.e()` 三重门控（Doraemon mode + autokey008 测试账号文件），release 不可达；`/action/mock_nologin_switch` 在 84,971 个反编译文件中**零命中**，仅 classes4.dex 留有字符串 → 未闭合但不可达。

---

## 10. 改包 / hook 实操路线

### 10.1 抓包

| 目标 | 手段 | 可行性 |
|---|---|---|
| WebView / 第三方 SDK / 广告 | 系统代理 + user CA（NSC 已放行） | **直接可行** |
| ANet-Java 层 / 部分 OpenAPI | hook `X509TrustManagerFactory.getX509TrustManager()` 返回空 TM | 可行（本包自带 `EmptyX509TrustManagerWrapper` 可直接复用） |
| MTOP / IM / QUIC 主通道 | ① hook `SSL_read`/`SSL_write`（`libssl-dd.so` 在包内，499 符号无 custom_verify）② PCAPdroid 抓 UDP + 导 lsquic 密钥（不现实） | 难，需 native hook |

### 10.2 Frida 落点（按优先级）

1. **先处理 `libsafeguard` 的 `.text` CRC 检测**（`HookScanner::InlineHook::GetLibTextSectionCrcInFile`）——这是唯一会主动发现 inline hook 的模块；平时 `isGrayOpen_=false` 不参与，但服务端可开。
2. 人脸链外的检测很少：`libfacedevice` 只在前置人脸时加载 → **不触发人脸就不必绕**。
3. SecurityGuard：`JNI_OnLoad` 内 `RegisterNatives`，hook 符号名无效 → hook `RegisterNatives` 本身或直接用已注册方法的 native 地址。
4. Doraemon/DevSetting 门控：要开面板，改 `ywm.a()` 返回值 + `Doraemon.getRunningMode()` 返回值（两处都是静态字段/单例，hook 成本低）。

### 10.3 改包注意

- v2 整包签名 → 改动必须重签自有证书；`META-INF/<pkg>.SF` 里 21,031 条覆盖（含 `resources.arsc`/`AndroidManifest.xml`），**不要只改 dex 不重签**。
- 包内有 `app-metadata.properties`（AGP 7.1.3 与 compileSdk 35 矛盾）、`dummy_dd.c` 等流水线痕迹，属正常构建产物。
- `libsg*` 段表被擦除，但**不要试图修复后回编译**（v2 会失败）；只有静态分析才需要修。

---

## 11. 未解项（明确列出，附下一步）

| # | 未解 | 建议验证方式 | 价值 |
|---|---|---|---|
| U1 | Surgeon `ISurgeon` 注入协议与 `$surgeonFlag` 签名校验 | 反编译 `com.alibaba.surgeon.*`（8 个类）+ 找 `surgeon$dispatch` 调用点 | **最高**：它是打开全部 dev 门控的钥匙 |
| U2 | `libzkfv_tj` 的 `RegisterNatives` 类名/方法名 | 动态 hook `RegisterNatives` dump | 中（人脸链） |
| U3 | LWS 会话密钥 KDF / `CIPHER_SUITE=0` 算法 | 逆 `libkaliumjni` / `liblws` | 中（IM 协议复现） |
| U4 | `libgaea`/`liblsquic` 内嵌 TLS 是否另有应用层 pin | 动态 hook `SSL_CTX_set_verify` / 抓 QUIC 握手 | 中（决定能否 MITM） |
| U5 | 服务端是否校验签名/包名（改包后能否登录） | 重签安装后观察登录接口返回 | **高**（决定改包可行性） |
| U6 | `ScreenRecorderService` / `RequestDispatchService`（exported 无权限）真实能力 | 反编译 + 动态调用 | 中 |
| U7 | `mock_nologin_switch` 的 dex 级 xref | 用 `dexdump`/smali 搜字符串引用 | 低（已判定不可达） |
| U8 | 5 个 `.ucb` 加密体的解密路径 / UC 7z 容器内部 | 逆 `libWebViewCore` 或动态 dump | 低（WebView 内核） |
| U9 | `libdalvikhack` 的 `dvmJdwpStartup` 是否被调用 | xref + 动态 | 低 |
| U10 | 重复 `start_tracing` 行为、TRACE artifact 是否真加载 | 动态 | 低 |

---

## 11.5 实战进展（第二轮「全部拿下」）

| 目标 | 结果 | 位置 |
|---|---|---|
| **Surgeon 热修框架** | 契约完整还原：`ISurgeon` + `Surgeon.e(i)` 反射写 `$surgeonFlag` + `InstantPatcher.handlePatches()`（默认**无签名校验**）→ 可整体替换任意 instrumented 方法 | `analysis/11-surgeon-unlock.md` |
| **解锁版 APK** | 三个字节级补丁（`ywm.a()` 恒真、`Doraemon.sMode=1`、`setRunningMode` 置 no-op 防降级）→ 重签名 v1+v2+v3 → **S10 真机安装运行成功、无 VerifyError**；`@webview_devtools_remote_*` 出现 = WebView 调试已解锁 | `analysis/11-surgeon-unlock.md`、`tools/patch/`、`tools/patch/shots/` |
| **Surgeon 契约修正** | 补丁文件名是 `surgeon<i>.jar`（非 dex）；`SecurityChecker` 用**运行时 APK 自身签名**校验补丁 jar → 官方包上第三方 patch 被拒，只有重签包可用。全包 **31,430 插桩类 / 583,595 个 (方法,id) / 317,536 个 id**，门控相关 49 条已核对 | `analysis/07-unlock.md`、`tools/patches/data/` |
| **Frida 脚本** | `ywm.a()` / `Doraemon.getRunningMode()` / `setWebContentsDebuggingEnabled` 三处 hook | `tools/frida/unlock.js` |
| **LWS 加密** | `CIPHER_SUITE=0` = **X25519 ECDH + ChaCha20-Poly1305（libsodium 非 IETF，8B nonce/16B tag/无 AAD），无 KDF**；`libkaliumjni.so` 只导出 9 个 JNI，无 hkdf/sha256 | `analysis/09-capture-lws.md`、`scan/net/lws_crypto.md` |
| **Gaea TLS** | 不走 `libssl-dd`，而是**静态内嵌 OpenSSL 1.1.1h-dev**；`SSL_read/SSL_write/SSL_CTX_new` 是**导出符号** → 可 hook 看明文（QUIC 不行）；另有 `set_ssl_verify_disabled` 导出 | 同上 |
| **攻击面 PoC** | `ExternalProvider`（normal 读权限、2 列布尔）、`TracingBroadcastReceiver`（`mcs_trace.trace`）、`ScreenRecorderService`（复用 MediaProjection 令牌）、`RequestDispatchService`（自报包名可伪造） | `analysis/10-poc.md`、`tools/poc/` |
| **mock_nologin_switch** | 全 30 dex 仅 1 处引用（`classes4/UrlUtils.G`），被 `getRunningMode()==4` 挡住 → **mode=1 解锁后变为可达** | `analysis/10-poc.md` |
| **免登录进调试面板** | `android:exported` 从 false 翻成 true（AXML 字节级补丁）→ **未登录状态 `adb am start` 直接进「开发设置」全量面板**（改环境/覆盖 6 组 endpoint/注入 uid/mock 扫描/UT key），真机实测通过 | `analysis/13-login-free.md`、`tools/patch/patch_manifest.py`、`tools/patch/shots/ds*.png` |

---

## 12. 产物索引

| 路径 | 内容 |
|---|---|
| `REPORT.md` | 本文件（总报告） |
| `README.md` | 目录导航 + 工具链 + 命令 |
| `analysis/00-identity-container.md` | 指纹/签名/清单/NSC/覆盖率（183 行） |
| `analysis/01-resources-assets.md` | 资源与 assets 全解（803 行） |
| `analysis/02-code-architecture.md` | 代码架构与调用链 |
| `analysis/03-security.md` | 安全栈/门控/攻击面/Frida 建议（770 行） |
| `analysis/04-native.md` | 152 个 .so 全解（470 行） |
| `analysis/05-network-api.md` | 网络与协议（388 行） |
| `java/sources/` | 全量反编译（84,971 文件 / 598 MB） |
| `apktool/` | 明文清单 + 全量资源解码（19,446 文件） |
| `unpacked/` | 原始 dex / native / res / assets |
| `scan/lead` `scan/res` `scan/dex-index` `scan/security` `scan/native` `scan/net` | 全部证据（tsv/json/脚本，可复算） |

---

## 13. 与既往报告的差异（复核结论）

| 既往结论 | 本轮复核 |
|---|---|
| 域名为 414 个 | **1,078 个**（本轮加入 assets + native 字符串） |
| "无 pinning" | 需限定在 **HTTP/Java 侧**；LWS 有应用层服务端公钥 pin（7 个硬编码 SNI 公钥） |
| `libsafechat` 含检测名单 | **不含**（3,623 符号 + 2.88 MB DWARF 全查，0 命中）；检测名单在 `libfacedevice` |
| `libcrashsdk` 仅崩溃捕获 | 另含 root/hook 探测串 |
| `libzkfv_tj` 未定性 | **已定性**：支付宝 java2jni AOT，人脸链专用 |
| 华为 `PushProvider` 有风险 | 实为 `signature` 级，第三方不可用 |
| `mock_nologin_switch` 可达 | 84,971 个反编译文件中零命中，仅残留字符串 |
| `ywm.a()` 写入方未知 | **不存在写入方**，唯一覆盖路径是 Surgeon |
| `Doraemon.getRunningMode()` 初始化未知 | `sMode=4`，只能 1→2，无法 4→1/2 |
