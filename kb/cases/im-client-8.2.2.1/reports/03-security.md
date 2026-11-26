# 03 · 安全栈与开发者门控全解

目标：`target.apk` = IM 8.2.2.1 专属版
包名 `<PKG>` / versionCode 689 / minSdk 21 / targetSdk 33 / compileSdk 35（`aapt2 dump badging` 实测）。

证据口径：
- **〔观察〕** = 本轮直接从 `target.apk` / 30 个 dex / 152 个 .so / 反编译产物读出的确定事实，附文件与行号/偏移。
- **〔推断〕** = 由观察按代码语义推导，未做动态验证。
- **〔未知〕** = 静态证据不足，给出下一步验证方法。

工具与产物：`scan/security/`（`dex_classes.txt` 184,177 类索引、`string_hits.txt` 关键词分组、`elf_info.json` 152 个 .so 的 ELF 清单、`native/` 取证与反汇编、`components.json` 1,252 个组件、`manifest_tree.txt`）。

---

## 0. TL;DR（九条结论）

1. **防护栈全部是阿里自有 + 已知开源组件，没有第三方加固壳（无梆梆/爱加密/维数），也没有 frida-gadget 注入器。** 六层：SecurityGuard（支付宝安全，5 个 ELF + 5 个签名迷你 APK + 5 个加密体）、SafeGuard（IM自研，38 条服务端下发命令）、ByteHook（PLT/GOT hook 框架）、Zoloz/facedevice（人脸前的设备风控）、libsafechat（安恒 wolfSSL 消息/文件加密）、libzkfv_tj（人脸链专用混淆安全库）。
2. **SecurityGuard 的"段表破坏"已实测可还原**：section header 被写成 `sh_addr/sh_offset = 0xffffffffffffffff`、`sh_name = 0`，导致 readelf / pyelftools / llvm-nm 全部报错；但 PT_LOAD/PT_DYNAMIC 完好，走 `DT_SYMTAB/DT_STRTAB/DT_HASH` 可恢复全部导出（5 个库均确认导出 `JNI_OnLoad`）。→ **静态逆向不受阻，只是需要换入口**。
3. **抓包的决定性事实不是 pinning，而是 TLS 栈不在平台上**：`libgaea.so → liblsquic.so`，而 `liblsquic.so` 的 `DT_NEEDED` 只有 `libz/libm/libdl/libc`（TLS 内嵌/自带）；MTOP/Gaea/LWS 通道不经过 Android 的 `TrustManager`，**`networkSecurityConfig` 里放行 user CA 对主通道完全无效**。
4. NSC 确认发布态生效且宽松：`cleartextTrafficPermitted=true` + `trust-anchors{system,user}`，无 `domain-config`、无 `debug-overrides`；叠加 manifest `usesCleartextTraffic=true`。其收益仅限**平台栈流量**（WebView / HttpsURLConnection / OkHttp 默认 TM / 第三方 SDK / 广告）。
5. **应用层无 certificate pinning**：`w33`（OkHttp3 `CertificatePinner`）只用默认空实例，`com.squareup.okhttp.CertificatePinner.DEFAULT` 同样为空，全包无任何 `add(host, pin)` 调用。→ 能抓到什么，取决于目标通道用的是不是平台 TLS，而不是 pin。
6. **开发者面板在 release 下是硬关闭的，且无法由本地配置翻越**：`ywm.a()` 常量 `false` 且**全包无写入方**；`Doraemon.getRunningMode()` 初值 `4`，APK 内唯一写入点是 `if (mode==1) setRunningMode(2)`——**只能 1→2 降级，永远无法 4→1/2**。所有 dev 能力（DevSettingActivity / WebView 调试 / endpoint 覆盖 / 测试账号登录）都挂在这两个值上。
7. **`DevSettingActivity` 门控失败后的行为是静默自杀**：`onCreate` else 分支 `paf.a().postDelayed(new h(), 1000)` → `finish()`（不设 contentView、无 toast）。
8. **攻击面里真正可利用的是两个，且都不是"高权限"级的**：
   - `owt.conference.debugger.TracingBroadcastReceiver`（exported、无 permission）→ 任意 App 一条广播即可让IM开始/停止 **全进程方法级 tracing**（DoS + 落盘可读的 `.trace`）。
   - `ExternalProvider` 的 **`readPermission` 是 `protectionLevel=normal`** → 任意 App 声明该权限即自动获得，可读出「是否已登录 + 组织是否开通考勤/审批微应用」两个布尔。
   其余（Huawei `PushProvider`、`TracingBroadcastReceiverMcsProcess`、`Bokui*`）需要签名级权限或已被门控。
9. **`libzkfv_tj.so` 定性完成**：不是"未知壳"，而是**只服务于人脸/活体链的设备安全库**——唯一 Java 入口是 `defpackage.lus.a()`（`System.loadLibrary("zkfv_tj")`），6 处调用点全部在 `com.dtf.face.*` / `com.dtf.toyger.*` / `faceverify.*`；10 个 `init_array` 构造器 + 控制流平坦化的 `JNI_OnLoad` + 导入 `dl_iterate_phdr`/`syscall`/`pthread_create`。详见 §3.8。

---

## 1. 防护矩阵

图例：可控性 = 静态/动态干预难度（低=容易处理，高=难）；「绕过位置」给的是可操作的落点。

| # | 能力 | 实现库 / 类 | 证据（〔观察〕） | 是否可绕过 | 绕过位置 / 备注 |
|---|---|---|---|---|---|
| 1 | 签名校验 / 反篡改 / 设备指纹（wua / securitybody） | `libsgmainso-6.6.230702`、`libsgsecuritybodyso-6.6.230702`、`libsgmiddletierso-6.6.230702`、`libsgmiscso-6.5.14625633`、`libsgnocaptchaso-6.5.14625633` + `com.alibaba.wireless.security.open.*` | 5 个 ELF 段表被毒化（`sh_addr=UINT64_MAX`），均导出 `JNI_OnLoad`；`libsgsecuritybodyso` 另有混淆导出 `one_jni_onload` / `one_jni_onunload` / `SIUl6HjRjt` / `J2qaFN4xHz` / `pDhsAJkF7h` / `iHUgZQREYY` / `HlupqL3ZAR` / `DWJlgGtyQT`；`libsgmain.so` 等 5 个同名文件是 **ZIP（签名迷你 APK）**；`*.ucb.so` 加密体、`*.version.so` 版本桩 | 中（静态可逆，运行时硬） | 静态：`scan/security/native/sg_recovered_symbols.txt`（PT_DYNAMIC 还原）。运行时：`JNI_OnLoad` 内 `RegisterNatives`，需在 `loader` 之后 hook 已注册方法而非符号名。**服务端仍会校验 wua/securitybody 签名**，客户端绕过≠业务可用 |
| 2 | 服务端驱动的 DLP / 反 Hook / 安全浏览器 / 沙箱 | `libsafeguard.so` + `com.alibaba.imclient.safeguard.*` | 1,928,984 B，**57 个 `init_array`**，`DT_NEEDED libbytehook.so + libcrypto-dd.so`；JNI 导出 `SafeGuardInterface$CppProxy{execCmdNative, execCmdV2Native, getInterface, nativeDestroy, setLocationManager, setLocationManagerExtra}`；`CommandType` 38 项（含 `START_SANDBOXIE/STOP_SANDBOXIE`、`INSTALL_IWEBOFFICE_API_HOOKS`、`CHECK_JSAPI`、`DECRYPT_HOOK_STRING`、`CATCH_RISK_SAMPLE`、`SAFE_BROWSER_CHECK_URL/CHECK_DOWNLOAD`） | 中 | 反 Hook 检查总闸 `AntiStrategyHandler.isGrayOpen_` **默认 false**，只有服务端策略下发才置 true（`initStrategyForJsCode` 回调）；`isInited()` 还要求 `SafeGuardMain.isInited()`。→ 平时不参与对抗；一旦服务端对该企业开启，需 hook `AntiStrategyHandler.isGrayOpen()` 返回 false，或掐 `SafeGuardDispatcher` RPC |
| 3 | PLT/GOT 内联 hook 框架（双刃） | `libbytehook.so` + `com.bytedance.android.bytehook.ByteHookMod` | 40 KB，14 个导出：`bytehook_hook_all/hook_partial/hook_single/unhook/get_prev_func/get_return_address/pop_stack/add_dlopen_callback/del_dlopen_callback/set_debug/bh_trampo_data` + `JNI_OnLoad` | —（既是防护也是**可用工具**） | 可用它做「对抗对抗」：`bytehook_hook_all("libc.so","open",...)` 之类，但注意与 Frida 的 inline hook 会互踩；建议 Frida 侧优先用 `Interceptor.attach` 且避开 bytehook 已占的 PLT 槽 |
| 4 | 人脸/活体设备风控（反 root / 反注入 / 反虚拟摄像头 / 反模拟器 / 反多开） | `libfacedevice.so`（2,624,112 B，15 个 `init_array`，2,627 导出，仅 `JNI_OnLoad`→`RegisterNatives`）、`libtoyger.so`、`libdtftoyger.so`；Java：`face.security.device.api.FaceSecDevice`（`System.loadLibrary("facedevice")`）→ `com.dtf.face.security.SecurityExt` | 检测名单见 §3.4；`UploadDeviceData` 上报；`getDeviceToken` 返回设备 token | 高（人脸场景） | 只在人脸/实人认证链路跑。刷脸必有；非刷脸路径不会被它判死。要过需同时遮蔽 `/proc/self/maps`、`/proc/self/status:TracerPid`、`/proc/net/{tcp,tcp6,unix}`、`pm list packages`、`which su`、`mount`，并清 stack trace 里的反射帧 |
| 5 | 消息/文件加密（企业级） | `libsafechat.so`（安恒 `com.dbappsecurity.et.DIJni`，内含 wolfSSL） | 3,698,232 B，**保留完整 `.symtab`（未 strip）**，1,193 个导出；wolfSSL 符号 `AddCA/AllocKey/AllocDer/BEGIN_CERT/BEGIN_PRIV_KEY/…`；JNI：`encryptMsg/decryptMsg/encryptFileHelper*/decryptFileHelper*/encryptKeys/encryptKeyData/encryptBufferHelper/setVoipKey/releaseVoipKey/getEncryptionAttributeHelper/domainName/stringFromJNI` | 低（业务数据面） | 不参与"防调试"，是**加密能力**而非检测能力。要分析其密钥协商需 hook `DIJni.encryptMsg` 入参；`.symtab` 未 strip 使静态定位极容易（相对其它库是最大突破口） |
| 6 | ART/Dalvik 运行时改造（JDWP 启动、bootclasspath、校验模式） | `libdalvikhack.so`（淘宝 `DalvikUtils` 血统） | 10 KB，导出 `_ZN13DalvikRuntime{4Init,6Create,C1Ev,C2Ev,16addBootClassPath,14dvmJdwpStartup}` + `instance_`；`init_array=['0x0']`（单槽空） | 低（仅 ART 下多为降级空路径） | 若被调用会改 bootclasspath / 启 JDWP —— 这本身是**可利用面**（JDWP 可被 attach）。检查 `Lcom/taobao/android/runtime/DalvikUtils;` 调用点是否为死代码 |
| 7 | 崩溃上报（含 native 栈） | `libcrashsdk.so` | 630 KB，18 个 `init_array`，22 导出，`JNI_OnLoad` | 低 | 上报通道，非对抗 |
| 8 | 人脸链专用混淆安全库（本轮新定性） | `libzkfv_tj.so` | 465,880 B；10 个 `init_array`；唯一导出 `JNI_OnLoad@0x3ecc4`；导入 `dl_iterate_phdr`、`syscall`、`pthread_create`、`__android_log_print`、`memcmp`；无任何 `Java_*` 导出 | 中 | 见 §3.8。Java 侧只需 hook `defpackage.lus.a()` 的返回值/副作用即可延后其初始化 |
| 9 | Hook 探测（Java 层，Xposed/Substrate） | `com.mobile.auth.gatewayauth.utils.security.CheckHook`、`com.alipay.edge.utils.FindHook` | `CheckHook.isHookByJar()` 读 `/proc/<pid>/maps` 匹配 `XposedBridge.jar` / `Xposed` / `xposed_art`；`isHookByStack()` 抛异常查栈：`com.android.internal.os.ZygoteInit` 出现 2 次、`de.robv.android.xposed.XposedBridge.main`、`…handleHookedMethod`；日志原文 `HookDetection, Xposed is active on the device.` 等 4 条 | 低（易绕） | 均为**第三方 SDK 自检**（号码认证 / 边缘计算），不是IM主业务闸。Frida 默认不改这两处栈帧 → 天然不触发 |
| 10 | 环境安全闸（root / 模拟器 / 代理 / 调试器） | `com.mobile.auth.gatewayauth.manager.SystemManager.checkEnvSafe`（`@SafeProtector`） | 四连检查 → 全部转 `-10003` 错误码：`手机终端不安全:the phone is root, …` / `…Emulator is detected, please use real phone!` / `…the phone is proxy, please do not proxy!` / `…the app is debuggerConnected, please do not debug!` | 低 | **只影响"一键登录/号码认证"业务**，不退出 App。要过：hook `SystemManager.checkEnvSafe` 返回 `null` |
| 11 | 反调试（Java，弱） | `defpackage.i.F()`、`com.alibaba.doraemon.impl.eventbus.EventButlerImpl.isDebuggerConnected()`、`com.alibaba.wukong.sync.impl.SyncMergeAck`、`defpackage.ck0`（ApmDebugMonitor） | `i.F()` = `E() && (Debug.isDebuggerConnected() || Debug.waitingForDebugger())`；`EventButlerImpl` = `mode==1 && Debug.isDebuggerConnected()` | 低 | `i.F()` 的调用者只有 ANRCanary（`HistoryTaskRecorder`），用途是**调试时抑制 ANR 误报**，不是安全闸。`ck0` 同理（抑制 APM 上报）。→ **Java 侧不存在"检测到调试器就退出"的路径** |
| 12 | 反调试（native） | `libfacedevice.so` / `libzkfv_tj.so` | `TracerPid:` + `/proc/self/status`；`/proc/%d/attr/prev|current`（SELinux 上下文）；`/proc/self/mountinfo`；`/proc/self/maps` 解析格式串 `%lx-%lx %4s %lx %*x:%*x %d%n`；`syscall` 直调 | 中 | 只在人脸链 + zkfv 初始化时跑。Frida 侧建议 **spawn 后立即 hook `open/openat/fopen/fgets/access/popen`** 做路径过滤，而不是等检测器起来 |
| 13 | 反注入（native） | `libfacedevice.so` | 库名黑名单：`gmain`、`gum-js-loop`、`pool-frida`、`gdbus`、`zposed`、`frida-agent`、`substrate`、`libriru_edxp.so`、`libsandhook.edxp.so`、`libwhale.edxp.so`、`libxposed_art.so`、`edxp.jar`、`fasthook`、`libfakeloc_initzygote.so`、`sandhook`、`libsubstrate.so`、`libiohook.so`、`libepic.so`/`libepic64.so`、`libexp824.so`/`libexp82464.so`、`libexposed.so`、`liblspd.so`、`libriru.so` | 中 | Frida 17 默认线程名 `gmain`/`gum-js-loop` 会被命中 → 需 `frida-server -d` / 重命名线程，或 hook `/proc/self/maps` 与 `/proc/self/task/*/comm` 读取 |
| 14 | 反 root（native，最全） | `libfacedevice.so` | 见 §3.4：Magisk / KernelSU / KernelSu-Next / APatch / APatch-Next / Kitsune Mask / Sukisu 全家族包名 + `/data/adb/ksu`、`/data/adb/ksud`、`/debug_ramdisk/su`、`/debug_ramdisk/shamiko/module.prop`、`libzygisk_loader.so`、`libzygisk.so` + 全量 `su`/`busybox` 路径 + `ro.boot.vbmeta.*`/`verifiedbootstate`/`sys.oem_unlock_allowed` | 中 | 需同时处理包名（`pm list packages -s/-3` 与 `getPackageManager`）、文件路径、属性、`/proc/self/maps` 四条线 |
| 15 | 反模拟器 / 反多开 | `libfacedevice.so`（模拟器）；`classes19`/`classes22`（多开） | Nox（`com.bignox.*`、`/system/bin/nox-prop`）、MEmu/microvirt、androVM、BlueStacks、`libnb.so`/`libhoudini.so`/`libntb.so`、`/sys/module/nemu*`、`/sys/class/thermal`；多开：dex 字符串 `, enableMultiApp `、`startMultiApp` | 中 | 多开检测在 Java 侧只有两个字符串、无检测实现体（推测为埋点/上报参数） |
| 16 | 反抓包（本地代理/端口探测） | `libfacedevice.so` | `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/unix`、`127.0.0.1`、`http_proxy`、`http.proxyHost`、`getNetworkInfo`；`CheckProxy.isDevicedProxy()` | 中 | 会识别「本机有 127.0.0.1 监听/http_proxy 设置」→ 抓包时**不要用本机代理端口**，改用透明代理或上游设备 |
| 17 | 反截屏/录屏（人脸场景） | `libfacedevice.so` | `/system/bin/screencap`、`/system/bin/screenrecord`、`/proc/self/mem`、`/proc/self/pagemap`、`/proc/self/task` | 低 | 同上，只影响人脸 |
| 18 | 字节码插桩（影响所有静态结论） | 阿里 Surgeon（`com.alibaba.surgeon.*`） | 全包方法带 `ISurgeon $surgeonFlag` + `InstrumentAPI.support(iSurgeon,"<id>")` + `surgeon$dispatch("<id>", …)` 双份实现；`InstrumentAPI.support` = `iSurgeon != null && iSurgeon.surgeon$support(id)` | — | **这是门控体系的核心**：`$surgeonFlag` 在 release 里恒为 `null`，所以每处都走"原实现"分支。要改行为，除了 hook 原实现，还可以**提供一个 `ISurgeon` 实现**（构造 `com.alibaba.surgeon.Surgeon` 实例并用反射写 `$surgeonFlag`）→ 一次性接管全包所有被插桩方法，比逐个 hook 高效得多〔推断，需动态验证 `Surgeon` 的注册协议〕 |

### 1.1 防护栈"齐全性"核对

| 期望能力 | 本包是否具备 | 承载 |
|---|---|---|
| 加固/壳（dex 加密、VMP、反 dump） | **否**（无独立壳；只有 Surgeon 插桩 + UC WebView 的按需 dex 加载） | `libdexloaderuc`/`liblibloaderuc`/`libfakedexuc.so` |
| 签名校验 | 是 | SecurityGuard `staticDataReport` / wua |
| 完整性校验 | 是 | SecurityGuard + `libfacedevice` 的 `SecurityExt`/`SgomInfoManager` 自检 |
| 反调试 | 是（但只在人脸链 + 号码认证 SDK 生效） | `libfacedevice`、`libzkfv_tj`、`CheckHook` |
| 反注入/hook | 是 | `libfacedevice`、SafeGuard、`CheckHook` |
| 反 root/模拟器/多开 | 是（native 最强） | `libfacedevice` |
| 证书 pinning | **否**（应用层无配置） | — |
| 抓包检测 | 是（限人脸链） | `libfacedevice` |
| 服务端风控联动 | 是 | wua/securitybody + SafeGuard 上报 + `UploadDeviceData` |

**总判**：这是一个「**服务端风控为主、客户端只在敏感链路（支付/人脸/一号通）做重检测**」的商业 App 防护形态，不是"整包加固"。主界面/IM/文档链路的客户端对抗强度很低。

---

## 2. SecurityGuard 段表破坏：机制与还原

〔观察〕5 个真实 ELF 的 section header 被系统性毒化，section table 本身仍在文件内：

```
libsgmainso-6.6.230702.so   filesize=1561580
  e_shoff=0x17cd88 e_shnum=25 e_shentsize=64 e_shstrndx=24
  section table end = 0x17d3c8 / file = 0x17d3ec  -> 表在文件内
  poisoned: sh_addr=UINT64_MAX in 25/25, sh_offset=UINT64_MAX in 21/25, sh_name=0 in 25/25
  [0] name=0x0 type=0x0  flags=0x0 addr=0xffffffffffffffff off=0xffffffffffffffff size=0x10
  [4] name=0x0 type=0x3  flags=0x0 addr=0xffffffffffffffff off=0x3e18 size=0x1c40
```

- 表现：`readelf -S` / `pyelftools` 抛 `ELFError("Expected section size to be a multiple of entry size in section ''")`；`llvm-nm` 抛 `section [index 6] has a sh_offset (0xffffffffffffffff) + sh_size (0x10) that cannot be represented`。
- 未受损：`PT_LOAD`（8 个 phdr 全部有效）、`PT_DYNAMIC`。
- **还原方法（已实现，`scan/security/tools/` 思路 + `sg_recovered_symbols.txt` 结果）**：
  1. 遍历 `PT_DYNAMIC`，取 `DT_SYMTAB(6)` / `DT_STRTAB(5)` / `DT_HASH(4)`（nchain 即符号数）/ `DT_SYMENT(11)`；
  2. 直接按 Elf64_Sym 数组遍历，用 `shndx != SHN_UNDEF` 且 `bind ∈ {GLOBAL, WEAK}` 过滤；
  3. 得到导出表：`libsgmainso` 319 个、`libsgsecuritybodyso` 17 个、`libsgmiddletierso` 12 个、`libsgnocaptchaso` 9 个、`libsgmiscso` 9 个，**全部包含 `JNI_OnLoad`**。
- 反推设计意图〔推断〕：破坏 section 只是为了打掉 IDA/Ghidra 的 section 视图与字符串引用恢复，**不增强任何运行时安全性**；对 Frida/动态分析零影响（`dlopen` 走 phdr）。

另有 10 个"非 ELF"同名文件（`scan/security/native/elf_info.json` 的 `kind` 字段）：

| 文件 | 实际类型 | 说明 |
|---|---|---|
| `libsgmain.so`、`libsgsecuritybody.so`、`libsgmiddletier.so`、`libsgmisc.so`、`libsgnocaptcha.so` | ZIP | **签名迷你 APK**（内含 `classes.dex` + `CERT.RSA`），SecurityGuard 的二次校验载体 |
| `libsgmainso.ucb.so`、`libsgsecuritybodyso.ucb.so`、`libsgmiddletierso.ucb.so` | 非 ELF 数据 | 加密体（ucb = update/encrypted body） |
| `libsg*so.version.so`（3 个） | 非 ELF 数据 | 版本桩 |
| `libWebViewCore_7z_uc_5.5.0.0.so` | 7Z | UC WebView 内核容器 |
| `libWebViewCore_7z_uc_jsi_255.so`、`libfakedexuc.so` | ZIP | UC WebView 内核 / 占位伪 APK |

---

## 3. 关键库逐个定性

### 3.1 `libsafeguard.so` — SafeGuard（IM自研，本轮最大增量）

〔观察〕
- 1,928,984 B；**57 个 `init_array` 构造器**（0x2c000 起，0x2d5b0 止）+ 1 个空槽；`DT_NEEDED` 含 **`libbytehook.so`** 与 **`libcrypto-dd.so`**。
- JNI：`Java_com_alibaba_imclient_safeguard_SafeGuardInterface_00024CppProxy_{execCmdNative, execCmdV2Native, getInterface, nativeDestroy, setLocationManager, setLocationManagerExtra}` + `JNI_OnLoad@0x7ee44`。
- `com.alibaba.imclient.safeguard.CommandType` 枚举 38 条命令（value → 名字，摘关键）：

| value | 命令 | 含义 |
|---|---|---|
| 1/2/3 | `REPORT_BASIC_DATA` / `REPORT_INC_DATA` / `REPORT_ANT_SDK_DATA` | 基础/增量/反 SDK 数据上报 |
| 4/5/23 | `SET_SWITCH_CONFIG` / `SET_STRATEGY_CONFIG` / `SET_SWITCH_CONFIG_DANGER` | 服务端下发开关与策略 |
| 7/8/18 | `GET_SECURITY_DATA_EX` / `GET_ATTEND_SECURITY_DATA` / `GET_ATTEND_CARD_SECURITY_DATA` | **考勤/打卡**安全数据 |
| 9 | `DO_DTPROTECT` | 触发整机保护 |
| 10/11 | **`START_SANDBOXIE` / `STOP_SANDBOXIE`** | 启动/停止沙箱容器 |
| 12 | `RELOAD_LIB_API` | 重载库 API |
| 16 | `CATCH_RISK_SAMPLE` | **抓取风险样本** |
| 17 | `CLEAR_INS` | 清理实例 |
| 25/28 | `SET_ANTI_STRATEGY` / `IS_NEED_UPDATE_ANTI_STRATEGY` | 反制策略 |
| 27 | **`CHECK_JSAPI`** | JSAPI Hook 检查 |
| 30–39 | `SAFE_BROWSER_*`（GET_JS_CODE/SET_STRATEGY/CALL/IS_NEED_UPDATE/CHECK_DOWNLOAD/CHECK_URL/CLEAR_STRATEGY_MEMORY/SAVE_UPLOAD_FILE） | 安全浏览器（URL 与下载检查） |
| 38 | **`INSTALL_IWEBOFFICE_API_HOOKS`** | 往 Office（iWebOffice/WPS）引擎装 hook |
| 40 | `DECRYPT_HOOK_STRING` | 解密 hook 字符串（反 hook 自身保护） |

〔观察〕反 Hook 闸门：`AntiStrategyHandler.checkJsApiInvoke()` 先判 `isInited() && isGrayOpen()`；`isGrayOpen_` 初值 **false**，仅在 `initStrategyForJsCode` 的服务端回调里置 true；`isInited()` 还要求 `SafeGuardMain.isInited()`。

〔推断〕这是**按企业/灰度的服务端开关式 DLP**：默认关闭，企业管理员开启后才有 JSAPI 防 hook、安全浏览器 URL 拦截、Office API hook、沙箱。对逆向的意义：**默认配置下它不是对抗阻力**，但一旦服务端开启 `INSTALL_IWEBOFFICE_API_HOOKS`，会与 Frida 的 hook 在同一 PLT 槽上打架。

### 3.2 `libbytehook.so` — ByteHook（字节开源，阿里改造）

〔观察〕40 KB，`JNI_OnLoad` + 14 个导出：`bytehook_hook_all` / `hook_partial` / `hook_single` / `unhook` / `get_prev_func` / `get_return_address` / `pop_stack` / `add_dlopen_callback` / `del_dlopen_callback` / `set_debug` / `get_mode` / `bytehook_init` / 数据符号 `bh_trampo_data`。dex 侧类名 `com.bytedance.android.bytehook.ByteHookMod`。
〔推断〕`libsafeguard.so` 用它做「后加载库的自动 hook」（`bytehook_add_dlopen_callback`）；它同时是一把**可借用的工具**：`bytehook_hook_all` 在 native 层做 PLT hook，比 Frida 的 `Interceptor` 更隐蔽（不写 ART 方法、不动 Java 栈）。

### 3.3 `libtoyger.so` / `libdtftoyger.so` — Zoloz 活体算法

〔观察〕`libtoyger.so`：9 个 `init_array`、121 导出，JNI 全是 `Java_com_alipay_zoloz_toyger_algorithm_Toyger_*`（`init` / `processImage` / `fetchRGBFrameData` / `fetchIRFrameData` / `fetchDepthFrameData` / `verifyFeature` / `storeFaceFeature` / `getSDKInfo` …）→ 活体算法本体，不含检测。`libdtftoyger.so`：`Java_com_dtf_toyger_base_algorithm_{Toyger,Nautilus}_*` + `Astro_sub_1message_1channel_*`；`init_array` 是 **18 个 0x0**（运行期由重定位填充）〔推断：被刻意清空以免静态定位构造器〕。

### 3.4 `libfacedevice.so` — 设备风控（检测名单全文）

〔观察〕2,624,112 B，15 个 `init_array`，2,627 导出，仅 `JNI_OnLoad`（→ `RegisterNatives`）。Java 桥：`face.security.device.api.FaceSecDevice`（`static { System.loadLibrary("facedevice"); }`）、`FaceSecSession`/`FaceSecToken`/`DeviceInfo`，上层 `com.dtf.face.security.SecurityExt.getDeviceToken()`（`UploadDeviceData` 上报，字段 `code`/`token`）。

检测名单（原文来自 `scan/security/native/facedevice_detection_strings.txt`，偏移 0x1b6000–0x1ba400）：

**Root/隐藏管理器包名**：`topjohnwu`、`me.weishu.kernelsu`(KernelSU)、`me.bmax.apatch`(APatch)、`io.github.huskydg.magisk`(Kitsune Mask)、`com.rifsxd.ksunext`(KernelSu-Next)、`com.sukisu.ultra`(Sukisu)、`me.garfieldhan.apatch.next`(APatch-Next)、`de.robv.android.xposed.installer`、`com.tsng.hidemyapplist`

**检测工具本身**：`icu.nullptr.nativetest`、`io.github.vvb2060.mahoshojo`(Momo)、`com.zhenxi.hunter`(Hunter)、`io.github.vvb2060.keyattestation`、`com.byxiaorun.detector`(Ruru)

**虚拟摄像头**：`com.xianyu.gaotong`、`virtual.camera.app`、`com.example.vcam`、`com.wangyiheng.vcamsx`、`com.telegram.a1064`、`com.pedia.vcamsx`、`com.paint.yssh`

**框架/注入库名**：`gmain`、`gum-js-loop`、`pool-frida`、`gdbus`、`zposed`、`frida-agent`、`substrate`、`libriru_edxp.so`、`libsandhook.edxp.so`、`libwhale.edxp.so`、`libxposed_art.so`、`edxp.jar`、`fasthook`、`libfakeloc_initzygote.so`、`sandhook`、`libsubstrate.so`、`libiohook.so`、`libepic.so`/`libepic64.so`、`libexp824.so`/`libexp82464.so`、`libexposed.so`、`liblspd.so`、`libriru.so`、`XposedBridge.jar`

**su / busybox / 隐藏路径**：`/system/bin/su`、`/system/xbin/su`、`/data/local/xbin/su`、`/data/local/bin/su`、`/data/local/tmp/su`、`/data/local/tmp/bin/su`、`/system/sd/xbin/su`、`/system/bin/failsafe/su`、`/data/local/su`、`/su/bin/su`、`/cache/su`、`/data/su`、`/dev/su`、`/vendor/bin/su`、`/system/bin/.ext/su`、`/system/usr/we-need-root/su`、`/system/xbin/ku.sud`、`/system/sbin/su`、`/debug_ramdisk/su`、`/data/adb/ksu`、`/data/adb/ksud`、`/debug_ramdisk/shamiko/module.prop`、`/system/lib64/libzygisk_loader.so`、`/system/lib64/libzygisk.so`、`/system/app/Kinguser.apk`、`/system/app/Superuser.apk`、`/system/etc/init.d/99SuperSUDaemon`、`/system/xbin/daemonsu`、`/dev/com.koushikdutta.superuser.daemon/` + 13 条 busybox 路径

**属性**：`ro.build.tags`、`ro.secure`、`ro.debuggable`、`ro.boot.flash.locked`、`ro.boot.vbmeta.device_state`、`ro.boot.verifiedbootstate`、`ro.boot.vbmeta.digest`、`sys.oem_unlock_allowed`、`ro.kernel.qemu`、`ro.adb.secure`、`dev_settings`、`development_settings_enabled`、`adb_enabled`、`persist.sys.vold_app_data_isolation_enabled`

**进程/内核侧**：`/proc/self/status`+`TracerPid:`、`/proc/self/maps`、`/proc/self/smaps`、`/proc/%d/maps`、`/proc/self/mountinfo`、`/proc/%d/attr/prev`、`/proc/%d/attr/current`、`/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/unix`、`/proc/self/task`、`/proc/self/mem`、`/proc/self/pagemap`、`/dev/__properties__/*`、`which su`、`mount`、`pm list packages -s`、`pm list packages -3`、`service list`、`syscall`、`popen`、`dl_iterate_phdr`〔导入〕

**栈完整性白名单**（反 Java 层 hook / 反反射）：`com.android.internal.os.ZygoteInit.main`、`RuntimeInit`、`java.lang.reflect.Method.invoke`、`ActivityThread.main`、`Looper.loop`、`Handler.dispatchMessage`、`HandlerThread.run`、`android.app.servertransaction`、`Instrumentation`、`Activity.performCreate`、`Activity.performStart`、`Handler.handleCallback`、`java.lang.Thread.run`
→〔推断〕把 `java.lang.reflect.Method.invoke` 与 `ActivityThread.main` 一起放进白名单，说明它做的是**栈形状匹配**（判断调用是否"像正常 UI 链"），Xposed/Frida Java hook 通常会让栈顶出现反射帧或缺失 `performCreate`。

**自检目标**：`com.alipay.zoloz.toyger.SgomInfoManager.updateSgomInfo`、`com.dtf.face.security.SecurityExt`

**模拟器**：Nox（`com.bignox.app.store.hd`、`com.bignox.google.installer`、`/system/bin/nox-prop`、`nox-vbox-sf`、`noxspeedup`）、MEmu/microvirt（`/system/bin/microvirt-prop`、`nemuVM-*`、`/sys/module/nemuguest|nemuvideo|nemuVM-prop`、`mumu.config`）、androVM（`/system/bin/androVM-*`）、BlueStacks（`/storage/emulated/0/Android/data/com.bluestacks.*`）、Houdini（`ro.dalvik.vm.native.bridge`、`libnb.so`、`libhoudini.so`、`libntb.so`）、`/sys/class/thermal`

### 3.5 `libsafechat.so` — 安恒消息/文件加密

〔观察〕3,698,232 B，1,193 导出，**未 strip**（`elf_info.json: has_symtab=true`，全 152 个库中唯一）。wolfSSL 完整符号（`AddCA`、`AllocDer`、`AllocKey`、`AllocateCtxSuites`、`BEGIN_CERT`/`BEGIN_PRIV_KEY`/`BEGIN_RSA_PRIV` 等 PEM 头常量）+ `Java_com_dbappsecurity_et_DIJni_*` 20 个 JNI 入口（`encryptMsg`/`decryptMsg`/`encryptFileHelper`/`decryptFileHelper`/`encryptKeys`/`encryptKeyData`/`encryptBufferHelper`/`decryptBufferHelper`/`setVoipKey`/`releaseVoipKey`/`getEncryptionAttributeHelper`/`domainName`/`stringFromJNI`）。
〔推断〕功能是**企业级消息与文件加密 + VoIP 密钥下发**，不是检测组件。`BEGIN_PRIV_KEY` 等常量是 wolfSSL 的 PEM 解析表，**不是**内置私钥（`scan/security/native/` 未发现可用 PEM 实体）。

### 3.6 `libdalvikhack.so` — DalvikUtils

〔观察〕10 KB；导出 `_ZN13DalvikRuntime{4Init,6Create,C1Ev,C2Ev,16addBootClassPath,14dvmJdwpStartup}E`、`instance_`、`JNI_OnLoad@0x1408`；`init_array = ['0x0']`。Java 侧 `com.taobao.android.runtime.DalvikUtils`（含 `DalvikUtils$ClassVerifyMode`、`DalvikUtils$DexOptMode`），被 `<PKG>` 引用；dex 字符串 `- DalvikUtils addBootClassPath: classPath=`。
〔推断〕能改 bootclasspath、改类校验模式、启 JDWP —— 在 ART-only、targetSdk 33 的设备上是**降级空路径**（`Create()` 找不到 dalvik 结构即退化）。但 `dvmJdwpStartup` 导出的存在意味着"可主动开 JDWP"是代码里的能力，属**可利用面**（若能调用，等于开一个调试端口）。本轮未找到调用点 → 记为〔未知〕。

### 3.7 `libcrashsdk.so` — 崩溃上报

〔观察〕656,152 B，17 个 `init_array`（+1 空槽），22 导出，`JNI_OnLoad`，`DT_NEEDED liblog/libz/libc/libdl`。
〔推断〕UC crashsdk 血统，纯上报。

### 3.8 `libzkfv_tj.so` — 本轮定性的"未知项"

〔观察〕
```
size=465880   ET_DYN aarch64   stripped(no .symtab)   exported=1
JNI_OnLoad @ 0x3ecc4
init_array = [0x14ce4, 0x1a7f0, 0x21c78, 0x270d8, 0x2ba98, 0x3104c, 0x1450c, 0x14540, 0x1458c, 0x145a4, 0x0]   # 10 个构造器
DT_NEEDED = liblog.so, libm.so, libstdc++.so, libdl.so, libc.so
```
- 全库 ASCII 串只有导入名与 C++ 运行时标记（`B~26`/`m~26`/`y~26` 等自定义链接器产物），**无任何业务字符串**。
- 导入里有 `dl_iterate_phdr`、`syscall`、`pthread_create`、`pthread_once`、`pthread_key_create`、`__android_log_print`、`memcmp`、`strcmp`。
- `JNI_OnLoad` 反汇编（`scan/security/native/disasm/zkfv_tj.dis`）：典型**控制流平坦化**——一个 `w20` 分发变量在 `0x42/0x51/0x55/0x35/0x37/0x3a/0x23/0x27/0x22…` 之间跳转，每个分支做 `ldrb w8,[x22,#0xNNN]` 取字节 + `add/and/cmp` 与常量比较（**逐字节比较的解密表**），并出现 `<unknown>`（数据被当指令）与 `sqdecw`/`bics` 之类的垃圾指令，末尾 `blr x8` 间接调用。
- 无 `Java_*` 导出 → 全部通过 `JNI_OnLoad` 里 `RegisterNatives` 注册。
- **Java 侧唯一入口**：`defpackage.lus`
  ```java
  public class lus { public static boolean a = false;
      public static void a() { if (a) return;
          try { System.loadLibrary("zkfv_tj"); a = true; }
          catch (UnsatisfiedLinkError e) { e.printStackTrace(); } } }
  ```
  调用点（全包仅 6 处，全部在人脸链）：`com.dtf.face.api.DTFacadeSec:50`、`com.dtf.face.utils.LogUtils:14`、`com.dtf.toyger.base.face.FaceBlobManagerJson:28`、`com.dtf.toyger.base.face.ToygerFaceService:341`、`faceverify.w:45`、`faceverify.y:17`。**Java 侧没有声明任何 native 方法**。

〔推断〕
1. **用途**：人脸/活体链的**加载期安全代理**——10 个构造器 + 平坦化 `JNI_OnLoad` 在 `System.loadLibrary` 那一刻就完成：模块枚举（`dl_iterate_phdr`）、直调内核（`syscall`，绕 libc 反 hook）、独立线程（`pthread_create`，周期性复查）、日志上报。名字里的 `tj` 与人脸链的 DT 定制一致（`dtf`=IMFace），`zkfv` 推断为「整体防护/风控校验」类内部代号。
2. **不是加壳器**：它不解析 dex、无 `libdexloader` 依赖、无 zip/elf 解析特征；对主业务无影响。
3. **对抗成本中等**：由于其行为发生在 `loadLibrary` 同步路径上，Frida 只需在 `lus.a()` 之前 hook（或直接 hook `System.loadLibrary` 过滤 `"zkfv_tj"`）即可整块跳过。

〔未知〕
- `RegisterNatives` 注册的类名/方法名：字符串被逐字节解密，需动态 dump（建议 `JNI_OnLoad` 返回前 hook `RegisterNatives`，或在 `JNIEnv->RegisterNatives` 处下断）。
- 10 个构造器的具体职能：需逐个人工逆向（0x14ce4/0x1a7f0/…/0x3104c 与 0x1450c/0x14540/0x1458c/0x145a4 两组，前者在 `.text` 深处、后者靠近 PLT，推断后者是 `__cxa_atexit` 注册）。

### 3.9 其它与"IP 栈 / 内存 / ANR"相关的 lib（排除误判）

`libipstack-detect.so`（`Java_com_laiwang_protocol_ipstack_IpStackDetectTool_detectLocalIpStack`）、`libipdetector.so`、`libmem-monitor.so`、`libanrcanarycompat.so`、`libperf.so`（`com.alipay.mobile.quinox.security.EncryptDataUtils.{encrypt,decrypt}`）、`libfulltrace.so`（`com.ali.ha.fulltrace.dump.DumpManager`）—— 均为**性能/IP 栈探测/日志**，不是安全检测。`libholmes.so`（2,922 导出，3 个 `init_array`）是 APM 引擎。

---

## 4. 反调试 / 反注入 / 反模拟器 / 多开：Java 侧证据表

〔观察〕对 30 个 dex 的完整字符串表做关键词匹配（`scan/security/string_hits.txt`），Java 侧"反调试"相关实现点只有以下这些，**没有一个会终止进程**：

| 类 / 方法 | 检测内容 | 触发后行为 | 影响面 |
|---|---|---|---|
| `com.mobile.auth.gatewayauth.manager.SystemManager.checkEnvSafe()`（`@SafeProtector`） | root（`CheckRoot.isDeviceRooted()`）→ 模拟器（`EmulatorDetector.isEmulator()`，仅主线程）→ 代理（`CheckProxy.isDevicedProxy()`）→ `Debug.isDebuggerConnected()` | 返回 `-10003` + 中文错误串，**中断一键登录/号码认证** | 仅号码认证业务 |
| `com.mobile.auth.gatewayauth.utils.security.CheckHook.isHookByJar()` | 读 `/proc/<pid>/maps`，匹配 `.so`/`.jar` 行末尾路径含 `XposedBridge.jar` / `Xposed` / `xposed` / `xposed_art` | 置 `1` + 打日志 `HookDetection, Xposed JAR found: …` | 号码认证 |
| `CheckHook.isHookByStack()` | 抛异常取栈：`ZygoteInit` 出现 2 次 / `XposedBridge.main` / `XposedBridge.handleHookedMethod` | 置 `1` + 3 条日志 | 号码认证 |
| `com.alipay.edge.utils.FindHook` | `Class.forName("com.saurik.substrate.MS$2")`、`de.robv.android.xposed.XposedBridge` | 打日志 `findHook …` | 阿里边缘计算 SDK |
| `com.alibaba.doraemon.impl.eventbus.EventButlerImpl.isDebuggerConnected()` | `Doraemon.getRunningMode()==1 && Debug.isDebuggerConnected()` | 跳过 EventBus 代理封装（调试友好） | Doraemon |
| `defpackage.i.F()` | `E() && (Debug.isDebuggerConnected() \|\| Debug.waitingForDebugger())` | 供 ANRCanary 标记 `RunningTaskInfo.debugging`、跳过 ANR 判定 | ANR 监控 |
| `defpackage.ck0`（ApmDebugMonitor） | `Debug.isDebuggerConnected()` | 抑制"页面打开时间>1s"上报 | APM |
| `com.alibaba.wukong.sync.impl.SyncMergeAck:304` | `Debug.isDebuggerConnected()` | 抑制日志 | IM 同步 |
| `com.alipay.mobile.quinox.startup.StartupSafeguard:198/1506` | `Debug.isDebuggerConnected()` | 跳过启动保护等待（避免调试卡死） | 启动器 |
| `com.alipay.alipaysecuritysdk.modules.x.b:96` | 反射注册 `Debug.isDebuggerConnected` 到检测项表（id=33） | 计入安全 SDK 风控采集 | 支付安全 SDK |

**关键否证**：
- `TracerPid` 在 **30 个 dex 里 0 命中** → Java 层没有读 `/proc/self/status` 的反调试。
- `/proc/self/maps` 在 Java 层只有 2 处：`com.taobao.weex.WXEnvironment`、`com.uc.crashsdk.e`（都是信息采集）。
- 没有"包名黑名单"式的 Java 检测表（除 `libfacedevice` 的 native 名单）。
- `Debug.isDebuggerConnected` 的 9 处调用者，没有一处调用 `System.exit` / `Process.killProcess` / `finishAffinity`。

**唯一会"杀进程"的路径不在安全逻辑里**：
〔观察〕`<PKG>(Activity)`（所有 exported Activity 的 `onCreate` 第一行）：
- 32/64 位安装错配 → 跳 `MisinstallActivity` + `System.exit(0)`
- 隐私政策未同意 → 跳 `PrivacyPolicyActivity` + `System.exit(0)`
- 预加载标记 → 跳 `PreloadActivity` + `System.exit(0)`
- 特例：`intent.data.path == "/action/auth_login"` 额外透传 `source_data`

→ 这是**所有 exported 组件的公共启动闸**，性质是隐私合规闸，不是鉴权闸（见 §7）。

### 4.1 多开检测

〔观察〕dex 中"多开"只有 2 个字符串：`", enableMultiApp "`、`"startMultiApp"`（classes19、classes22），未找到包名黑名单、`/proc/<pid>/cmdline` 比对或 `android:sharedUserId` 探测。native 侧 `libfacedevice` 也没有多开名单。
〔推断〕"多开"在本包**没有实质检测实现**，最多是埋点参数。多开环境下的失败更可能来自 `libfacedevice` 的通用 root/注入判定。

---

## 5. 抓包对抗：能不能抓、怎么抓、抓不到的原因

### 5.1 Network Security Config（发布态已复核）

〔观察〕对 `target.apk` 内 `res/xml/network_security_config.xml` 直接 `aapt2 dump xmltree`：

```
E: network-security-config
  E: base-config
    A: cleartextTrafficPermitted=true
      E: trust-anchors
          E: certificates  A: src="system"
          E: certificates  A: src="user"
```

- **无 `<domain-config>`、无 `<debug-overrides>`、无 `<pin-set>`**。
- Manifest：`android:usesCleartextTraffic=true`、`android:networkSecurityConfig=@0x7f150014`、`android:allowBackup=false`、`android:requestLegacyExternalStorage=true`；`targetSdkVersion=33`。
- 〔观察〕NSC 的 `user` anchor 对 **targetSdk ≥ 24** 才是"额外信任用户 CA"；这里显式声明，且在 release（非 `debug-overrides`）下生效 → **平台 TLS 栈的 user CA 注入确实可用**。

### 5.2 TLS 栈分层（决定性）

〔观察〕`DT_NEEDED` 关系（`scan/security/native/elf_info.json`）：

```
libgaea.so          -> liblog, libandroid, libz, libdmojo_support, libc, liblsquic, libm, libdl
libgaealwp_jni.so   -> libc, libgaea, liblsquic, libdmojo_support, libm, libdl
libgaeahttp_jni.so  -> libc, libgaea, liblsquic, libdmojo_support, libm, libdl
liblsquic.so        -> libz, libm, libdl, libc            <-- 无任何 libssl/libcrypto
libBifrost.so       -> libc++_shared, liblog, libz, libc, libm, libdl
libXcdnEngine.so    -> liblog, libandroid, libm, libc++_shared, libdl, libc
libtnet-4.0.0.so    -> libzstd, libz, liblog, libc, libm, libdl
```

- `liblsquic.so` **不依赖任何外部 TLS 库** → TLS/crypto 静态内嵌在 lsquic（BoringSSL 风格的内嵌构建）。
- 独立 TLS 是 `libssl-dd.so`（499 个 `SSL_*`/`TLS_*` 导出，符号版本 `OPENSSL_1_1_0`；含 `SSL_CTX_set_verify`、`SSL_get_verify_result`、`X509_verify_cert`，**无 `SSL_CTX_set_custom_verify`** → 是 **OpenSSL 1.1.0 而非 BoringSSL**，阿里内部构建），`DT_NEEDED` 引用者仅：`libbarcodessl.so`、`libencrypt_algorithm.so`、`libsafeguard.so`、`libssl-dd.so→libcrypto-dd.so`。
- **结论〔推断，但依据是链接关系而非猜测〕**：MTOP / ANet / Gaea（HTTP/2、QUIC）/ LWS 长连接走的是 **native 内嵌 TLS**，不经过 `javax.net.ssl`、不查 `NetworkSecurityPolicy`、不读 `networkSecurityConfig`。→ **把用户 CA 装进系统 store 对主通道无效**。

### 5.3 pinning

〔观察〕
- OkHttp3 的 `CertificatePinner` 以 `defpackage.w33` 存在，`w33.c = new a().a()`（空 builder）。**但该类被裁得只剩骨架**：公开 API 只有 `w33(Set<b>, v33)`、`static c(Certificate)`、`static d(X509Certificate)`、`static e(X509Certificate)`，以及内部 `a`（Builder）与 `b`（含 `b.a(String)` 域匹配）。**没有 `check(host, chain)` / `check$okhttp(...)` 校验入口** → 即使有人往里塞 pin 也无处执行。
- `com.squareup.okhttp.CertificatePinner.DEFAULT = new Builder().build()`（OkHttp2 侧同样为空集）。
- 全包无任何 `CertificatePinner.add(host, "sha256/…")` / `pin-set` / `sha256/` 配置；`NetworkSecurityPolicy` 唯一使用点是 `defpackage.ag0:305`，用途是**查 cleartext 是否允许**，不是 pin。

**结论**：应用层**没有 pinning**，且 pin 校验器本身已被裁空（双重证明）。难点从来不是 pin，而是 §5.2 的"通道不走平台 TLS"。

### 5.4 与本包自带的"TrustAll"路径的关系

〔观察〕
- `com.alibaba.doraemon.impl.request.http.certs.HttpsTrustAllCertsTrustManager`（空校验），被 `doraemon.impl.request.http.okhttp.{OkHttpClientFetcher, OkHttpNetwork, SmartSpeedNetwork}` 使用 → 仅限 **Doraemon 自己的 HTTP artifact**（TRACE/Holmes/性能数据）。

  **启用条件**：只有当 `Doraemon.getRunningMode()` 使对应 artifact 加载、且走 `SmartSpeedNetwork` 分支时才会被装配；`getRunningMode()` 在 release 恒为 4 → 该路径一般不启用，但 `OkHttpClientFetcher` 在 artifact 被 `Doraemon.getArtifact("TRACE")` 拉取时仍会构造 client。〔未知：需动态确认 release 下 TRACE artifact 是否加载〕

- `com.alipay.mobile.common.transport.ssl.EmptyX509TrustManagerWrapper`（`checkServerTrusted` 空实现）+ `X509TrustManagerFactory.setX509TrustManager()`（可被任意代码替换单例）→ 只要有人调 `setX509TrustManager(new EmptyX509TrustManagerWrapper())`，**ANet 的 Java 层 TLS 就变成不校验**。本轮未找到该调用点〔未知〕，但**这是全局最省的抓包突破口**：hook `X509TrustManagerFactory.getX509TrustManager()` 返回空实现即可覆盖所有走 ANet 的 Java 请求。

### 5.5 MTOP 签名与设备指纹

〔观察〕
- appkey `21811227`（dex 字符串）；`MtopSign`/`getMtopSign` 出现在 `classes21.dex`（号码认证 SDK 侧）。
- 设备指纹链路：`utdid` / `umid`（`IUMIDComponent`，由 SecurityGuard 提供）→ `umidToken` 进 `AntiStrategyHandler._umidToken`；`deviceId` 由 `classes.dex`「hostAuth deviceId」与 `GaeaAppInfo{deviceId=…}` 等模型携带；`securityId` 亦在字符串表内。
- 签名/安全体由 `libsgsecuritybodyso`（`ISecurityBodyComponent`、`SecurityBodyDefine`、`ISecurityBodyPageTrack`）提供，`wua` 参数由 SecurityGuard 产出。

〔推断〕MTOP 的 `sign` 是 `SecurityGuard(securitybody wua) + appkey + t + 设备指纹` 组合，**服务端可验**；因此：
- 即使实现完美 MITM，**改包体会导致 `sign` 失效 → 业务报非法请求**；
- 只读观察（不改 body）在通过 TLS 后是可行的。

〔未知〕`sign` 的具体拼接与算法在 SecurityGuard native 内（`ISecurityBodyComponent.getSecurityBodyData`），未逆；这属于 analysis/05 的范围，此处只给结论：**签名可被"透传"绕过（不改包），不可被"伪造"绕过**。

### 5.6 QUIC / 其它网络栈

〔观察〕`liblsquic.so`（4.53 MB）+ `libxquic.so`（1.30 MB）+ `libgaea.so`（9.21 MB）+ `libBifrost.so`（3.11 MB）+ `libXcdnEngine.so`（3.29 MB）+ `libquic_jni.so` / `libgaeadns_jni.so` / `libGaeaConfigJni.so`。
〔推断〕Gaea 有 QUIC（lsquic）与 HTTP/2 双栈，QUIC 可自动降级到 TCP/TLS；**抓包时若客户端走 QUIC(UDP 443)，传统 HTTP 代理无效**，必须 UDP 阻断/重定向，让它退化到 TCP，或做 UDP 层 transparent proxy。

### 5.7 抓包结论（可执行）

| 目标 | 能否抓到 | 方法 | 抓不到的原因 |
|---|---|---|---|
| WebView / H5 / 第三方 SDK / 广告 / 部分 OpenAPI（平台 TLS） | **能** | 用户 CA 装进系统 store（NSC 已放行，无需改包）；或用 `objection`/Frida hook `X509TrustManager` 双保险 | 只在用了 `javax.net.ssl` 的平台栈上成立 |
| ANet 的 Java 层请求 | **大概率能** | hook `com.alipay.mobile.common.transport.ssl.X509TrustManagerFactory.getX509TrustManager()` → 返回空 TM；或 hook `SSLContext.init` / `X509TrustManager.checkServerTrusted` | 若走 native securitybody 直连则无效〔未知〕 |
| MTOP / Gaea / LWS（长连接）/ QUIC 主通道 | **不能靠证书** | ① `uprobe`/`frida` hook `SSL_read`/`SSL_write`（`libssl-dd.so` 内的 OpenSSL 1.1.0 符号）；② 若走 lsquic 内嵌 TLS，hook `liblsquic.so` 的读写入口（需先定位符号，无 .dynsym 导出符号 → 靠字符串/`ssl_read` 调用点定位）；③ 最实用：**上游路由 + 透明代理 + UDP 阻断逼降级 TCP**，再在 Gaea 的 Java 层（`GaeaProxy`/`SessionCenter`）hook 明文 | 内嵌 TLS 不经平台 TrustManager；且 `sign`/`wua` 由 native 生成，改包即被服务端识破 |
| 人脸/刷脸链路 | **不建议** | `libfacedevice` + `libzkfv_tj` 会查 `/proc/net/*`、`http_proxy`、本机监听端口、注入库名；被判定后不是断网而是**上报 + 业务拒绝** | 本机代理端口会被点名 |

**推荐组合**（按性价比）：
1. **优先**：`frida -U -f <pkg> -l ssl_bypass.js --no-pause`，hook 三处 —— `X509TrustManagerFactory.getX509TrustManager`、`okhttp3/w33` 的 `check`、`SSLContext.init`；观察哪些流量解密了 → 未解密的即 native 通道。
2. native 通道：`frida` 在 `dlopen` 后对 `libssl-dd.so` 做 `Module.findExportByName("libssl-dd.so","SSL_read")` → `Interceptor.attach`；对 lsquic 用 `Memory.scan` 找 `SSL_read` 调用点（因为 lsquic 静态链接，符号可能仍在 `.symtab`）。
3. 网络层兜底：虚拟机/上游网关做 UDP 443 阻断 + TCP 透明代理；DNS 走 `libgaeadns` 会绕系统 resolver，需在网关侧劫持。
4. **不要**在本机起 8080/8888 监听：`libfacedevice` 读 `/proc/net/tcp{,6}` + `127.0.0.1` + `http_proxy`。

---

## 6. 开发者能力门控闭合（上次遗留 6 项，全部闭合）

### 6.1 `ywm.a()` 的写入方 → **不存在；只能由 Surgeon 覆盖**

〔观察〕`defpackage/ywm.java`（classes8.dex）全文：
```java
public class ywm {
    public static boolean f69400a = false;                       // 唯一"值"
    public static boolean a() {
        ISurgeon s = $surgeonFlag;
        return InstrumentAPI.support(s, "1669440712")
             ? ((Boolean) s.surgeon$dispatch("1669440712", new Object[0])).booleanValue()
             : f69400a;
    }
}
```
- 全包 grep `f69400a` → **只有 2 处：声明与读取，零写入**。
- `$surgeonFlag` 在 release 恒 `null` → `InstrumentAPI.support` 恒 `false` → `a()` **恒等于 `false`**。
- 调用方仅 3 处：
  - `CommonSettingActivity:1875` `findViewById(d9k.settings_develop).setVisibility(ywm.a() ? 0 : 8)` → "开发者选项"入口 **GONE**。
  - `CommonSettingActivity:1729` `if (ywm.a()) { … }`
  - `DeveloperOptionsActivity:129` `if (ywm.a()) { … }`

**闭合结论**：想打开开发者入口，**改 SP / 改 prop / 换 debug 包都不行**；唯一路径是让 `com.alibaba.surgeon.instrument.InstrumentAPI.support()` 返回 true，即提供一个非空 `ISurgeon` 且 `surgeon$support("1669440712")` 为 true。这意味着 Surgeon 仪器化包必须与该 APK **同签名**才有意义（`ISurgeon` 由谁注入、如何校验签名属〔未知〕，但 `Surgeon` 类存在：`sources/com/alibaba/surgeon/Surgeon.java`、`bridge/ISurgeon.java`、`bridge/Protocol.java`）〔推断〕。

### 6.2 `Doraemon.getRunningMode()` 的初始化 / 设置点 → **只能 1→2，永不能 4→1/2**

〔观察〕`com.alibaba.doraemon.Doraemon`（classes14.dex）：
```java
public static final int MODE_DEBUG = 1; MODE_GRAY = 2; MODE_RELEASE = 4;
private static int sMode = 4;                                   // 初值 = RELEASE
public static int getRunningMode() { … : sMode; }               // Surgeon id -1919346692
public static void setRunningMode(int i) { … if (validateMode(i)) sMode = i; }  // id 1549858190
public static void setDebugMode(boolean z) { … z ? 1 : 4 }      // id 787505523
private static boolean validateMode(int i) { return i == 1 || i == 2 || i == 4; }
public static synchronized void init(Context c) { … }           // 只填 sContext/sMetaDataMap
```
- 全包 `setRunningMode` / `setDebugMode` 的**唯一相关调用点**：
  - `defpackage/f6.java:489`（`initVoiceTranscriber` 内）：`if (Doraemon.getRunningMode() == 1) Doraemon.setRunningMode(2);`
  - `com/alibaba/lightapp/runtime/view/AIBallPublisherHelper.java:195`：同样形式。
  - 其余 `setDebugMode` 命中全是 WPS/KStat、`com.laiwang.protocol.android.LWP:568`、`com.youku.upsplayer.util.Logger` 等**同名不相关 API**。
- 全包 `Doraemon.init(...)` 调用点 10 处（`wukong/auth/h`、`defpackage/{vui,ncr,yq7}`、`H5AppManagerImpl`、`CameraActivity` …），**init 不改 sMode**（`sMode` 的赋值只在 `setRunningMode`/`setDebugMode`）。

**闭合结论**：release 下 `sMode` 永远是 4。`"if mode==1 then set 2"` 只能把 DEBUG 降成 GRAY，**没有任何代码把 4 提升为 1/2**。所有"`mode==1||mode==2` 才生效"的能力（DevSetting、WebView 调试、`abg.b()`、`q01.e()`、`DevSettingActivity.L()`）在发布包中**结构性不可达**，仅 Surgeon `1549858190` 能改。

### 6.3 服务端 dev_setting 读取点 → 三个键，其中两个默认不成立

〔观察〕
| 读取点 | 表达式 | 默认/可达性 |
|---|---|---|
| `AboutActivity:127`、`DevSettingActivity:1884` | `getRunningMode()==1 \|\| ContactInterface.v1().y0("dev_setting") \|\| (getRunningMode()==2 && E())` | `mode` 恒 4 → 前/后项 false；只剩 `y0("dev_setting")` |
| `ContactInterfaceImpl:11166` → `j35.k().e("dev_setting")` → `j35.h(str,false)` | `if ((mode==1\|\|mode==2) && n()) return true;` 否则查本地 map（服务端下发） | `mode` 恒 4 → 跳过快捷 true；**查询本地 map：未下发时走 `j35.p(str)` 触发 RPC，默认返回 `false`** |
| `AboutActivity:794` | `ContactInterface.v1().e1()==0 \|\| GaeaConfigInterface.q().m("general","dev_setting_for_gray_android",false)` | `e1()` → `DevSettingActivity.v1`，初值 **2** → `2==0` 恒 false；**只剩 Gaea 键，默认 false** |

- `DevSettingActivity.v1` 声明：`public static int v1 = 2;`（第 154 行）；写入点：`L()` 里 `v1 = sp.getInt("DevSettingActivity_ENV", v1)`、`Y()` 里 `v1 = xn5.j(k1.get(i2),2)` —— **两者都在 `mode ∈ {1,2}` 门控内**。
- 门控失败行为〔观察〕：`DevSettingActivity.onCreate` else 分支
  ```java
  paf.a().postDelayed(new h(), 1000L);   // class h: run() -> DevSettingActivity.this.finish()
  ```
  → **1 秒后静默 `finish()`，不设 contentView、无提示**。

**闭合结论**：`dev_setting` 是**服务端按用户/企业下发**的布尔；客户端没有任何本地开关能伪造它（`j35` 的 map 来自 LWP RPC，`f50016a` 是 `Map<String,Boolean>` 内存缓存）。Gaea 键 `general.dev_setting_for_gray_android` 同理（Gaea 配置由服务端下发并签名）。

### 6.4 `WebView.setWebContentsDebuggingEnabled` 全链路

〔观察〕两条独立链：

**链 A（IM自有，门控最严）**
```
SP "DevSettingActivity_WEBVIEW_DEBUG"      ← 只在 DevSettingActivity.L() 读，L() 只在 mode∈{1,2} 执行
        ↓ 写入 xz6.f68320a
defpackage.abg.b():
    if (Doraemon.getRunningMode() != 1 && != 2) return false;       // 第一道闸
    if (sp.getBoolean("DevSettingActivity_WEBVIEW_DEBUG", false)) return true;
    return gko.d0("ga_7100x_js_debug_android");                     // 第二道：Gaea 服务端键
        ↓ 消费
CommonNXBridge:42 / BridgeAccessExtension:109 / defpackage.x5g:701   // 均为 JSAPI 调试面板桥
```
`xz6`（classes30.dex）是纯静态开关池：`f68320a`(WEBVIEW_DEBUG)、`b`(HPM_DEBUG)、`c`(WEBVIEW_NO_HPM)、`d`(DISABLE_PERF_WINDOW，默认 **true**)、`e`(USE_SYSTEM_CORE)、`f`(DISABLE_UC_PROXY)、`g`(DISABLE_UC_PRELOAD)、`h/i/j/k`(int)；全部只在 `L()` 里被灌值。

**链 B（各业务模块自己开，无门控）**
〔观察〕硬编码 `setWebContentsDebuggingEnabled(true)` 的位置：
- 邮件模块：`MailWebViewWrapper`/`AndroidWebView`/`UcWebView` 的包装、`MailLoginSecondVerifySMSActivity:687`、`MailMeetingDetailActivity:611`、`CMailBaseSignTmpListAdapter:132`、`MailSignListAdapter:625`、`MailSignListAdapterV6:655`、`MailDetailFragment:4146`、`MailDetailV6Fragment:4322`、`RichEditor:895`
- 文档：`BaseEditorToolBarPopupActivity:65/69` `WebView.setWebContentsDebuggingEnabled(zU)`
- 阿里用户 SDK：`BaseWebViewActivity:70` `WebView.setWebContentsDebuggingEnabled(SDKLogger.isDebugEnabled())`

〔推断〕**链 B 是更现实的 WebView 调试入口**：邮件签名/正文预览、文档编辑器页面会被无条件打开 WebView 远程调试；`chrome://inspect` 在 root/`adb` 环境下可直接 attach 这些 WebView。这与"调试模式开关"无关，属**产品代码遗留**。

### 6.5 `DevSettingActivity` 环境切换副作用（endpoint 覆盖键全集）

〔观察〕**静态字段即 endpoint 表**（classes8.dex，第 135–190 行）：

| 字段 | 默认值 | SP 键 | 被 `Y()` 覆盖为 |
|---|---|---|---|
| `o1` | `""` | `DevSettingActivity_LWS_URL` | 各环境 LWS 长连接 URL |
| `p1` | `""` | `DevSettingActivity_LWS_SHORT_URL` | 短连接 URL |
| `q1` | `""` | `DevSettingActivity_LWS_QUIC_URL` | QUIC URL |
| `r1` | `https://login.<host>` | `DevSettingActivity_OAUTH_URL` | OAuth URL |
| `s1` | `null` | `DevSettingActivity_ALADDIN_URL` | 由 `U()`：`v1==1 → https://pre-resolver.<host>`；`v1==2 → https://resolver.<host>`；else `null` |
| `t1` | `https://static.<host>/media/` | `DevSettingActivity_MEDIA_ID_DOMAIN` | 媒体域 |
| `u1` | `https://repay.<host>/RENotify/notify_mobile_securitypay_pay` | `DevSettingActivity_ALIPAY_CALLBACK` | 支付回调 |
| `w1`/`x1`/`y1`/`z1`/`A1` | `https://t.<host>/…`、`https://h5.<host>/…` | `DevSettingActivity_TEAM_DATA_URL` | 团队主页 |
| `B1`..`G1` | `https://alimei-*.alibaba.com`、`https://preview.<host>`、`space` referer | `DevSettingActivity_MAIL_URL_{API,FILE,AUTH,PREVIEW,SPACE_PREVIEW,DENTRY}`、`MAIL_APP_NAME`、`MAIL_APP_KEY` | 邮箱域 |
| `H1` | `https://mailsso.mxhichina.com` | `DevSettingActivity_MAIL_URL_H5SSO` | 邮箱 SSO |
| `I1`/`J1` | `dingding_android` / `jepjyUnozbFsmRlMGRCr` | 同上 | 邮箱 appkey |
| `K1` | `""` | `DevSettingActivity_LWP_SCM_PROJECT_NAME` | SCM 工程名（`testing-trunk` 特判） |
| `v1` | `2` | `DevSettingActivity_ENV` | 环境索引（0=日常/1=预发/2=线上…） |

副作用链（都在 `mode∈{1,2}` 内）：
- `L(Context)`：读全部 SP → 赋值 → `xz6.a(v1)`、`U()`、`O()`（`MailInterface.H0/G0` 重设邮箱域）、`SpaceInterface.B0().c3(G1,F1)`、`z()`、`T()`。
- `T()`：`v1==2 → AlipayInterface.f().setAPSecurityEnv(0)`，否则 `setAPSecurityEnv(1)` —— **会切换支付安全环境的线上/测试**。
- `Y(Context,int)`：直接改上表 + `AlipayInterface.f().j(v1)` + `B(context)`（重启相关服务）。
- 入口 `I(Context)`：`if (mode==1||mode==2) startActivity(DevSettingActivity)` → **连"打开页面"都门控**。
- 唯一调用 `L()` 的地方：`ContactInterfaceImpl:5398` 的 `G3(Context)`，而 `G3` 由启动任务 `defpackage/jmm.d(LaunchContext)` 调用（`jmm` 依赖 `UserTrackTask`/`IMFrameworkTask`，`main` 进程）→ **每次冷启动时执行一次，但内部 mode 判定恒不满足 → 直接 return**。

〔推断〕这是"**一处改域、全局生效**"的测试基建：一旦 `mode` 被提到 1/2，改 `DevSettingActivity_ENV` 就能把 LWS/QUIC/OAuth/媒体/邮箱/支付安全全套指向预发或日常。反过来说，**release 下这整套是死的**。

### 6.6 `HttpsTrustAllCertsTrustManager` 启用条件

〔观察〕`com.alibaba.doraemon.impl.request.http.certs.HttpsTrustAllCertsTrustManager`（`checkServerTrusted` 空实现），使用方：`doraemon.impl.request.http.okhttp.{OkHttpClientFetcher, OkHttpNetwork, SmartSpeedNetwork}`。
〔推断〕启用条件 = **走 Doraemon 的 HTTP artifact**（`Doraemon.getArtifact("TRACE"/"TRACE2")` → `DoraemonConstants.HOLMES_ARTIFACT` → `ArtifactFetcher` → 构造 OkHttp client）。它服务于 TRACE/Holmes APM 的自建上报通道，**不覆盖 MTOP**。另一个同类：`com.alipay.mobile.common.transport.ssl.EmptyX509TrustManagerWrapper` + 可替换单例 `X509TrustManagerFactory.setX509TrustManager()`（见 §5.4）。
〔未知〕release 下 TRACE artifact 是否真的被 `getArtifact` 拉取并装配 —— 需在 `Doraemon.getArtifact` 下断点确认。

---

## 7. 攻击面复核：exported 组件的真实鉴权强度

〔观察〕`AndroidManifest.xml` 解析：**1,252 个组件，79 个 `exported=true`**（`scan/security/components.json`、`manifest_tree.txt`）。逐个复核后：

### 7.1 `owt.conference.debugger.TracingBroadcastReceiver` — **无鉴权，可被任意 App 触发（本轮最高实际风险）**

〔观察〕Manifest：
```xml
<receiver android:name="owt.conference.debugger.TracingBroadcastReceiver" android:exported="true"/>
<receiver android:name="owt.conference.debugger.TracingBroadcastReceiverMcsProcess"
          android:exported="true" android:process=":mcs"/>
```
无 `android:permission`。实现（classes24.dex，`owt.conference.debugger.TracingBroadcastReceiver`）：
```java
public void onReceive(Context ctx, Intent it) {
    OwtLog.i("TracingBroadcastReceiver", "receive action: " + it.getAction());
    if ("imclient.mcs.start_tracing".equals(it.getAction()))
        Debug.startMethodTracing(new File(ctx.getExternalFilesDir("mcs"), "mcs_trace").getAbsolutePath());
    else if ("imclient.mcs.stop_tracing".equals(it.getAction()))
        Debug.stopMethodTracing();
}
```
〔推断〕**任意第三方 App 只需一行**：
```java
sendBroadcast(new Intent("imclient.mcs.start_tracing"));  // 或 "imclient.mcs.stop_tracing"
```
即可让IM主进程（以及 `:mcs` 进程变体）开始/停止方法级 tracing。可获得/造成：
1. **DoS / 性能塌陷**：`startMethodTracing` 对全进程所有方法插桩，开销可达数十倍；重复 start 或 start/stop 抖动可让 App 明显卡死/ANR。
2. **信息泄露**：`/sdcard/Android/data/<PKG>/files/mcs/mcs_trace` 是**未加密的 `.trace`（方法名+类名+时序）**；`targetSdk 33` 下其他 App 不能直读该路径，但 **adb / root / file-manager（All-Files）/ MDM / 备份** 均可取出，等于把内部类结构与方法调用时序交出去。
3. 不含隐私数据（无参数、无字符串内容），因此**信息泄露等级中等，DoS 等级高**。

〔未知〕`Debug.startMethodTracing` 在已 start 状态下再 start 的行为（AOSP 是写新文件覆盖）；未动态验证是否可连续触发。

### 7.2 `ExternalProvider` — **read 权限是 `normal`，任意 App 可读（含登录态预言机）**

〔观察〕Manifest：
```xml
<provider android:name="<PKG>"
          android:authorities="<PKG>"
          android:exported="true"
          android:readPermission="<PKG>"
          android:writePermission="<PKG>"
          android:grantUriPermissions="false"/>
```
权限定义（同一 manifest）：
| 权限 | protectionLevel | 实际含义 |
|---|---|---|
| `…permission.external.provider.READ` | **`0x00000000` = normal** | **任意 App 在清单里声明即自动授予** |
| `…permission.external.provider.WRITE` | `0x00000002` = signature | 仅同签名可用 |
| `…permission.PUSH_PROVIDER` / `PUSH_WRITE_PROVIDER` / `PROCESS_PUSH_MSG` | `0x00000002` = signature | 仅同签名/系统 |
| `…permission.MIPUSH_RECEIVE` | `0x00000002` = signature | 同上 |

实现（classes4.dex，`ExternalProvider`）：
```java
query(uri, ...):
  if (!eb9.a().b("f_base_external_provider_enabled")   // 云控开关
      || !mj7.g().c().isLogin()                        // 必须已登录
      || !"/oa".equals(String.valueOf(uri.getPath())))  // 只认 /oa
      return null;
  boolean hasAttend      = a(158L);      // 微应用 appId 158 是否在本组织启用
  boolean hasAttendance  = a(-8L);       // 微应用 appId -8
  return MatrixCursor{"hasAttend","hasAttendance"} → {hasAttend?1:0, hasAttendance?1:0};
insert/update/delete/getType → 恒 null / 0
onCreate → 仅 setLifecycleCallbacks
```
〔观察〕`eb9.b(str)` = `c(str, true)` → **云控键缺失时默认 `true`**（`eb9.c` 里 `if (TextUtils.isEmpty(strI)) return z;`，`z=true`）。

〔推断〕**任意第三方 App 可做**：
```java
// App A 的 AndroidManifest 里声明
<uses-permission android:name="<PKG>"/>
// 运行时代码
Cursor c = getContentResolver().query(
    Uri.parse("content://<PKG>/oa"),
    null, null, null, null);
```
可得：① **该用户是否已登录IM**（cursor 有行 vs null）；② **该用户所属组织是否开通"考勤/审批"类微应用**（两个 0/1）。
不能得：通讯录、消息、文件、token。`grantUriPermissions=false` 且无 `openFile` 实现 → 无文件面。
→ 定性：**低危信息泄露 + 登录态预言机**（可用于社工前置判断/指纹识别），非数据面突破。

### 7.3 `Bokui*` 系列 — 已被隐私闸 + Doraemon 门控双重拦截

〔观察〕4 个 exported、无 permission 的 Activity：`BokuiActivity`、`BokuiFullScreenActivity`、`BokuiTransferActivity`、`BokuiRouterActivity`（均 `launchMode=1`、`screenOrientation=3`、`configChanges=0xda0`；`BokuiTransferActivity` 另有 `taskAffinity=…BokuiExternalActivity`）。共同启动闸：`attachBaseContext → ExportedActivityUtils.b(...)`、`onCreate` → `ExportedActivityUtils.a(this)`：
- 32/64 位装错 → `MisinstallActivity` + `System.exit(0)`
- 隐私政策未同意 → `PrivacyPolicyActivity` + `System.exit(0)`
- 预加载标记 → `PreloadActivity` + `System.exit(0)`
- `/action/auth_login` 特例透传 `source_data`（用于退出/换号后回跳）

`BokuiActivity.onCreate` → `s(intent)` / `p(intent)` / `o(intent,true)`，异常时 `if (Doraemon.getRunningMode()==1) throw; else finish();` → **release 下任何异常都是 `finish()` 兜底，不崩不泄露**。

**唯一的"凭据来自 Intent"路径（`p(Intent)`）三重门控，release 不可达**：
```java
public final void p(Intent intent) {
    if (intent == null                       // ① 要有 intent
        || TesterInterface.a().b(this,intent) // ② 内测判定：实现体 return false（恒通过）
        || !q01.e()                           // ③ 关键闸
        || (data = intent.getData()) == null
        || !f0d.f44718a.equals(data.getPath())) return;   // ④ path 必须 == "/ding/home.html"
    String phone = j0d.h(intent,"phone"), pwd = j0d.h(intent,"password");
    if (isEmpty(phone) || isEmpty(pwd)) return;
    String outerId = …当前账号 outerId…;
    if (!isEmpty(outerId) && !outerId.equals(phone)) LoginUtils.z(this,null);  // 登出当前账号
    q01.h(phone, pwd);                        // 写入静态 Account，供自动登录使用
}
```
- ③ `q01.e()`（classes4.dex）：`"autokey008".equals(l1r.d(ctx)) && (2 == Doraemon.getRunningMode() || 1 == Doraemon.getRunningMode())`
  → **要求 Doraemon mode 1/2**，且要求一个名为 `autokey008` 的**测试账号配置文件**存在。`q01` 全貌是 autokey 自动登录框架：`autokey007/008/010/101` → `monkey_account_for_icbu.txt` 等测试账号文件；`f()` 需 `mode==2` 且 autokey ∈ {007,010,101}。
- ④ `f0d.f44718a = h1c.b()` = `"/ding/home.html"`（非 EasyGo）或 `"/ding/home_easygo.html"`。

**结论**：这是**内测自动登录框架**的入口，release 下 `q01.e()` 恒 false → 整段死代码；第三方 App 无法借此注入账号。即便通过 Surgeon 打开 mode，也还需要 `autokey008` 配置文件。

### 7.4 `com.huawei.hms.support.api.push.PushProvider` — 签名级，第三方不可用

〔观察〕`authorities="<PKG>"`、`readPermission=…PUSH_PROVIDER`、`writePermission=…PUSH_WRITE_PROVIDER`，两者 `protectionLevel=0x2 (signature)`。
〔推断〕只有同签名（HMS 侧预置的同签证书）或系统可访问；普通 App 无法读写。dex 侧仅 `use sdk PushProvider openFile` 一条日志，实现体为 HMS 标准模板。→ **无额外风险**。

### 7.5 其余 exported 组件抽样判定

| 组件 | 保护 | 判定 |
|---|---|---|
| `<PKG>`、`apshare.ShareEntryActivity` | 无 permission | 微信/支付宝分享回调；SDK 标准校验（appId 匹配），风险低 |
| `com.alipay.sdk.app.AlipayResultActivity`、`com.alipay.android.app.pay.certpay` receiver | 无 permission | 支付结果回调；由支付宝 SDK 校验，**可被伪造广播观察行为**（只能触发 UI 回调，无数据面） |
| `com.alibaba.lightapp.runtime.activity.TransparentForRequestActivity` | 无 permission | 小程序/H5 请求中转；受 ariver 域校验 |
| `com.alibaba.lightapp.runtime.service.ScreenRecorderService` | 无 permission | 小程序录屏服务；**值得单独复核**（可被外部 startService）〔未知〕 |
| `com.rokid.sdk.tatooine.lite.{SceneActivity,ProcessSceneActivity,LoadActivity}` | 无 permission | Rokid AR 眼镜 SDK 遗留，可被任意启动（显示空白/报错） |
| `com.alibaba.android.teleconf.mozi.activity.TeleVideoConf{Easygo,Pad,}Activity` | 无 permission | 视频会议外部拉起，需有效会议参数 |
| `com.alibaba.imclient.imclientwatchsdk.msghandler.RequestDispatchService` | 无 permission | 手表 SDK 消息分发；**值得复核**（外部 bind 后能否注入消息）〔未知〕 |
| 各类 `android.appwidget.provider` receiver（7+ 个） | 无 permission | AppWidget 标准回调，由系统调用 |
| `com.xiaomi/heytap/coloros/vivo/huawei` 推送 service/receiver | 各家 signature 级 permission | 安全 |
| `com.google.firebase.*`、`com.android.vending.INSTALL_REFERRER` | `INSTALL_PACKAGES` / `c2dm.SEND` | 安全 |

### 7.6 「任意第三方 App 能做什么」总结

**能做（按风险从高到低）**：
1. **让IM进入/退出全进程方法追踪**（`imclient.mcs.start_tracing` / `stop_tracing` 广播）→ 性能 DoS + 可提取的 `.trace` 落盘文件。
2. **读取"用户是否登录IM + 组织是否开通考勤/审批微应用"**（`ExternalProvider`，normal 级 read 权限）。
3. 拉起 `Bokui*` / `TeleVideoConf*` / `rokid SceneActivity` 等 exported Activity（只能造成 UI 层骚扰，凭据注入路径被 `q01.e()` 门控）。
4. 伪造 `com.alipay.android.app.pay.certpay` 广播观察支付 SDK 回调行为（无数据面）。

**不能做**：读写通讯录/消息/文件/DB（无 exported 文件 Provider 且 `grantUriPermissions=false`）、注入登录凭据（`q01.e()` 门控）、读取 token/cookie（`allowBackup=false`，凭据在 app 私有目录 + 加密）、让 App 崩溃（exported 路径全部 `finish()` 兜底）。

---

## 8. Frida 侧建议（attach 时机 / 必绕检测点 / pinning hook 位置）

### 8.1 attach 时机

| 场景 | 建议 |
|---|---|
| 只抓平台栈流量 + 看 Java 逻辑 | `frida -U -f <PKG> --no-pause -l hook.js`（**spawn 模式**，不能 attach 已启动实例） |
| 必须赶在 `libzkfv_tj` / `libfacedevice` 之前 | spawn + `setTimeout(main, 0)` 里先装 `dlopen`/`android_dlopen_ext` 监视，再按需 `Interceptor` |
| 只要 IM/文档（不碰人脸） | 可以不处理 `libfacedevice`/`libzkfv_tj`：它们只在人脸链 `System.loadLibrary` 时才加载 |
| 想一次性接管所有 Surgeon 插桩分支 | 在 `LauncherApplication.attachBaseContext` 之后、`ywm.a()`/`Doraemon.getRunningMode()` 首次调用之前，反射写 `$surgeonFlag`〔推断路径，需验证 `Surgeon` 注册协议〕 |

**关键**：`libsafeguard.so` 有 57 个 `init_array`（`dlopen` 即刻执行），`libzkfv_tj.so` 有 10 个 —— 任何 `Interceptor.attach` 都必须在这之前或之后对已 hook 的 GOT 做复查（bytehook 会抢 PLT 槽）。

### 8.2 需绕过/屏蔽的检测点（按优先级）

| 优先级 | 目标 | hook 建议 |
|---|---|---|
| P0 | `defpackage.lus.a()` / `System.loadLibrary("zkfv_tj")` | 直接不加载：`Java.perform(() => { const S=Java.use('java.lang.System'); const o=S.loadLibrary.overload('java.lang.String'); o.implementation=function(n){ if(n==='zkfv_tj') return; return o.call(this,n); }})`。**代价最小、收益最大** |
| P0 | `libfacedevice` 的路径/属性读取 | hook `libc.so` 的 `open`/`openat`/`fopen`/`fgets`/`access`/`popen`/`__system_property_get`，按参数白名单过滤（`/proc/self/maps`、`/proc/self/status`、`/proc/net/*`、`/data/adb/*`、`*/su`、`*busybox*`） |
| P0 | Frida 自身痕迹 | `frida-server` 改名 + `--disable-*`；线程名避开 `gmain`/`gum-js-loop`/`pool-frida`（Frida 17 默认 `gmain` 会被命中）；`/proc/self/task/*/comm` 一并过滤 |
| P1 | `com.mobile.auth.gatewayauth.manager.SystemManager.checkEnvSafe(...)` | `return null`（= 通过） |
| P1 | `com.mobile.auth.gatewayauth.utils.security.CheckHook.isHookByJar/isHookByStack` | `return false` |
| P1 | `com.alibaba.imclient.safeguard.AntiStrategyHandler.isGrayOpen()` | `return false`（默认已是 false，防服务端开启后反噬） |
| P1 | `SafeGuardInterface$CppProxy.execCmdNative` | `return null` 或按 `CommandType` 白名单放行 |
| P2 | `Doraemon.getRunningMode()` / `ywm.a()` | `return 1` / `return true`（**注意**：这只打开 UI 面板；`DevSettingActivity.L()` 里的 SP 覆盖与 endpoint 改域会**真的生效**，会把 App 指向预发。生产环境慎用） |
| P2 | `TracingBroadcastReceiver.onReceive` | 若不打算用 trace，可 `return` 屏蔽 DoS 面 |

### 8.3 SSL pinning / TLS hook 位置（Java + native 双层）

**Java 层**（三步，覆盖平台栈与部分 ANet）：
```js
// 1) 全局 TrustManager 换成空实现 —— 覆盖面最大
Java.perform(() => {
  const F = Java.use('com.alipay.mobile.common.transport.ssl.X509TrustManagerFactory');
  const Empty = Java.use('com.alipay.mobile.common.transport.ssl.EmptyX509TrustManagerWrapper');
  F.getX509TrustManager.implementation = function () { return Empty.$new(); };
  F.setX509TrustManager(Empty.$new());
});
// 2) 兜底：所有 checkServerTrusted 直通
Java.perform(() => {
  const X = Java.use('javax.net.ssl.X509TrustManager');
  Java.enumerateLoadedClassesSync().filter(c => c.includes('TrustManager')).forEach(c => {
    try { const K = Java.use(c);
      K.checkServerTrusted.overloads.forEach(o => { o.implementation = function () {}; });
    } catch (e) {}
  });
});
// 3) OkHttp 侧（保险）：本包 w33 已被裁得没有 check() 入口，pin 实际无处执行，
//    此处只做防御性处理，不存在也不要报错
Java.perform(() => {
  try { const P = Java.use('defpackage.w33');
    if (P.check) P.check.overloads.forEach(o => { o.implementation = function () {}; });
  } catch (e) { /* 该类在当前构建无 check 方法，属预期 */ }
});
```

**native 层**（主通道，必须做）：
```js
// libssl-dd.so（OpenSSL 1.1.0 ABI）—— 覆盖 encrypt_algorithm / safeguard / barcodessl
['libssl-dd.so','libcrypto-dd.so'].forEach(m => {
  const mod = Process.findModuleByName(m); if (!mod) return;
  ['SSL_read','SSL_write','SSL_read_ex','SSL_write_ex'].forEach(fn => {
    const p = Module.findExportByName(m, fn);
    if (p) Interceptor.attach(p, { onEnter(a){ this.buf=a[1]; this.n=a[2]|0; },
      onLeave(r){ if (r>0) console.log(m, fn, hexdump(this.buf, {length: Math.min(r,256), ansi:true})); } });
  });
});
// Gaea / lsquic：静态内嵌 TLS，无导出 → 先确认是否在 .symtab 里
//   llvm-nm -D liblsquic.so | grep -i ssl   （本轮结果：无 SSL_* 导出）
//   退化方案：hook getaddrinfo/connect 定位，再 Memory.scan 找 TLS record 特征(0x17 0x03 0x03)
//   最实用：在 Java 层 hook GaeaProxy / anet SessionCenter 的请求构造与响应回调拿明文
```

**服务端校验的现实约束**：`wua`/`securitybody`/`sign` 由 `libsgsecuritybodyso` 生成，**改包体会被服务端识破**；只读观察（不解密内容、不改 body）在通过 TLS 后是安全的。

### 8.4 一次性总表（不做事会踩的坑）

| 坑 | 症状 | 处理 |
|---|---|---|
| `libsafeguard.so` 57 个 `init_array` | hook 装晚了，PLT 已被 bytehook 占 | 先 `dlopen` 监视再 hook；必要时 `bytehook_unhook` |
| `libzkfv_tj` 10 个构造器 + 平坦化 `JNI_OnLoad` | 难以静态定位注册的方法 | 不加载该库（P0 方案） |
| `libfacedevice` 查本机端口/代理 | 一开代理就被人脸链判定 | 用上游透明代理，别在本机起监听 |
| `Surgeon` 双份实现 | 改了 `$surgeonFlag` 分支却发现"改了没用"（release 下走的是原实现） | 明确每次 hook 的是**原实现**还是**dispatch 分支** |
| `DevSetting` 改域真的生效 | 打开 mode 后 App 连到预发，登录态混乱 | 只在离线/测试设备上打开；改完 `DevSettingActivity.v1` 记得复位 |
| `System.exit(0)` | exported Activity 在隐私未同意/装错位数时直接杀进程 | 保留一份已同意隐私的 profile |

---

## 9. 未解项与下一步验证

| # | 未解项 | 现有证据 | 建议验证方法 |
|---|---|---|---|
| U1 | `libzkfv_tj.so` 的 `RegisterNatives` 类名/方法名 | 字符串逐字节解密，无明文 | hook `JNIEnv->RegisterNatives`（`libart.so` 的 `RegisterNatives` 或 `art::JNI::RegisterNatives`）dump 参数 |
| U2 | `libzkfv_tj.so` 10 个 `init_array` 构造器各自的职能 | 只有地址 | 逐个 `llvm-objdump -d --start-address` 反汇编，或运行时在 `__cxa_atexit`/`atexit` 下断 |
| U3 | `Surgeon` 的注入协议与签名校验方式 | `ISurgeon`/`Protocol`/`Surgeon` 类存在，`$surgeonFlag` 恒 null | 动态在 `InstrumentAPI.support` 下断，或分析 `com.alibaba.surgeon.Surgeon` 的 `IPC`/`ClassLoader` 逻辑 |
| U4 | `/action/mock_nologin_switch` 的实现与可达性 | **仅存在于 `classes4.dex` 字符串表**（`scan/security/string_hits.txt` devgate 组）；jadx 全量 84,971 个 `.java`（含 283 个反编译失败类）grep **零命中** | dex 级 xref：对该字符串的 `string_idx` 做 `code_item` 引用扫描（baksmali 或自写 dex 解析），确认是否被拼接构造 / 是否落在反编译失败类中 |
| U5 | `libdalvikhack.so` 的 `dvmJdwpStartup` 是否被调用 | 仅有导出与 `DalvikUtils` Java 类引用（`LauncherApplication`） | hook `DalvikUtils` 各方法确认是否执行；或在 `dvmJdwpStartup` 符号上下断 |
| U6 | `X509TrustManagerFactory.setX509TrustManager(空 TM)` 是否有调用点 | 未找到调用方 | 运行时在 `setX509TrustManager` 下断；若无人调用，则 §5.4 的 hook 是纯收益 |
| U7 | 主通道 Gaea 是否有应用层 pin（native 内自建） | `liblsquic.so` 无 SSL 导出符号，无法从符号判断 | 用 `frida-trace -I liblsquic.so -i "SSL_*"` 或 `Memory.scan` 找 TLS record；也可截获 `Gaea` 的 `SessionCenter` 握手参数 |
| U8 | `ScreenRecorderService` / `RequestDispatchService`（exported、无 permission）的真实能力 | 只有 manifest 声明 | 静态读二者实现 + 运行时 `adb shell am startservice/bind` 试探 |
| U9 | `TracingBroadcastReceiver` 重复 `start_tracing` 的行为 | 代码只有一次调用 | 真机发两次广播观察是否 ANR / 文件覆盖 |
| U10 | release 下 `Doraemon` 的 TRACE/Holmes artifact 是否真的加载（决定 `HttpsTrustAllCertsTrustManager` 是否活） | `getArtifact` 逻辑清楚，加载时机不明 | hook `Doraemon.getArtifact` 与 `OkHttpClientFetcher.<init>` |

---

## 10. 证据索引（全部在 `scan/security/`）

| 文件 | 内容 |
|---|---|
| `dex_classes.txt` | 30 个 dex 的完整类描述符索引（**184,177** 类，每行附所属 dex） |
| `string_hits.txt` | 19 个关键词组的字符串命中（antidebug / hook / root / emulator / multiapp / devgate / pinning / sg / safeguard / bytehook / zoloz / safechat / dalvikhack / zkf / crash / nsc / mtop / quic / exported），格式 `组\t关键词\tdex\t字符串` |
| `utils/dex_strings.py` | 上述两个文件的生成脚本（dex 字符串表直读 + 单正则预筛） |
| `manifest_tree.txt` | `aapt2 dump xmltree --file AndroidManifest.xml` 全量（23,579 行） |
| `components.json` | 1,252 个组件的属性表（kind/name/exported/permission/…） |
| `native/elf_info.json` | 152 个 .so 的 ELF 清单：kind / type / segments / sections / init_array / needed / exports / JNI 导出 / has_symtab |
| `native/sg_section_corruption.txt` | SecurityGuard 5 个库的 header + 毒化 section header 原始值 + "表在文件内"证明 |
| `native/sg_recovered_symbols.txt` | 经 `PT_DYNAMIC → DT_SYMTAB/DT_STRTAB/DT_HASH` 还原的导出符号（含 `JNI_OnLoad` 与混淆名） |
| `native/facedevice_detection_strings.txt` | `libfacedevice.so` 偏移 0x1b6000–0x1ba400 的 418 条检测字符串（带真实文件偏移） |
| `native/disasm/zkfv_tj.dis` | `libzkfv_tj.so` 全量 AArch64 反汇编（70,733 行，llvm-objdump 19.1.7） |
| `utils/elf_recon.py` | ELF 清单生成脚本（pyelftools） |

复现命令要点：
```bash
# dex 字符串/类索引（17 s 跑完 30 dex）
python scan/security/tools/dex_strings.py unpacked/dex scan/security
# ELF 清单
python scan/security/tools/elf_recon.py unpacked/native/lib/arm64-v8a scan/security/native
# NSC 复核（直接读 target.apk，不依赖 unpacked/res）
aapt2 dump xmltree --file res/xml/network_security_config.xml target.apk
aapt2 dump xmltree --file AndroidManifest.xml target.apk > scan/security/manifest_tree.txt
# SecurityGuard 反汇编（section 坏了也能用，走 phdr）
llvm-objdump -d --no-show-raw-insn --arch-name=aarch64 unpacked/native/lib/arm64-v8a/libzkfv_tj.so
```

---

## 11. 与既往报告的差异（复核结论）

| 既往结论 | 本轮复核 | 判定 |
|---|---|---|
| NSC `cleartext=true` + `trust-anchors{system,user}` | 直接对 `target.apk` 用 `aapt2` 复核一致 | **确认** |
| "SecurityGuard 段表破坏、PT_LOAD/PT_DYNAMIC 有效" | 确认，并补：**毒化形式是 `sh_addr/sh_offset=UINT64_MAX` + `sh_name=0`**；给出 PT_DYNAMIC 还原法与全部导出 | 确认 + 深化 |
| "`libzkfv_tj` 是唯一无法定性的库" | 定性为**人脸链专用混淆安全库**，给出 Java 入口 `defpackage.lus.a()` 与 6 个调用点、10 个构造器、导入表 | **闭合（部分）**，剩 U1/U2 |
| "`mock_nologin_switch`（BokuiActivity 超大路由）" | **在 84,971 个反编译文件中零命中**，仅 classes4.dex 有字符串 `/action/mock_nologin_switch` | **降级为未闭合（U4）**：不能说它是可用开关 |
| "调试模式开关 = WebView 远程调试（完整链路已观察）" | 链路确认，并补全三道闸（`mode∈{1,2}` → SP → Gaea 键）；另发现**邮件/文档模块硬编码 `setWebContentsDebuggingEnabled(true)`**（无门控，更现实的入口） | 确认 + 修正（真实入口在链 B） |
| "`DevRealmConfigActivity` 只读" | 未在本轮任务范围，未复核 | 未验证 |
| "exported 79 个" | 一致（1,252 组件 / 79 exported） | 确认 |
| "`ExternalProvider` 是 exported 但未评估权限级别" | **read 权限 protectionLevel = normal** → 任意 App 可读；且云控键默认 true | **新增高危修正** |
| "Huawei PushProvider 属 exported 面" | 实为 signature 级 read/write 权限，第三方不可用 | 修正（降级） |
