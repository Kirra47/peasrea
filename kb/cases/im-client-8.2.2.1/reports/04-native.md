# 04 · Native 层全解（IM 8.2.2.1 专属版 · arm64-v8a · 152 个文件）

- 目标目录（只读）：`re/base_apk3/unpacked/native/lib/arm64-v8a/` — **152 个文件 / 244,792,580 B（233.5 MiB）**，无其他 ABI。
- 上级包：`re/base_apk3/target.apk`（IM内核 8.2.2.1，`<PKG>`，enterprise/exclusive）。本轮全部结论来自 `target.apk` 内 `lib/arm64-v8a` 的独立解析，**未修改原件**；一切派生产物落在 `re/base_apk3/scan/native/`。
- 本报告与既往 `re/imclient_mod/report/native-libs.md` 的关系：**独立复核，不引用其结论**。凡与其不一致处，在 §1.3 明列（共 4 处修正、1 处新增）。
- 标注约定：**【观察】**=可从产物直接复现；**【推断】**=基于观察的合理归因；**【未知】**=本轮证据不足。

---

## 0. 结论摘要

1. **138 个 ELF**（全部 `ELF64 / AArch64 / DYN / PIE`），**14 个非 ELF**（6 个签名迷你 APK、1 个伪 APK、1 个 7z、1 个 ZIP 容器、3 个 `.ucb` 数据桩、3 个 `.version` 文本桩）。**【观察】**
2. **只有 `libsafechat.so` 未 strip**，且罕见地**完整保留 `.symtab` + 全套 `.debug_*`（2.88 MB DWARF，含源码路径）**；其余 137 个已 strip。**【观察】**
3. **5 个 SecurityGuard ELF 的节头表被"擦除式"破坏**（`sh_addr/sh_offset = 0xffffffffffffffff`、`sh_name` 全 0、`sh_size=0x10`），但程序头/`PT_DYNAMIC` 完好 → 加载器无感、静态工具受阻。本轮已**从 PT_LOAD+PT_DYNAMIC 重建节头表**并产出可用副本（`llvm-readelf -S`/`objdump -d` 均恢复正常）。**【观察+已复现】**
4. **12 个库存在悬空 `DT_NEEDED`**，去重后 5 个缺失库：`libijkffmpeg.so`(7 处)、`libv8uc.so`(2)、`libjsi.so`(1，实体在 UC 的 ZIP 容器内)、`libantplayer-2.0.so`(1)、`libistylepdfengine.so`(1)。**【观察】**
5. **JNI 面**：87 个库导出 `JNI_OnLoad`；70 个库共 **2,488 个 `Java_*` 导出**；**33 个库的 `JNINativeMethod` 表在 `.data.rel.ro` 里是明文的，共解析出 808 个 native 方法**（名称+签名+函数地址）。**【观察】**
6. **`libzkfv_tj.so` 已定性**：它是支付宝 **`java2jni` 编译器**（Java→native AOT 转换器）的产物，由 **DTF 人脸 SDK**（`com.dtf.face.api.DTFacadeSec` / `com.dtf.toyger.base.face.*` / `faceverify.*`）装载，native 侧承载这些类的 Java 逻辑（含 `initApdid`、`generateBlob`、`processFrame`、`LogUtils`）。"零字符串"的真相是：**功能性字符串全部被编译进代码 + 一段 ~14 KB 高熵可打印字符池（加密串表）+ 方法名/签名运行时解密**，不是"空壳"，也不是独立的反调试模块。**【观察+推断】**
7. **`libsafechat.so`（安恒信息）内没有任何 frida/xposed/root/模拟器/调试检测项**（3,623 条符号、6,259 条 DWARF 字符串、全库 ASCII 串扫描均为 0 命中）；它是纯加解密 SDK（SM4 + wolfSSL，`Java_com_dbappsecurity_et_DIJni_*` 20 个入口，含 VOIP 会话密钥接口）。检测名单实际在 **`libfacedevice.so`（Zoloz 安全设备模块）**，本轮完整提取（hook 框架 20 项、root 套件 12 项、虚拟摄像头 12 项、模拟器 40+ 路径、调试/注入 8 项）。**【观察】**
8. **`libcrashsdk.so` 不只是崩溃捕获**：内含 `/libsechook.so`、`has root: %s`、`Read self maps` 等 root/hook 探测串（既往报告仅记为"崩溃处理"）。**【观察，修正既往结论】**
9. **`libsafeguard.so` 内置 inline-hook 检测器**：C++ 符号 `imclient::safeguard::HookScanner::InlineHook::GetLibTextSectionCrcInFile` + `/proc/self/maps`、`/proc/%d/maps`、`antiStrategyJsapiHookCheck`，通过 **CRC 比对已加载库 .text 段**发现 inline hook。**【观察+推断】**

---

## 1. 方法与可复现性

### 1.1 工具链与产物

| 环节 | 做法 | 产物（`re/base_apk3/scan/native/`） |
|---|---|---|
| ELF 解析 | **自写解析器** `scripts/elfcore.py`（只依赖 ELF header + program headers + `PT_DYNAMIC`，节头表损坏也能解析；含 GNU_HASH 符号计数、RELA/RELR 相对重定位、`init_array` 项解析） | `elf_summary.tsv`（152 行 × 30 列） |
| 结构深挖 | `scripts/dump.py`：`DT_*` 全量、段表/节表、全部导出/导入符号、`init_array`、`JNINativeMethod` 表发现（按 `.data.rel.ro` 中「名字指针+签名指针+函数指针」三元组） | `symbols/<lib>.txt`（30 个重点库）、`jni_tables.tsv`（33 库 / 808 方法） |
| 字符串 | `scripts/strings_scan.py`：ASCII≥6 + UTF-16LE≥4，记录**文件偏移**；再按 9 类关键词、URL/域名/IP、PEM 分类 | `interesting_strings.txt`（32,072 行）、`urls.tsv`（2,626 行）、`pem_hits.txt`/`pem_blocks.txt`、`string_stats.tsv`、`strings/<lib>.txt`（26 个库全量串） |
| 常量 | 长十六进制常量（≥32 字符）抽取并**逐条回查上下文** | `hex_constants.tsv`（301 条，已剔除工具链 commit hash 假阳性） |
| 依赖 | `DT_NEEDED` × APK 内 152 文件清单 × Android 平台库白名单 | `deps_toolchain.tsv`、`embedded_containers.tsv` |
| 反汇编 | `scripts/disasm.py`（capstone 5.0.7）：AArch64 线性反汇编 + `ADRP/ADD`/`ADRP/LDR` 字符串交叉引用 + `BL` 目标符号化 | `symbols/zkfv_tj_disasm.txt` |
| 段表还原 | `scripts/repair_shdr.py`：由 `PT_LOAD`+`DT_*` 重建节头表、回填 `.shstrtab`、按地址区间重写 `st_shndx` | `unpacked/*.shdr-repaired.so`（5 个） |
| 容器解包 | `zipfile` 解出 7 个 ZIP；AXML 字符串池自解析取 `package/versionName`；7z 仅做结构解析（无 7z 工具，见 §3.2 未知项） | `unpacked/<name>/`、`scan/native/containers.md` |
| 交叉 | `java/sources/`（jadx 全量，84,971 文件）按 `System.loadLibrary("X")` 反查装载方；对关键串做 Java 侧有无比对 | 见 §4.3、§6.3 |

> 本机可用：`llvm-readelf / llvm-objdump / llvm-nm / llvm-strings`（WinLibs POSIX LLVM，`mingw64/bin`）、`pyelftools`、`capstone 5.0.7`、Python 3.12。**未使用** 任何在线服务。

### 1.2 关键统计（可从 `elf_summary.tsv` 复算）

| 维度 | 分布 |
|---|---|
| `e_type` / `e_machine` | `DYN`×138 / `AArch64`×138（无 EXEC、无 x86） |
| `DF_1_PIE` | `0x1`×131、`0x9`(PIE+NODELETE)×2、`0x0`×5（恰为 sg* 五个） |
| `GNU_STACK` | `RW`×138（**无 RWX**，无栈可执行） |
| `TEXTREL` | 0×138（无文本重定位） |
| `DT_RELR` | 0×138（全部用传统 `.rela`） |
| `.symtab` | 仅 `libsafechat.so`（3,623 条） |
| `.debug_*` | 仅 `libsafechat.so`（`.debug_info` 775 KB / `.debug_loc` 1.45 MB / `.debug_str` 99 KB / `.debug_line` 358 KB） |
| `.note.gnu.build-id` | 缺 7 个：`libAMapSDK_MAP_v8_1_0.so`、`libcrypto-dd.so`、`libistylepdfengine-jni.so`、`liblogging.so`、`libmpaas_crypto.so`、`libssl-dd.so`、`libtaopai_data_core.so` |
| `.note.android.ident` | `android_api=21`×124、`22`×1，其余 24 个无（14 个非 ELF + 10 个 ELF 无该 note） |
| `JNI_OnLoad` | 有×87 / 无×51 |
| `Java_*` 导出 | 2,488 个，70 个库非零（Top：jingle 398、dtnest_module 246、TangleSDK 161、istylepdfengine-jni 153、dtnest 134、AMap 125、taopai-jni 119、aladdin 104） |
| `RegisterNatives` 明文表 | 33 库 / 808 方法（Top：antplayerinf 105、jsengine-api 103、weexcore 85、TaoLive 55、database_sqlcrypto 54、ijkmmengine 50、flutter 49） |
| `init_array` | 合计 3,631 项；最多 dtnest_module 538、TangleSDK 406、dtnest 356、flutter 303 |
| 无 `.comment` | 8 个：`libapp.so`、`libdexloaderuc.so`、`liblibloaderuc.so` + 5 个 sg*（被擦除） |

### 1.3 与既往报告的差异（复核结论）

| # | 既往说法 | 本轮复核 | 依据 |
|---|---|---|---|
| 1 | `libzkfv_tj` "无任何功能字符串，无法定性" | **已定性为 java2jni 产物 + DTF 人脸 SDK 的 Java 逻辑原生实现**（详见 §5.1） | 0x5e03b 水印串 + `lus.a()`/`DTFacadeSec.initApdid` 交叉 |
| 2 | `libcrashsdk` 属"崩溃处理而非注入检测" | **同时含 root/hook 探测串**（`/libsechook.so`、`has root: %s`、`/proc/self/maps`） | `strings/libcrashsdk.so.txt` |
| 3 | `libsafechat` 仅记"保留 .symtab" | **还有完整 DWARF + 源码路径 + Windows/macOS 双构建机路径**，无任何检测项 | §5.3 |
| 4 | 悬空依赖 5 个（无精确依赖方） | 5 个确认；给出**12 个依赖方**逐一清单 | `deps_toolchain.tsv` |
| 5 | —（未提） | **新增**：`libsafeguard.so` 的 `HookScanner::InlineHook::GetLibTextSectionCrcInFile` inline-hook CRC 检测 | §5.6 |

**已排除的假阳性（重要）**：78 个库中重复出现的 `003100370607242ddd5815e4a043907ea9004281` / `1d739ffb0366421d383e04ff80ec2ee591315116` 等 20 字节十六进制串**不是密钥**，而是 `.comment` 里 NDK r19c `clang`/`llvm` 的 **git commit hash**（上下文：`clang version 7.0.2 (https://android.googlesource.com/toolchain/clang 0031…)`）。同理 `libsgmainso` 里的 `32461960712c…`/`183abd29…` 是 NDK r19 clang 6.0.2 的 commit hash。**【观察】**

---

## 2. 全量清点

### 2.1 结构异常矩阵（仅列异常/值得注意者）

| 库 | 异常 | 证据 |
|---|---|---|
| `libsgmainso-6.6.230702.so`、`libsgmiddletierso-6.6.230702.so`、`libsgmiscso-6.5.14625633.so`、`libsgnocaptchaso-6.5.14625633.so`、`libsgsecuritybodyso-6.6.230702.so` | **节头表被擦除**（非"加壳"，是可加载但不可静态解析） | `llvm-readelf -S` 报 `section [0..8] has invalid sh_name / sh_addr=0xffffffffffffffff`；`sh_size` 统一 `0x10`；`DT_FLAGS_1=0` |
| `libWebViewCore_7z_uc_5.5.0.0.so` | 7z 归档（非 ELF） | 魔数 `37 7a bc af 27 1c`，7z v0.4，尾部 37 B 编码头 |
| `libWebViewCore_7z_uc_jsi_255.so` | ZIP 容器（非 ELF） | `PK\x03\x04`，8 条目，含 63.5 MB `libwebviewuc.so` |
| `libapp.so` | Dart AOT 快照，仅 6 个 dynsym、0 个导出函数、无 `.comment`、`init_array=0` | 符合 Flutter AOT 特征 |
| `libMNN_CL.so` / `libface3d_jni.so` | 导出函数 0（仅数据/导入），符合 OpenCL 内核库 / 纯 JNI stub 特征 | `elf_summary.tsv` |
| `libflutter.so` | `.comment` 为 `Linker: Fuchsia LLD 16.0.0`；1 MB 首段熵 2.995（大段零填充） | 正常 Flutter 引擎 |

### 2.2 `DT_NEEDED` 与悬空依赖（去平台库后的真实缺口）

| 缺失库 | 依赖方（12 个库） | 判读 |
|---|---|---|
| `libijkffmpeg.so` | `libijkplayer`、`libijksdl`、`libijkmmengine`、`libijkeditor`、`libijkengine-gif`、`libijkrecorder`、`libmediaflow` | ijk 栈在本包**未随包提供 ffmpeg**（实体是 `libtbffmpeg-imclient.so`），运行期由 `IjkLibLoader` 另行下载/装配；`com.alipay.streammedia.utils.SysLoadLib` 显式 `loadLibrary("ijkffmpeg")` → 属"可用但通常不走"的降级路径。**【推断】** |
| `libv8uc.so` | `libjsengine-api`、`libjsengine-platform` | UC V8，运行期由 UC 容器提供 |
| `libjsi.so` | `libv8worker-native` | **实体存在**：`libWebViewCore_7z_uc_jsi_255.so` 内 `lib/arm64-v8a/libjsi.so`(866 KB) |
| `libantplayer-2.0.so` | `libantplayerinf-2.0` | 播放器实体缺失（仅 info 壳） |
| `libistylepdfengine.so` | `libistylepdfengine-jni` | PDF 引擎主体缺失，仅 JNI 层 |

其余 130 个 ELF 的 `DT_NEEDED` 全部命中 APK 内文件或 Android 平台库（白名单见 `scripts/survey.py` 同目录脚本）。

### 2.3 JNI 面（谁在注册什么）

- **导出 `Java_*` 直连型（70 库）**：最简单、静态可读，如 `libsafechat`(20)、`libdtftoyger`(12)、`libdecode100380`(42)。
- **`JNI_OnLoad` + `RegisterNatives` 型**：33 库的 **808 个方法表是明文**，已全量落地到 `jni_tables.tsv`。示例（`libdtftoyger.so`，25 方法，类 `com.dtf.toyger.base.*`）：`processImage (Ljava/util/List;Lcom/dtf/toyger/base/algorithm/TGDepthFrame;Lcom/dtf/toyger/base/ToygerAttr;)V`、`init (Landroid/content/Context;[BLjava/lang/String;Ljava/lang/String;Ljava/util/Map;)Z`、`allocDepthFrameData (J)Ljava/nio/ByteBuffer;`。
- **仅 `JNI_OnLoad`、表被加密（2 库）**：`libzkfv_tj.so`、`libAPSE_J.so` — 全库检索 `scanPackage`/`methodToNative`/`cy1`/`xp1`/`(Landroid/content/Context;)Z` 等 Java 侧声明名**均为 0 命中**，说明注册表由运行时解密。**【观察+推断】**（详见 §5.1）
- **`JNI_OnLoad` 但走 `FindClass`+`GetMethodID` 反射型**：如 `libfacedevice.so`（0 个 `Java_*`、0 个明文表，JNI 面由 Java 侧 `face.security.device.api.FaceSecDevice` 的 `native` 声明定义）。

### 2.4 编译器/NDK 指纹

| clang / LLD | NDK build | 库数 | 代表库 |
|---|---|---|---|
| clang 7.0.2（NDK r19c，`Android (4751641 based on r328903)`） | 4751641 | **77** | dtnest、gaea、facedevice 之外的大多数阿里自研库 |
| （无 `.comment`） | — | 16 | `libapp.so`、UC loader、5 个 sg* |
| clang 5.0.300080（老 mPaaS 工具链） | — | 12 | `libAPSE*`、`libmpaas_crypto` 同族 |
| clang 9.0.9（`Android (7019983 based on r365631c3)`） | 7019983 | 5 | `libfacedevice`、`libalieas`、`libflybird`、`libHolmesJni`、`libtaopai_data_core` |
| clang 8.0.2 / 9.0.8 | — | 5 / 3 | `libc++_shared`、`libjingle_peerconnection_so` |
| **Alipay clang 6.0.1 (`Alipay.Obfuscator build200917`)** | — | **3** | `libAPSE_7.1.0`、`libAPSE_J`、`libzkfv_tj`（均含自定义 `.llvm` 节） |
| LLD 20.0.0 + clang 20.0.0（`Android (13065274 based on r547379)`） | 13065274 | 1 | **`libsafechat.so`**（安恒，2025 年重编，NDK r29） |
| LLD 18.0.3 | 12470979 | 1 | `libdtftoyger.so` |
| LLD 16.0.0 (Fuchsia) | — | 1 | `libflutter.so` |
| LLD 14.0.7 | 9352603 | 1 | `libavif_android.so` |
| LLD 12.0.5 | 7284624 | 2 | `libbytehook.so`、`libcycloneuc.so` |
| LLD 11.0.5 | 7155654/6875598 | 2 | `libykosboost_qs-1.0.1.so` 等 |

**【推断】** 77 个主力库统一用 NDK r19c 构建 → 该包 native 侧主构建基线是 r19c；`libsafechat`(r29)、`libdtftoyger`(r18+) 是少数"新工具链"组件，说明它们由第三方/独立流水线构建后合入。

---

## 3. 非 ELF 14 个的定性

| 文件 | 类型 | 内部结构（本次解包） | 定性 |
|---|---|---|---|
| `libsgmain.so` | ZIP / 签名 APK | `AndroidManifest.xml`(2596) `classes.dex`(76608) `resources.arsc`(564) `META-INF/CERT.{RSA,SF}` + `lib/arm64-v8a/libsgmainso.ucb.so`(112) | SecurityGuard **插件包** `com.alibaba.wireless.security.mainplugin`，`pluginname=main`，`versionName=6.6.230702` |
| `libsgmiddletier.so` | ZIP / 签名 APK | 同上，`classes.dex` 64852 + `libsgmiddletierso.ucb.so`(96) | 插件 `…middletierplugin`，6.6.230702，依赖 `main:6.6.0;securitybody:6.6.0;` |
| `libsgsecuritybody.so` | ZIP / 签名 APK | `classes.dex` 71340 + `libsgsecuritybodyso.ucb.so`(96) | 插件 `…securitybodyplugin`，6.6.230702 |
| `libsgmisc.so` | ZIP / 签名 APK | `classes.dex` 11484（无 `.ucb`） | 插件 `com.alibaba.wireless.security.misc.MiscPlugin`，6.5.14625633 |
| `libsgnocaptcha.so` | ZIP / 签名 APK | `classes.dex` 7424 + `res/layout/activity_verify.xml` + `res/anim/anim_fit.xml` + `resources.arsc` | 插件 `…nocaptchaplugin`，6.5.14625633，勾选式验证码 UI；`activities=com.alibaba.TestActivity;com.alibaba.RealActivity` |
| `libfakedexuc.so` | ZIP / 伪 APK | `AndroidManifest.xml`(496) + `classes.dex`(472，仅 `Lcom/uc/sandbox/fake/EmptyClass;`) | UC 的占位包 `com.uc.webviewsdk.corelibs`，`versionName=1.1.1.1.BuildSeq` |
| `libWebViewCore_7z_uc_jsi_255.so` | ZIP / 伪 APK | 8 条目：`core.jar`(1.0 MB)、`sdk_shell.jar`(15 KB)、`lib/arm64-v8a/libjsi.so`(866 KB)、`lib/arm64-v8a/libwebviewuc.so`(**63.5 MB**)、自签 `META-INF/ANDROID_.{SF,RSA}` | UC WebView 内核运行期装配包（同 package 名） |
| `libWebViewCore_7z_uc_5.5.0.0.so` | **7z** | 7z v0.4；`nextHeaderOffset=19,953,605`、`nextHeaderSize=37`（**编码头**） | 与上一个容器同一 UC 内核的另一分量（19.0 MB 压缩体）；**内部文件名需 LZMA 解头**，本轮未解（§7 未知项） |
| `libsgmainso.ucb.so`(112 B) / `libsgmiddletierso.ucb.so`(96 B) / `libsgsecuritybodyso.ucb.so`(96 B) | 高熵二进制桩 | 熵 6.17–6.57，无 ASCII、无 ELF/ZIP 魔数 | SG 的**加密体/校验数据桩**，由插件 dex 在运行期解密 |
| `libsgmainso.version.so` / `libsgmiddletierso.version.so` / `libsgsecuritybodyso.version.so` | 文本 | 内容 = ASCII `6.6.230702`（10 B） | 版本标记，供 SG 选择对应 `.ucb` 实体 |

> 容器、证书与解包落盘位置见 `re/base_apk3/scan/native/containers.md`；解包副本在 `re/base_apk3/scan/native/unpacked/`。

**【观察】** 5 个 SG 迷你 APK 的 `CERT.RSA` 均为 1382 B，与主 APK 的 Alibaba 证书链同族（v1 签名）；`classes.dex` 熵 5.1–5.6，无二次加密。

---

## 4. 按 SDK 归类（152/152 全覆盖）

### 4.1 分组表

| 组 | 数量 | 成员（大小） |
|---|---|---|
| A IM自有业务/框架（IM·日历·搜索·Aladdin·Holmes·性能） | 20 | dtnest(2.3MB) dtnest_module(7.9MB) TangleSDK(2.6MB) DtSync(1.1MB) nest_mmkv(258KB) calendar_sdk(2.9MB) imclient-searcher(1.3MB) aladdin_jni(322KB) flybird(463KB) holmes(1.2MB) HolmesJni(54KB) fulltrace(93KB) perf(149KB) mem-monitor(9KB) dt-asan(5KB) prglite.3.0(322KB) alpha(93KB) anrcanarycompat(46KB) dmojo_support(322KB) imclientMindNlu(834KB) |
| B Flutter | 3 | flutter(9.8MB) app(24.2MB) flutter_ffi(322KB) |
| C 阿里 mPaaS / 支付宝基础（APSE·Bifrost·jsengine） | 17 | APSE_7.1.0(3.2MB) APSE_J(2.1MB) ap_sec_store(162KB) Bifrost(3.1MB) mpaas_crypto(33KB) APMUOCPLIB(85KB) AWT_Generator(37KB) logging(41KB) loggingdevice(29KB) AlipayBitmapNative(9KB) antkv(77KB) alieas(2.0MB) jsengine-api(160KB) jsengine-loadso(25KB) jsengine-platform(95KB) v8worker-native(90KB) quickjs(597KB) |
| D Gaea 网络栈（QUIC/LWP/ZTNA/XCDN/TNET） | 13 | gaea(9.2MB) GaeaConfigJni(198KB) gaeadns_jni(66KB) gaeahttp_jni(126KB) gaealwp_jni(534KB) quic_jni(150KB) xquic(1.3MB) lsquic(4.5MB) tnet-4.0.0(354KB) coap(54KB) XcdnEngine(3.3MB) ipdetector(9KB) ipstack-detect(9KB) |
| E UC WebView 容器 | 7 | WebViewCore_7z_uc_5.5.0.0(19.0MB) WebViewCore_7z_uc_jsi_255(23.5MB) libloaderuc(42KB) dexloaderuc(17KB) fakedexuc(3KB) uc_bhook_jni(538KB) cycloneuc(50KB) |
| F SecurityGuard | 16 | sgmain(39KB) sgmainso-6.6.230702(1.5MB) sgmainso.ucb/version sgmiddletier(35KB) sgmiddletierso-6.6.230702(731KB) +2 桩 sgmisc(12KB) sgmiscso-6.5.14625633(157KB) sgnocaptcha(12KB) sgnocaptchaso-6.5.14625633(137KB) sgsecuritybody(40KB) sgsecuritybodyso-6.6.230702(594KB) +2 桩 |
| G 安全/Hook/检测 | 7 | safeguard(1.8MB) bytehook(42KB) dalvikhack(9KB) zkfv_tj(454KB) safechat(3.5MB) crashsdk(640KB) facedevice(2.5MB) |
| H 人脸/活体（Zoloz + dtf） | 11 | toyger(605KB) dtftoyger(1.3MB) Face3D(343KB) face3d_jni(25KB) AliCVKit(4.8MB) facebeauty(33KB) FalconFaceDynamic(146KB) falconlooks(29KB) LivenessModule(126KB) mnnface(130KB) pixelai(702KB) |
| I MNN / AI 推理 | 6 | MNN(1.8MB) MNN_CL(1.1MB) MNN_Express(786KB) MNNOpenCV(157KB) xnn(810KB) mnnkitcore(221KB) |
| J 音视频（ijk / taopai / tb* / media） | 23 | ijkeditor(238KB) ijkengine-gif(590KB) ijkengine-mp3(197KB) ijkmmengine(1.2MB) ijkplayer(167KB) ijkrecorder(54KB) ijksdl(318KB) taopai-ffmpeg(3.6MB) taopai-jni(242KB) taopai_data_core(62KB) taobaoplayer-imclient(1.1MB) tbffmpeg-imclient(7.1MB) tbplayer-imclient(268KB) tbsdl-imclient(362KB) mediaflow(474KB) TaoLive(2.4MB) antplayerinf-2.0(584KB) antpng(317KB) pbo_jni(9KB) ddopustools(353KB) silk_jni(209KB) yuv(45KB) ali_tvsharelib(5KB) |
| K RTC | 2 | grtn(2.4MB) jingle_peerconnection_so(23.0MB) |
| L JS 引擎 / Weex / 小程序 | 6 | JavaScriptCore(8.8MB) WTF(558KB) weexcore(1.2MB) weexjsb(5KB) weexjss(434KB) weexjst(5KB) |
| M 高德地图 | 1 | AMapSDK_MAP_v8_1_0(7.4MB) |
| N 加密/安全存储 | 7 | openssl(1.9MB) ssl-dd(507KB) crypto-dd(2.4MB) encrypt_algorithm(926KB) barcodessl(9KB) database_sqlcrypto(2.0MB) kaliumjni(110KB) |
| O 图像/文档/图形 | 7 | avif_android(1.4MB) pl_droidsonroids_gif(41KB) freetype(529KB) istylepdfengine-jni(85KB) gcanvas(574KB) bitmaps(6KB) ddbitmaps(9KB) |
| P 扫码/条码 | 1 | decode100380(992KB) |
| Q 运行时/压缩/工具 | 5 | c++_shared(954KB) stlport_shared(580KB) zstd(541KB) ddmemchunk(5KB) ykosboost_qs-1.0.1(8KB) |

覆盖校验：`152 = 20+3+17+13+7+16+7+11+6+23+2+6+1+7+7+1+5`，无遗漏、无重复、无"无法归属"项。

### 4.2 每组的关键证据（节选）

| 组 | 符号证据（`symbols/*.txt` / `elf_summary.tsv`） | 字符串/版本证据 |
|---|---|---|
| A | `Java_com_imclient_nest_*`(134)、`Java_com_alibaba_imclient_*`；TangleSDK 161 个 `Java_*` | `imclient` 业务串、`mmkv`、`Bokui` 相关 |
| B | `libapp.so` 仅 6 dynsym / 0 导出 | `_exclusiveConfigMapPC`、`pre-workspace.<host>`、`pre-test-workspace.<host>`、`wsdebug.<host>` |
| C | `Java_com_alipay_mars_*`、`Java_com_alipay_bifrost_*`、`Java_com_uc_webview_*`(UC 桥) | `.comment=Alipay clang 6.0.1 … Alipay.Obfuscator build200917`；`mygwshort.alipay.com` |
| D | `Java_com_imclient_gaea_*`；tnet 27 / XcdnEngine 5 个 RegisterNatives | `quic://…`, `lws://…sni=dk&rm=na620`, `ztna://accelerate.ztna-<host>:8081` |
| E | `Java_com_uc_webview_export_multiprocess_DexLoader_nativeLoadDexByFdOnL*`；`uc_bhook_jni` 13 个 RegisterNatives | `com/uc/hook/TrafficHook`、`hook cfi OK` |
| F | 5 个 sg* ELF：`dynsym` 合计 798 条（510/101/55/46/86），其中**已定义函数 127 个**（108/5/2/2/10），全部导出 `JNI_OnLoad`、无 `Java_*` | `sgcookiecheck`、`outsidesgext`、`guard variable for` |
| G | `bytehook_*`(14)、`DalvikRuntime::*`、`HookScanner::InlineHook::…` | 见 §5 |
| H | `Java_com_alipay_zoloz_toyger_algorithm_Astro_*`、`Java_com_dtf_toyger_*`(25 个 RegisterNatives) | `NSSecurityDevice` 混淆类、检测名单（§5.4） |
| I | `MNN*` 符号 | `PixelAI module: %s set int params`、`src/submodule/FaceDetection/src/face_3d.cpp` |
| J | `ijk*` / `Api_*`（ijkmmengine 50 个 RegisterNatives） | `libijkffmpeg.so`、`ftp://upload.ffmpeg.org/incoming/` |
| K | `Java_org_webrtc_mozi_*`(398)、`Java_com_taobao_testwebrtcso_*` | `webrtc.org/experiments/rtp-hdrext/*` |
| L | `jsHandleCallNative`、`nativeLayoutRenderObject`（weexcore 85） | `Weex`、`QuickJS` |
| M | `Java_com_autonavi_base_*`(125) | `m5.amap.com`、`mpsapi.amap.com`、`10.65.64.70` |
| N | `Java_org_abstractj_kalium_*` | `FIPS module in DEGRADED mode`（wolfSSL/safechat）、`0123456789ABCDEF`（SQLCipher 测试向量） |
| O | `Java_com_istyle_pdf_*`(153)、`Java_com_taobao_gcanvas_*` | `freetype`/`avif`/`gif` |
| P | `Java_com_alipay_ma_decode_MaDecode_*`(42) | `visualead::ReaderResult/DecoderResult` |
| Q | `zstd`/`c++_shared` | — |

### 4.3 Java 侧装载方交叉（`System.loadLibrary` 反查，节选）

| native 库 | Java 装载类（jadx 全量） |
|---|---|
| `zkfv_tj` | `defpackage.lus.a()` ← `com.dtf.face.api.DTFacadeSec`、`com.dtf.toyger.base.face.ToygerFaceService`、`com.dtf.toyger.base.face.FaceBlobManagerJson`、`com.dtf.face.utils.LogUtils`、`faceverify.w`、`faceverify.y` |
| `APSE_J` | `defpackage.kus.a()` ← `com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack` |
| `APSE_7.1.0` | `com.alipay.alipaysecuritysdk.modules.x.ac` |
| `facedevice` | `face.security.device.api.FaceSecDevice` |
| `toyger` / `dtftoyger` | `com.alipay.zoloz.toyger.algorithm.{Toyger,Astro}`、`com.dtf.toyger.base.algorithm.Toyger`、`com.dtf.face.ui.FaceLoadingActivity` |
| `safechat` | `com.dbappsecurity.et.DIJni`（静态块，两处） |
| `dalvikhack` | `com.taobao.android.runtime.DalvikUtils`（静态块） |
| `bytehook` | `com.bytedance.android.bytehook.ByteHookMod` |
| `safeguard` | `com.alibaba.imclient.safeguard.SafeGuardMain`(6 处)、`SafeGuardInterfaceManager` |
| `safeguard` 依赖 | `libsafeguard.so` 的 `DT_NEEDED` 含 `libbytehook.so`（native 层强依赖） |
| `alpha` | `com.alibaba.android.imclient.alpha.AlphaManager` |
| `crashsdk` | `com.alibaba.motu.crashreporter2.CatcherManager` |
| `gaea*` | `com.imclient.gaea.{http,dns}.{GaeaHttp,GaeaDns}`；lwp `defpackage.w2b`；`com.laiwang.protocol.gaea.GaeaAladdinManager` |

> 反向亦成立：`libapp.so`(Dart)、`libtnet`、`libcoap` 等无 Java 直接 `loadLibrary` 的库，由上层库/Flutter 引擎间接装载。

---

## 5. 关键库专题

### 5.1 `libzkfv_tj.so` —— **判定：java2jni 产物 + DTF 人脸 SDK 的 Java 逻辑原生实现**（不是加固壳，也不是独立检测模块）

**观察（可复现）**

| 项 | 值 | 位置/证据 |
|---|---|---|
| 类型/大小 | ELF64 AArch64 DYN，454 KB | `elf_summary.tsv` |
| 导出 | **仅 `JNI_OnLoad`**；40 个 dynsym（36 个未定义导入）；0 个 `Java_*` | `symbols/libzkfv_tj.so.txt` |
| `init_array` | **10 项**（0x14ce4、0x1a7f0、0x21c78、0x270d8、0x2ba98、0x3104c、0x1450c、0x14540、0x1458c、0x145a4） | 同上 |
| 导入 | `syscall`、`dl_iterate_phdr`、`pthread_*`、`__android_log_print`、`libstdc++` 相关 | 同上 |
| `.comment` | `Alipay clang version 6.0.1 (based on LLVM 6.0.1.Alipay.Obfuscator build200917)` + 自定义 `.llvm` 节 | 同上 |
| **工具水印** | `0c8d4b1a-9f6c-407f-8fde-4f18c43c0775\|1764746815.4558694\|java2jni-1.0.10.0-(20201217)\|` @0x5e03b | 唯一 ASCII 水印 |
| 高熵可打印池 | 0x5b2f0–0x5e5d0（约 14 KB）全是 `"?[_Z]aXN$QVXcS[V` 这类可打印乱码 | 加密串表 |
| 功能串 | 只有 libc++ 异常消息（`std::future_error`/`Broken promise`/`No associated state`）+ 导入符号名 | 无 URL/类名/JNI 名 |

**交叉（决定性）**
- `java/sources/defpackage/lus.java`：`System.out.println("java2jni java.library.path is: …"); System.loadLibrary("zkfv_tj")` —— **工具自动生成的 loader stub**。
- 同一 stub 模式出现在 `kus.java` → `System.loadLibrary("APSE_J")`（`libAPSE_J.so` 带同一 `java2jni` 水印，`GUID 7b931e66-…` / `1754884215.1595547`）。
- 装载 `zkfv_tj` 的 6 个类**各自声明了 `native` 方法**，构成该库的 JNI 面（17 个）：`DTFacadeSec.initApdid(Context, APICallback)`、`ToygerFaceService.{handleCaptureCompleted, handleInfoReady, processImage}`、`FaceBlobManagerJson.generateBlob(×2)`、`LogUtils.{get, init, save}`、`faceverify.w.{processDepthInfo, processFrame(×3), processSensorData}`、`faceverify.y.{b(byte[]), a(int), a(byte[])}`。
- 全库检索这些方法名与签名（`scanPackage`/`methodToNative`/`(Landroid/content/Context;)Z` 等）**0 命中** → 名字/签名运行时解密。**【观察】**

**推断**
1. `java2jni` 是支付宝内部「Java → native」AOT 转换器：把选定 Java 类编译成 C++/native 代码并 `RegisterNatives` 注册，用于**抗反编译**（`.java` 逻辑在 dex 里只剩 `native` 声明）。
2. `zkfv_tj` 承载 **DTF 人脸 SDK** 中"blob 生成 / 帧处理 / 日志落盘 / apdid 初始化"等较敏感逻辑的 native 实现；`initApdid` 说明它还负责向支付宝 apdid 体系取设备令牌。
3. 它不是检测器：没有检测名单、没有 `/proc` 扫描串、没有 frida/xposed 常量；`dl_iterate_phdr` 是 JNI/libstdc++ 运行时的常规用法（java2jni 运行时要定位自身模块）。

**未知**：注册表解密算法与密钥（`init_array[0]` 对 8 字节常量做逐字节求和得校验值，见 `symbols/zkfv_tj_disasm.txt`，但未见完整解密流程）；`JNI_OnLoad` 内 0x42–0x55 的 opcode 风格比较链是否为"转换后字节码解释器"，需动态验证。

### 5.2 `libsgmain.so` 系列 —— 段表破坏的机制与还原

**观察**
- 5 个真实 ELF（`sgmainso-6.6.230702`、`sgmiddletierso-6.6.230702`、`sgmiscso-6.5.14625633`、`sgnocaptchaso-6.5.14625633`、`sgsecuritybodyso-6.6.230702`）的节头表被"擦除"：`sh_name=0`（所有节名丢失）、`sh_addr=sh_offset=0xffffffffffffffff`、`sh_size=0x10`、`DF_1_PIE=0`；只有第 4 项（STRTAB）保留 `sh_offset=0x3e18`。
- 程序头完好：2×`PT_LOAD`（`R E` + `RW`）、`PT_DYNAMIC`、2×`PT_NOTE`、`GNU_EH_FRAME`、`GNU_STACK(RW)`、`GNU_RELRO`。`llvm-readelf -l` 正常，`-S` 报 `invalid sh_entsize`/`offset … greater than file size`。
- 因此 **Android linker 可正常加载**（只用 program headers），而 IDA/Ghidra/objdump 依赖节表会失败 —— 这就是该保护的全部目的（反静态分析，不是加密）。

**还原方法（本轮已实现并验证）**
1. 用 `PT_LOAD` 反推 `.text`/`.rodata`/`.data`/`.bss`（按 `p_flags` 与 `memsz-filesz` 切分）；
2. 用 `PT_DYNAMIC` 的 `DT_HASH/DT_GNU_HASH/DT_SYMTAB/DT_STRTAB/DT_VERSYM/DT_VERNEED/DT_RELA/JMPREL` 反推各动态表的位置与大小（`DT_RELASZ/PLTRELSZ/STRSZ` 给长度）；
3. 追加新的 `.shstrtab` 与节头表，改写 `e_shoff/e_shnum/e_shstrndx`；
4. 因原始 `st_shndx` 指向已不存在的旧编号，按符号地址区间重写 `st_shndx`。

产物：`scan/native/unpacked/libsg*so-*.shdr-repaired.so`（各 +932 B）。验证：`llvm-readelf -S` **0 error**，`llvm-objdump -d --start-address=0x20bc0` 正常反汇编出 `adrp/add/b` 序列。**【观察+已复现】**

**可见 JNI 符号**：5 个 sg* ELF 均导出 `JNI_OnLoad`，**无 `Java_*`**（全部走 `RegisterNatives`，且表不在明文区——检索 `registerNatives` 目标名 0 命中）。导出函数数：510/101/55/46/86 条 dynsym 中定义函数 108/5/2/2/10。`DT_NEEDED` 仅平台库（`liblog/libz/libc/libm/libdl`，middletier/securitybody 另含 `libstdc++`）。

**内部嵌套**：明文名 `libsg*.so` 是**签名迷你 APK**（§3.1），内含 `classes.dex` + `.ucb.so` 加密体；`.version.so` 是 `6.6.230702` 文本；插件清单给出依赖图（`main:6.6.0; middletier:6.6.0; securitybody:6.6.0; misc:6.5.0; nocaptcha:6.5.0`）→ **SG 是"按插件粒度分发 + 双版本并存（6.6 主体 / 6.5 附加）"的结构**。**【观察】**

### 5.3 `libsafechat.so`（安恒信息 DBAPPSecurity）—— **纯加解密 SDK，无环境检测**

**观察**
- 3,698,232 B，`Linker: LLD 20.0.0` + `Android (13065274, based on r547379) clang 20.0.0`（**NDK r29**），`DT_NEEDED` 仅 `liblog/libm/libdl/libc`。
- **唯一保留 `.symtab`(3,623 条，1,306 个函数) + 全套 DWARF（2.88 MB）**；`.debug_line` 文件表暴露出源码结构：
  - `src/main/jni/safechat.c`、`encrypt.c`、`cryptAPI.c`、`safeutil.c`、`sm4.c`
  - `src/main/jni/inc/{define.h, encrypt.h, cryptAPI.h, funcuntil.c, log.c, logh.c, pcnative.c, FThread.c, safeutil.h}`
  - wolfSSL 头：`inc/wolfssl/wolfcrypt/{types,rsa,md5,coding,random,sp_int}.h`
  - 构建机路径并存：`C:/Users/Administrator/AppData/Local/Android/Sdk/ndk/29.0.13113456/...`（Windows）与 `…/darwin-x86_64/sysroot/…`（macOS）
- JNI 入口 20 个：`encryptMsg/decryptMsg`、`encryptFileHelper{,New,Test}`、`decryptFileHelper{,New,Test}`、`encrypt/decryptBufferHelper`、`encryptStreamHelper/decryptStreamHelper`、`encryptKey/encryptKeys/encryptKeyData`、`getEncryptionAttributeHelper`、**`setVoipKey`/`releaseVoipKey`**、`getNonce`、`domainName`、`dbappsecurityLg`、`stringFromJNI`、`OpenRDemo`、`test`。
- 密码学证据：`wolfCrypt_Init`、`wc_AesGcmEncrypt`、`wc_RsaPublicEncrypt`、`ChachaAEADEncrypt`、`DoTls13HandShakeMsgType`、`FIPS module in DEGRADED mode`、`Hash_DRBG_Instantiate`、`/system/etc/security/cacerts`、`/dev/crypto`、`/dev/urandom`；SM4 源码在位。
- **检测项检索结果：0 命中**。全库 ASCII/UTF-16 串（6,259 条 DWARF 字符串 + 3,623 条符号）中 `frida`/`gum`/`xposed`/`magisk`/`riru`/`substrate`/`ptrace`/`TracerPid`/`qemu`/`busybox`/`/system/bin/su` 全部为 0；`root` 子串命中全部来自 `…/sysroot/usr/include/…` 编译路径。
- 唯一 `su` 字节命中 3 处（0x248938/0x2790e9/0x28b9a3）经上下文核对为指令立即数/字符串片段，非路径。

**推断**：`libsafechat` = 安恒「安全通讯」SDK 的 Android 侧，职责是**消息/文件/流的对称+非对称加密、会话密钥（含 VOIP）托管、密钥属性查询**；`domainName` 疑似许可证/域名绑定校验，`dbappsecurityLg` 为日志通道。它**不承担环境风控**（风控在 `libfacedevice`/`libsafeguard`/`libcrashsdk`/SG）。**【推断】**

**未知**：`domainName(byte[], ResultHolder)` 的入参语义（是否含授权域名）、`Test`/`OpenRDemo` 是否为遗留调试入口（均在导出表内，**建议动态确认是否可被任意调用**）。

### 5.4 `libfacedevice.so`（Zoloz 安全设备）+ `libtoyger*`（人脸算法）—— 检测名单与 JNI 对应

**JNI 对应（Java 声明 = native 接口规范）**
- `libfacedevice.so`：0 个 `Java_*`、0 个明文 RegisterNatives 表 → 接口由 `face.security.device.api.FaceSecDevice` 定义，共 17 个 native：`initExFirstRaw/initExSecondRaw(Context)`、`getSessionRaw/getSessionIdRaw/getBizSessionRaw(String)`、`gsRaw(String)`、`ascRaw(Activity)`、`mpRaw/otiRaw(Context)`、`lpRaw(int,String)`、`lxRaw()`、`reportUserDataRaw(String,String)`、`setOptionsRaw(Context,Map)`、`getVersionRaw()`、`reserved0/reserved1()`。
- `libtoyger.so`：21 个 `Java_*`（`com.alipay.zoloz.toyger.algorithm.*`）。
- `libdtftoyger.so`：25 个明文 RegisterNatives（类 `com.dtf.toyger.base.*`），含 `processImage`/`init`/`config`/`allocDepthFrameData`/`allocIRFrameData`；符号带自定义版本命名空间（`@@ADOPLYERX`）。

**检测名单（完整提取，偏移为文件内偏移）**

| 类别 | 条目（`libfacedevice.so`） |
|---|---|
| Frida / 注入线程 | 0x1b9d4a `gmain`、0x1b9d50 `gum-js-loop`、0x1b9d5c `pool-frida`、0x1b9d74 `frida-agent`、0x1b9d67 `gdbus`、0x1b9d6d `zposed` |
| Hook 框架库黑名单 | 0x1b9d80 `substrate`、0x1b9d8a `libriru_edxp.so`、0x1b9d9a `libsandhook.edxp.so`、0x1b9dae `libwhale.edxp.so`、0x1b9dbf `libxposed_art.so`、0x1b9dd0 `edxp.jar`、0x1b9dd9 `fasthook`、0x1b9de2 `libfakeloc_initzygote.so`、0x1b9dfb `sandhook`、0x1b9e04 `libsubstrate.so`、0x1b9e14 `libiohook.so`、0x1b9e21 `libepic.so`、0x1b9e2c `libepic64.so`、0x1b9e39 `libexp824.so`、0x1b9e46 `libexp82464.so`、0x1b9e55 `libexposed.so`、0x1b9e63 `liblspd.so`、0x1b9e6e `libriru.so`、0x1b9cd4 `XposedBridge.jar` |
| Root/Magisk 系 | 0x1b6fa3 `topjohnwu`、0x1b6fad `me.weishu.kernelsu`、0x1b6fc0 `KernelSU`、0x1b6fc9 `me.bmax.apatch`、0x1b6fd8 `APatch`、0x1b6fdf `io.github.huskydg.magisk`、0x1b6ff8 `Kitsune Mas…`、0x1b7004 `com.rifsxd.ksunext`、0x1b7017 `KernelSu-Next`、0x1b7025 `com.sukisu.ultra`、0x1b7036 `Sukisu`、0x1b703d `me.garfieldhan.apatch.next`、0x1b8740 `Apatch`、0x1b8747 `kernelSu`、0x1b8750 `shamiko`、0x1b8758 `zygisk_lsposed`、0x1b8767 `zygisk` |
| SU/二进制路径 | 0x1ba001 `/system/app/Superuser.apk`、0x1ba01b `/system/bin/su`、0x1ba02a `/system/xbin/su`、0x1ba03a `/data/local/xbin/su`、0x1ba04e `/data/local/bin/su`、0x1ba061 `/system/sd/xbin/su`、0x1ba074 `/system/bin/failsafe/su`、0x1ba08c `/data/local/su`、0x1ba09b `/su/bin/su`、0x1b8430 `/system/app/Kinguser.apk`、0x1b8449 `/data/local/tmp/su`、0x1b8473 `/dev/com.koushikdutta.superuser.daemon/`、0x1b84ab `/system/etc/init.d/99SuperSUDaemon`、0x1b8552 `/data/adb/ksu`、0x1b8560 `/data/adb/ksud`、0x1b856f `/debug_ramdisk/su`、0x1b8581 `/debug_ramdisk/shamiko/module.prop`、0x1b85a4 `/system/lib64/libzygisk_loader.so`、0x1b85c6 `/system/lib64/libzygisk.so`；busybox 15 条（0x1b85e1–0x1b86f9） |
| 虚拟摄像头/改机 | 0x1b6dbd `com.xianyu.gaotong`、0x1b6e28 `virtual.camera.app`、0x1b6e3b `Vcamera`、0x1b6e43 `com.example.vcam`、0x1b6e54 `VCAM`、0x1b6e59 `com.wangyiheng.vcamsx`、0x1b6e6f `VCAMSX`、0x1b6e76 `com.telegram.a1064`、0x1b6e89 `com.pedia.vcamsx`、0x1b6e9a `VCAMpedia`、0x1b6ea4 `com.paint.yssh`、0x1b6f3b `com.variable.apkhook`、0x1b6f79 `com.tsng.hidemyapplist`、0x1b6f1a `com.yztc.studio.plugin` |
| 检测工具 App | 0x1b708a `icu.nullptr.nativetest`、0x1b70ab `io.github.vvb2060.mahoshojo`(Momo)、0x1b70cc `com.zhenxi.hunter`(Hunter)、0x1b70e5 `io.github.vvb2060.keyattestation.AppApplication`、0x1b7123 `com.byxiaorun.detector`(Ruru)、0x1b7064 `de.robv.android.xposed.installer` |
| 模拟器 | Nox：0x1b9549 `/data/data/com.bignox.app.store.hd`…0x1b95c0 `/system/bin/noxspeedup`、`/system/bin/nox-prop`；MEmu/Microvirt：0x1b9600–0x1b97db（`/system/bin/microvirt-prop`、`nemuVM-*`、`/sys/module/nemuguest`、`mumu.config`）；AndroVM：0x1b9814–0x1b982d；BlueStacks：0x1b98a5/0x1b98de；翻译层：0x1b9913 `ro.dalvik.vm.native.bridge`、0x1b992e `libnb.so`、0x1b9937 `libhoudini.so`、0x1b9945 `libntb.so`；`ro.kernel.qemu` 0x1b69bc |
| 启动完整性/属性 | `ro.boot.flash.locked` 0x1b6a22、`ro.boot.vbmeta.device_state` 0x1b6a37、`ro.boot.verifiedbootstate` 0x1b6a53、`ro.boot.vbmeta.digest` 0x1b881f、`sys.oem_unlock_allowed` 0x1b8876、`ro.adb.secure` 0x1b69cb、`ro.secure` 0x1b69d9、`ro.build.display.id` 0x1b880b、`bootKeyHex` 0x1b88b9、`securityLevel` 0x1b88c4、`deviceLocked` 0x1b88d2、`verifiedBootState` 0x1b88df |
| 调试/注入/代理 | `TracerPid:` 0x1b90ce、`/proc/self/status` 0x1b90bc、`/proc/self/maps` 0x1b762d、`/proc/self/smaps` 0x1b9ce5、`/proc/%d/maps` 0x1b89b5、`/proc/net/unix` 0x1b89a6、`/proc/net/tcp{,6}` 0x1b6a05/0x1b6a13、`/proc/self/mountinfo` 0x1b8a6b、`/proc/self/mem` 0x1b8f9e、`/proc/self/pagemap` 0x1b8fad、`http_proxy` 0x1b698d、`http.proxyHost` 0x1b9fb6、`127.0.0.1` 0x1b90d9、`pm list packages -s/-3` 0x1b718f/0x1b71a3、`which su` 0x1b89fe、`service list` 0x1b8c0a、`/system/bin/screencap` 0x1b8f55、`/system/bin/screenrecord` 0x1b8f6b |
| 调用栈黑名单 | `com.android.internal.os.ZygoteInit.main` 0x1b7adc、`java.lang.reflect.Method.invoke` 0x1b7b28、`android.app.Activity.performCreate` 0x1b7bf9、`android.app.Instrumentation` 0x1b7bdd、`android.os.Looper.loop` 0x1b7b68、`com.alipay.zoloz.toyger.SgomInfoManager.updateSgomInfo` 0x1b7cb8、`com.dtf.face.security.SecurityExt` 0x1b7cef |
| Hook 函数名监控 | 0x1b903e `popen`、0x1b9012 `syscall`、0x1b901a `access`、0x1b9021 `fopen`、0x1b902d `faccessat`、0x1b9037 `openat`、0x1b8fe6 `clock_gettime`、0x1b8ff4 `gettimeofday`、0x1b9001 `ftime`、0x1b9007 `clock`、0x1b900d `rand`（**被 hook 时的时间/随机源篡改检测**）；`libsecuritydevice.so` 0x1b9088、`libutils.so` 0x1b909d |
| 上报字段/结构 | 0x1b8e50 `UploadDeviceData`、0x1b8e61 `ABSENT,ABSENT`、混淆类 `N16NSSecurityDevice{6aabbcc,7BaseEnv,8eeccaa11,9hhccxz13d,9hhpp113fx,10rrnnaajada,10vvada1aq43}E` |

**【推断】** 该库是支付宝 Zoloz「设备安全/环境可信度」模块 + IM dtf 定制（`com.dtf.face.security.SecurityExt` 出现在其调用栈黑名单中，说明它同时知道宿主的类名）；检测结果通过 `UploadDeviceData` 结构上报，供人脸风控评分。

### 5.5 `libdalvikhack.so` —— DalvikUtils 能力表（9 个 RegisterNatives）

| native 方法 | 签名 | 实现地址 |
|---|---|---|
| `setClassVerifyModeNative` | `(I)Z` | 0x1558 |
| `getClassVerifyModeNative` | `()I` | 0x158c |
| `setDexOptModeNative` | `(I)Z` | 0x15bc |
| `getDexOptModeNative` | `()I` | 0x15f0 |
| `disableJitCompilationNative` | `()Z` | 0x1620 |
| `dvmJdwpStartupNative` | `(S)Z` | 0x1660 |
| `bootClassPathNative` | `()Ljava/lang/String;` | 0x1694 |
| `addBootClassPathNative` | `([Ljava/lang/String;[I)Z` | 0x16c0 |
| `nativeInit` | `()Z` | 0x1808 |

- 导入表极小（21 项）：`dlopen`、`dlsym`、`__android_log_print`、`str*`、`malloc` —— **无 ptrace、无 execve、无文件写入**。**【观察】**
- 字符串含 `com/taobao/android/runtime/DalvikUtils`、`libdvm.so`、`_Z14dvmJdwpStartup…`。
- **判定**：Dalvik 时代的**运行时改造/热修复基础设施**（类校验模式、dexopt 模式、JIT 开关、boot classpath 注入、JDWP 启动）。在 ART-only 环境（本包 `android_api=21+`）中除 `nativeInit` 外的能力大多**降级为空实现或返回失败**。**【推断】** 注意 `disableJitCompilationNative` 与 `addBootClassPathNative` 若在 ART 上仍可用，属"可被滥用"的高价值接口，建议动态确认。

### 5.6 `libsafeguard.so` + `libbytehook.so` + `libuc_bhook_jni.so`（Hook 检测与 Hook 框架并存）

| 库 | 角色 | 关键证据 |
|---|---|---|
| `libsafeguard.so`(1.8 MB) | IM DLP/JSAPI 防护 + **inline hook 检测** | `Java_com_alibaba_imclient_safeguard_*`(6)、`DT_NEEDED=libbytehook.so`、`antiStrategyJsapiHookCheck`@0x1769b0、`/proc/self/maps`、`/proc/self/fd/`、**`_ZN8imclient9safeguard11HookScanner10InlineHook26GetLibTextSectionCrcInFileEPKcE`**、`…HookScanner…GetLibTextSection…`(shared_ptr) → 对已加载库的 `.text` 段做 CRC 比对以发现 inline hook；平台串 `https://n.<host>/`、`https://h5.<host>/`、`pre-n`/`pre-h5` |
| `libbytehook.so`(42 KB) | ByteHook（字节开源 PLT/GOT hook 框架，被阿里改造） | 14 个 `bytehook_*` API（`init/hook_all/hook_partial/hook_single/unhook/get_prev_func/add_dlopen_callback/get_mode/pop_stack/set_debug`）、`hook chain: del func, GOT %lx`、`libbytehook.so`；2 个 RegisterNatives(`nativeInit(IZ)I`, `nativeSetDebug(Z)V`)；正文依赖 `liblog/libm/libdl/libc` |
| `libuc_bhook_jni.so`(538 KB) | UC 的 GOT hook + 流量拦截 JNI | 13 个 RegisterNatives（`nativeHookTraffic`/`nativeUnhookTraffic`/`nativeAddUnhookTrafficLibraryName` + 回调签名），`com/uc/hook/TrafficHook`、`com/bytedance/android/bytehook/ByteHookMod`、`hook cfi OK/NOSYM`、`hook chain: manual REPLACE. GOT %lx: %lx -> %lx` |

**判读**：同一 App 内"自己 hook（bytehook/uc_bhook）"与"检测别人 hook（safeguard HookScanner / facedevice 名单 / crashsdk `/libsechook.so`）"并存；**safeguard 的 CRC 检测是 Frida/内联 hook 落地时最需要绕过的点**（它按库粒度校验 .text，`libart.so`、`libc.so`、自身库均在扫描面内）。**【推断】**

### 5.7 其他值得记录的专题（简）

- **`libalpha.so`（93 KB）**：导出 `dt_alpha_{start,stop}_discovery`、`dt_alpha_send_data`、`dt_alpha_set_callback_obj`、`dt_alpha_is_debug`、`dt_alpha_set_debug`、`dt_alpha_android_trace` + 读 `/proc/self/status` → **IM的"Alpha"远程调试/追踪通道**（Java 侧 `com.alibaba.android.imclient.alpha.AlphaManager`）。属开发者能力面，**建议与 task-3 的 Doraemon/DevSetting 门控一起评估**。**【观察+推断】**
- **`libgrtn.so` / `libjingle_peerconnection_so.so`**：RTC；jingle 导出 398 个 `Java_org_webrtc_mozi_*`（阿里 Mozi 分支），含 `8.8.8.8`、`ftp://%s:%s@%s`（ffmpeg 遗留）、`portal-hz.mcs.<host>`。
- **`libgaea.so`（9.2 MB）**：网络栈总入口，内置完整备用端点表（§6.1），12 个长十六进制常量均为工具链 commit hash（非密钥）。
- **`libXcdnEngine.so`**：`xpis-xcdn.youku.com` / `pre-xpis-xcdn.youku.com`；5 个 RegisterNatives。
- **`libcrashsdk.so`**：25 个 RegisterNatives；`ptrace`(0x18f2)、`/libsechook.so`、`has root: %s`、`(default root)`、`/proc/self/maps`、`/proc/%d/{comm,cmdline,task/%d/comm}`、`/proc/cpuinfo` → **崩溃捕获 + root/hook 环境探测**（修正既往"仅崩溃"结论）。
- **`libpixelai.so`**：`cat /proc/cpuinfo | grep "model name"`、`src/submodule/FaceDetection/src/{face_3d,face_ar,face_alignment,face_attribute}.cpp` → 阿里人脸检测/属性引擎（供IM人脸场景）。
- **`libdecode100380.so`**：42 个 `Java_com_alipay_ma_decode_MaDecode_*` + `visualead::*`（扫码/二维码解码），4 个 init_array。
- **`libAMapSDK_MAP_v8_1_0.so`**：125 个 `Java_com_autonavi_base_*`、`m5.amap.com`、`mpsapi.amap.com`、`gitlab.alibaba-inc.com`、内网 `10.65.64.70`。

---

## 6. IOC：URL / 域名 / IP / 协议指纹 / 常量 / 证书

> 全量：`re/base_apk3/scan/native/urls.tsv`（911 URL + 1,661 域名 + 54 IP）、`pem_blocks.txt`（155 段 PEM 头）、`hex_constants.tsv`（301 条）。

### 6.1 协议指纹（native 侧最独特的部分，来自 `libgaea.so`）

```
quic://quic.<host>:443 | quic-short | quic-short-pre | backup.quic | local.<host>:6121
lws://lws.<host>:443?sni=dk | lws-pre | lws-short-pre | lws-eos | lws-desktop | lws-satellite
lws://<IP>:443?sni=dk&rm={na610,na620,sg52,os30,us44,us68}       ← 硬编码 IP+区域码备份表
tls://tls-{pre,eos,short-pre,desktop}.<host>:443?sni=...
ztna://accelerate.ztna-<host>:8081 | pre-accelerate.ztna-<host>:8081
udp://121.89.233.47:443?sni=backup&pub-key=741cf40d…9103        ← backup 通道信任参数
http://backup.http.<host>:80?sni=backup&pub-key=…
lws://127.0.0.1:443                                             ← 本机代理/本地回环
```

硬编码 IP 共 35 条（其中 34 个公网/内网地址 + `127.0.0.1`，**全部在 `libgaea.so`**），代表性网段：`59.82.x`（阿里华东）、`106.11.x`/`203.119.x`（阿里 CDN/国际）、`47.246.x`（新加坡/海外）、`161.117.x`（阿里云国际）、`121.89.x`/`39.x`（阿里云 ECS）。

### 6.2 预发/调试端点（native 独有性已交叉验证）

| 端点 | 库 | Java 侧 |
|---|---|---|
| `pre-workspace.<host>`、`pre-test-workspace.<host>`、`wsdebug.<host>` | `libapp.so`（Dart） | `wsdebug` 在 `CommonWebViewActivity` 有命中；两个 `pre-*` 在工作区域名逻辑中未直接命中（Dart 侧持有） |
| `lws-short-pre`、`tls-short-pre`、`quic-short-pre`、`pre-resolver`、`ztna pre-` | `libgaea.so` | `DevSettingActivity` 有 `lws://lws-short-pre-dr.<host>:443`（**带 `-dr` 后缀，native 侧没有**）→ 开发者面板可注入额外 pre 域 |
| `pre-n.<host>`、`pre-h5.<host>` | `libsafeguard.so` | — |
| `pre-xpis-xcdn.youku.com` | `libXcdnEngine.so` | — |
| `pre-accelerate.ztna-<host>` | `libgaea.so` | 未命中 → **native 独有** |

### 6.3 "native 独有"清单（Java 侧 grep 0 命中）

| 项 | 来源 | 说明 |
|---|---|---|
| `ztna://accelerate.ztna-<host>:8081` / `pre-accelerate.…` | `libgaea.so` | ZTNA 零信任加速通道，仅 native 端点表持有 |
| `xpis-xcdn.youku.com` / `pre-xpis-xcdn.youku.com` | `libXcdnEngine.so` | 优酷 P2P/CDN 引擎 |
| `/libsechook.so`、`has root: %s`、`(default root)` | `libcrashsdk.so` | root/hook 探测（C++ 侧） |
| `HookScanner::InlineHook::GetLibTextSectionCrcInFile` | `libsafeguard.so` | inline hook CRC 检测 |
| `dt_alpha_{start,stop}_discovery` / `dt_alpha_send_data` | `libalpha.so` | Alpha 调试通道 JNI |
| `741cf40d3bdd9ed1af96eed70621bd99f7d1e32a839f7c3b31eae9dcc8609103` | `libgaea.so` | **注意：Java 侧 `GaeaAladdinManager` 也拼同一 `pub-key`** → 非 native 独有（列入以示交叉验证） |

### 6.4 加密常量与证书/私钥

| 项 | 结论 |
|---|---|
| PEM 头 | 155 处：`libgaea.so` 135×`BEGIN CERTIFICATE`、`libBifrost.so` 7×`BEGIN CERTIFICATE`、`libcoap.so` 1×、`libjingle…`/`libistylepdfengine-jni` 各 1×`BEGIN PUBLIC KEY`、`libsafechat.so` 10 段（`RSA/DSA/EC/ENCRYPTED PRIVATE KEY`、`DH PARAMETERS`、`X509 CRL`、`PUBLIC KEY`、`RSA PUBLIC KEY`、`CERTIFICATE`） |
| 实际嵌入证书 | `libgaea.so` 的 135 段为**完整可解析 PEM**（含 body，`bodylen` 1,205–1,428 B，`-----END CERTIFICATE-----` 齐全）：GlobalSign Root CA/R2/R3、DigiCert Global Root (G2)/High Assurance EV Root、VeriSign Class 3 PCA-G5 等**公共根证书**（供自建 TLS 校验链内置 CA），**不含任何私有 CA 或私钥**。**【观察】** |
| `libsafechat.so` 的 PRIVATE KEY 头 | **全部是 wolfSSL 的 PEM/曲线格式表，不是硬编码私钥**。级联解析后的"body"实为后续符号名/参数表：`ENCRYPTED PRIVATE KEY`@0x17755 后接 `SECP224R1`、`B3312FA7E23EE7E4…`（P-224 曲线常数）；`RSA PRIVATE KEY`@0x182c8 后接 `-----BEGIN DSA PRIVATE KEY-----`（下一个串）；`DH PARAMETERS`@0x187c8 后接 `/SN=`、`1FFFFFFFF…`（FFDHE 模数）；`PRIVATE KEY`@0x18afa 后接 `/emailAddress=unknown`、`verify problem on certificate`；`RSA PUBLIC KEY`@0x1ae51 后接 `FFDHE_8192`、`peer did not return a certificate`；@0x1baab/0x1c371 的 `PUBLIC KEY`/`CERTIFICATE` **连 `-----END` 都没有**（纯格式前缀）。**【观察】** |
| 其他 | `libsafechat` 的 23 条长十六进制常量经上下文核对为 **NIST P-256 曲线参数**（`6B17D1F2E12C4247…`、`FFFFFFFF00000000FFFFFFFF…BCE6FAADA7179E84F3B9CAC2FC632551` 等）与 SM2 参数，属实现常数，非密钥；`libdatabase_sqlcrypto` 的 `0123456789ABCDEF…` 为 SQLCipher 测试向量。**【观察】** |

> **结论：152 个库中没有可用的硬编码私钥/对称密钥。** 唯一的"信任材料"是 `pub-key=741cf40d…`（32 字节，backup 通道参数，Java 侧同名常量）与 `libgaea` 内置的公共根证书集。

---

## 7. 未定性项与后续验证建议

| # | 项 | 现状 | 建议 |
|---|---|---|---|
| 1 | `libzkfv_tj.so` / `libAPSE_J.so` 的 native 方法名与签名解密 | 明文 0 命中；`init_array[0]` 仅见 8 字节校验和计算 | 动态：`frida -f <PKG>` hook `RegisterNatives`（`art::JNI::RegisterNatives` 或 libart 内 `RegisterNatives` 符号），打印 `JNINativeMethod*` 三元组；APSE_J 侧预期得到 `ScanAttack.{cy1..cy3,xp1..xp6,vir1,scanPackage,methodToNative,getInstance}` |
| 2 | `libWebViewCore_7z_uc_5.5.0.0.so`（7z）内部文件名 | 7z 编码头（37 B）需 LZMA 解头；本机无 7z 工具、无网络（pip 代理拒连） | 在有 7z/`py7zr` 的环境执行 `7z l`；或按 §8.4 用 Python `lzma` 解 `kEncodedHeader` |
| 3 | 5 个 sg* 的 `.ucb.so`（112/96 B）内容与解密路径 | 高熵桩，需插件 dex 侧算法 | 动态 dump 解密结果；或对 `libsgmainso` 的 `init_array[0]` 单函数做符号执行 |
| 4 | `libsafechat` `domainName()` / `Test` / `OpenRDemo` 语义 | 仅知入参为 `byte[]` + `ResultHolder` | 动态调用 + 抓返回值；核对 `DIJni` 调用方（`EncryptManage`） |
| 5 | `libdalvikhack` 在 ART 上的真实可用面 | 仅静态：`dvmJdwpStartup` 等 Dalvik 符号在 ART 不存在 | 动态 hook 9 个 native 方法，记录返回值/是否降级 |
| 6 | `libalpha.so` 的 Alpha 通道是否可被服务端开启 | 导出 JNI 齐全，`dt_alpha_set_debug` 可写 | 交叉 task-3：`AlphaManager` 的开关来源（本地/服务端） |
| 7 | `libpixelai`/`libmnnface` 的模型来源 | 仅代码，模型应在 assets/服务端 | 交叉 task-1（assets 模型清单） |
| 8 | `libykosboost_qs-1.0.1.so`(8 KB) | 仅 `Java_com_youku_osboost_*`；`Linker: LLD 11.0.5` | 低优先级；优酷 "OS boost" 性能组件 |

---

## 8. 复现命令

```bash
# 0) 环境（本机实测）
export PATH="/c/Users/ROG STRIX/AppData/Local/Microsoft/WinGet/Packages/BrechtSanders.WinLibs.POSIX.MSVCRT.LLVM_Microsoft.Winget.Source_8wekyb3d8bbwe/mingw64/bin:$PATH"
cd /d/Deepseek-Harness-workspace/re/base_apk3/scan/native

# 1) 全量 ELF 清点（152 行 elf_summary.tsv）
python scripts/survey.py

# 2) 重点库结构深挖 + JNINativeMethod 表发现
python scripts/dump.py            # 30 个重点库 -> symbols/<lib>.txt
python scripts/dump.py all        # 全部 152 个 -> jni_tables.tsv（33 库 / 808 方法）

# 3) 字符串 / IOC / 常量
python scripts/strings_scan.py    # interesting_strings.txt / urls.tsv / pem_hits.txt / strings/*
#    PEM 实体抽取与长常量上下文核对见 §6（脚本内联于本报告生成过程）

# 4) 段表还原（5 个 sg*），产物可被 IDA/Ghidra/objdump 直接识别
python scripts/repair_shdr.py libsgmainso-6.6.230702.so libsgmiddletierso-6.6.230702.so \
    libsgmiscso-6.5.14625633.so libsgnocaptchaso-6.5.14625633.so libsgsecuritybodyso-6.6.230702.so
llvm-readelf -S unpacked/libsgmainso-6.6.230702.shdr-repaired.so          # 期望：0 error
llvm-objdump -d --start-address=0x20bc0 unpacked/libsgmainso-6.6.230702.shdr-repaired.so

# 5) zkfv_tj 取证
python scripts/disasm.py libzkfv_tj.so --jni > symbols/zkfv_tj_disasm.txt

# 6) 原始 readelf 对照（段表破坏证据）
llvm-readelf -l libsgmainso-6.6.230702.so     # 正常
( cd /d/Deepseek-Harness-workspace/re/base_apk3/unpacked/native/lib/arm64-v8a && \
  llvm-readelf -S libsgmainso-6.6.230702.so ) # 报 invalid sh_name / offset 0xffff…ff

# 7) 交叉：native 库 -> Java 装载方
#    rg 'loadLibrary\("(zkfv_tj|safechat|facedevice|dalvikhack|APSE_J)"\)' java/sources
```

**产物索引**（均在 `re/base_apk3/scan/native/`）

| 文件 | 内容 |
|---|---|
| `elf_summary.tsv` | 152 行 × 30 列：类型/架构/strip/节表完整性/悬空依赖/build-id/JNI/init_array/工具链/flags |
| `symbols/<lib>.txt` | 30 个重点库：段表、`DT_*` 全量、全部导出/导入符号、`init_array` 项、JNINativeMethod 表 |
| `jni_tables.tsv` | 33 库 / 808 个 native 方法（名称+签名+地址） |
| `strings/<lib>.txt` | 26 个库的全量 ASCII/UTF-16 串（带偏移） |
| `interesting_strings.txt` | 9 类关键词 × 命中的串（32,072 行） |
| `urls.tsv` / `pem_hits.txt` / `pem_blocks.txt` / `hex_constants.tsv` / `string_stats.tsv` | IOC 与常量 |
| `deps_toolchain.tsv` / `embedded_containers.tsv` | 依赖闭合性与内嵌容器 |
| `unpacked/` | 7 个 ZIP 解包副本 + 5 个 `.shdr-repaired.so` |
| `scripts/*.py` | 全部解析/扫描/还原脚本（elfcore/survey/dump/strings_scan/disasm/repair_shdr） |
| `containers.md` | 非 ELF 14 个的结构说明与解包清单 |
