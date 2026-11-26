# 08 · Native 续攻（task-7）：zkfv/APSE_J RegisterNatives · .ucb/UC 容器 · SafeGuard CRC · Gaea TLS

- 目标（只读）：`re/base_apk3/unpacked/native/lib/arm64-v8a/`、`re/base_apk3/java/sources/`
- 承接：`re/base_apk3/analysis/04-native.md`（§7 未解项 #1/#2/#3 + 安全栈结论）
- 本轮新产物：`re/base_apk3/scan/native/zkfv_jni.tsv`、`ucb_notes.md`、`safeguard_crc.md`；新脚本 `scripts/{deep,pltmap,tlsmap,jev,emu_jni}.py`
- 标注：**【观察】**=可复现、**【推断】**=有依据的归因、**【未知】**=本轮未拿下

---

## 0. 结论摘要

| # | 目标 | 结论 | 状态 |
|---|---|---|---|
| ① | `libzkfv_tj.so` RegisterNatives | **表结构全解**：`.data.rel.ro` 里 6 条类描述符（`{className*, JNINativeMethod*, nMethods}`，stride 24）→ 6 个 methods 数组 → **17 个 (name, sig, fnPtr)**，**fnPtr 全部是函数入口**（`sub sp`/`stp x19..x30` 标准序言）。名字/签名在 `.bss` 运行时填充，**用"长度一致性"从 Java 声明反解得 17/17 全部唯一匹配**（含 79/83/120/122 这类长签名逐字符核对） | ✅ 拿下（附 1 处 2 选 1 歧义） |
| ② | `libAPSE_J.so` 同类表 | **同构**（`[desc+8]=methods, [desc+0x10]=count`，RegisterNatives 调用点 2 处）；扫出 33 条候选描述符，最大类 13 个方法。方法名为 1 字符（混淆），长度不足以唯一匹配 → 只给**结构+fnPtr**，名字标未知 | ◐ 结构拿下 |
| ③ | `.ucb.so` ×3 | **定长加密体**：112/96/96 B，**全部 16 字节整数倍**，熵 6.17–6.57，无 ELF/ZIP/7z/DER 魔数；与外层迷你 APK 内同名条目**逐字节相同** → 随插件分发的加密配置，解密逻辑在 `classes.dex`（Java 层） | ✅ 定性，明文未知 |
| ④ | `libWebViewCore_7z_uc_5.5.0.0.so` | **标准 7z（v0.4）**，`nextHeader` = 37 B 的 **kEncodedHeader**；全包 4 段熵均 **8.00**、`\x7fELF`/`PK` 0 命中 → 真压缩、不可 carve；本机无 7z/py7zr 且 pip 代理拒连 → 未解内部清单 | ◐ 定性 |
| ⑤ | `HookScanner::InlineHook::GetLibTextSectionCrcInFile` | **自比对模型**：磁盘 `.text` 摘要 vs 内存 `.text` 摘要（不需要服务端基准）；覆盖 **8 个库**（不含 `libart.so`）；命中后**只上报**（`integrity_tag/hash_ver/hash_sha256`），不本地退出 | ✅ 拿下 |
| ⑥ | `libgaea` / `liblsquic` TLS | gaea **静态内嵌 OpenSSL**（1750 个 openssl 类符号、9180 个定义符号），`lsquic`/`xquic` **零 TLS 符号** → TLS 全部由 gaea 承担；存在应用层开关 `Setting::set_ssl_verify_disabled(bool)` / `set_tls_verify_host(string)`（**已导出，可按名 hook**）+ 内置 135 张公共根证书；**未发现 SPKI/证书 pin 常量** | ✅ 拿下（pin 为"未见"，非"不存在"） |

---

## 1. ① `libzkfv_tj.so` 的 RegisterNatives 表（静态重建）

### 1.1 方法：从调用点反向定位表

`JNI_OnLoad`（`dynsym` 值 `0x3ecc4`）经混淆器做了**控制流扁平化**（`mov w8,#imm; b 0x3ed0c` 的 dispatcher），直接线性反汇编会走偏。可靠路径是**找 `JNIEnv->RegisterNatives` 的 vtable 调用**：

- `JNIEnv` 函数表索引 **215**（偏移 `0x6b8`）= `RegisterNatives`；扫描 `ldr Xa,[Xb]; ldr Xc,[Xa,#0x6b8]; blr Xc` 三连（脚本 `deep.find_vtable_calls`）→ **唯一命中 `0x3efe0`（call `0x3efec`）**。**【观察】**

调用点上下文（`0x3efd8`）：

```asm
ldr  x8, [x0]              ; x0 = JNIEnv*
ldp  x1, x9, [x29,#-0xb0]  ; x1 = jclass, x9 = &desc
ldr  x8, [x8,#0x6b8]       ; RegisterNatives
ldr  x2, [x9,#8]           ; x2 = desc->methods
ldr  w3, [x9,#0x10]        ; x3 = desc->nMethods
blr  x8
```

结构定义由此确定：**`struct desc { const char* className; const JNINativeMethod* methods; int nMethods; }`（24 B）**。

再回溯到**填充 desc 的代码**（`0x3eec8`）：

```asm
ldur x0, [x29,#-0x58]      ; JNIEnv*
ldur x11,[x29,#-0xc0]      ; 类索引
adrp x10, #0x72000         ; ┐
mov  w9, #0x18             ; │ stride 24
ldr  x8, [x0]              ; │ env->vtable
add  x10, x10, #0x9a8      ; ┘ x10 = 0x729a8  ← 类描述符表基址
madd x9, x11, x9, x10      ; x9 = &desc[i]
ldr  x1, [x9]              ; x1 = desc[i].className
ldr  x8, [x8,#0x30]        ; FindClass
blr  x8                    ; → 得到 jclass
stur x0, [x29,#-0xb0]      ; 存 jclass
```

**类描述符表 = `0x729a8`（`.data.rel.ro`，6 条 × 24 B）**。**【观察】**

### 1.2 表内容（同一 `.data.rel.ro` 内，全部由 `R_AARCH64_RELATIVE` 静态给出）

```
desc[0] 0x729a8  className→0x785d6  methods→0x72a38  n=1
desc[1] 0x729c0  className→0x785f3  methods→0x72a50  n=3
desc[2] 0x729d8  className→0x7860f  methods→0x72a98  n=2
desc[3] 0x729f0  className→0x7863c  methods→0x72ac8  n=3
desc[4] 0x72a08  className→0x78667  methods→0x72b10  n=5
desc[5] 0x72a20  className→0x78674  methods→0x72b88  n=3
                                    合计 17 个方法
```

每个 methods 数组元素 = 24 B：`{name→.bss, signature→.bss, fnPtr→.text}`。**`fnPtr` 是静态可读的**，例如：

```
desc[0].methods[0]: name→0x78681  sig→0x7868b  fn=0x14634
desc[4].methods[1]: name→0x788c7  sig→0x788d4  fn=0x28c10
```

### 1.3 名字/签名的还原：**长度一致性反解**（本轮的关键手法）

名字/签名不是明文，也不是简单 XOR —— 它们在 `.bss`（`0x785d6..0x78a40`）由运行时解密填充，`.data.rel.ro` 只保存指向 `.bss` 的指针。本轮**没有**强行破译加密串（见 §1.5），而是利用一个更强的约束：

> **JNI 注册要求 name/sig 与 Java 侧 `native` 声明逐字一致**，而 `.bss` 里这些字符串是**紧凑排布、NUL 分隔**的 → `len(s[i]) = addr(s[i+1]) - addr(s[i]) - 1`，**长度可静态精确求出**；再用 Java 声明算出每个方法的 JNI 签名，**按 (name_len, sig_len) 二元组匹配**。

结果：**17/17 全部唯一匹配**（`scan/native/zkfv_jni.tsv` 全表）。关键校验点：

| 类（长度） | name_len / sig_len | 匹配到的签名 | 逐字符核对 |
|---|---|---|---|
| `com.dtf.face.api.DTFacadeSec`(28) | 9 / **79** | `(Landroid/content/Context;Lcom/dtf/face/network/APICallback;)Ljava/lang/String;` | 79 ✔ |
| `com.dtf.face.utils.LogUtils`(27) | 4/57, 4/21, 3/38 | `save(String,String,String)V` / `init(String)V` / `get(String)Object` | ✔✔✔ |
| `com.dtf.toyger.base.face.FaceBlobManagerJson`(44) | 12/**35**, 12/**32** | `generateBlob(List,Map)[B` / `generateBlob(Map)Map` | ✔✔ |
| `com.dtf.toyger.base.face.ToygerFaceService`(42) | 12/**63**, 15/**83**, 22/**35** | `processImage(List,TGDepthFrame)Z` / `handleInfoReady(TGFrame,ToygerFaceAttr)V` / `handleCaptureCompleted(int,List,Map)V` | ✔✔✔ |
| `faceverify.w`(12) | 17/22, 12/**120**, 16/**46**, 12/6, 12/**122** | `processSensorData(String)[B` / `processFrame(FaceInfo,FaceAttr,int,int,String,boolean,Map)[B` / `processDepthInfo(ToygerDepthInfo)[B` / `processFrame(byte[])[B` / `processFrame(FaceInfo,FaceAttr,String,boolean,Map)[B` | ✔✔✔✔✔ |
| `faceverify.y`(12) | 1/22, 1/6, 1/6 | `b(byte[])String` / `a(int)[B` / `a(byte[])[B` | ✔ / △ / △ |

**类名长度也可独立验证**：`28 / 27 / 44 / 42 / 12 / 12` 与 `DTFacadeSec / LogUtils / FaceBlobManagerJson / ToygerFaceService / faceverify.w / faceverify.y` 一一对应（无第二个候选）。

> △ = `faceverify.y` 的 `a(int)[B` 与 `a(byte[])[B` **签名长度都是 6**，仅靠长度无法区分这两个重载；TSV 中标 `confidence=medium`。不影响 fnPtr。

### 1.4 实现地址（可直接下断/反编译）

| 类 | 方法 | fn（=文件内 vaddr，load base 0） |
|---|---|---|
| `DTFacadeSec` | `initApdid` | **`0x14634`** |
| `LogUtils` | `save` / `init` / `get` | `0x14ebc` / `0x17274` / `0x1a19c` |
| `FaceBlobManagerJson` | `generateBlob(List,Map)` / `generateBlob(Map)` | `0x1ab2c` / `0x1f6dc` |
| `ToygerFaceService` | `processImage` / `handleInfoReady` / `handleCaptureCompleted` | `0x21ee0` / `0x265d8` / `0x26b74` |
| `faceverify.w` | `processSensorData` / `processFrame`(7 参) / `processDepthInfo` / `processFrame(byte[])` / `processFrame`(5 参) | `0x27468` / `0x28c10` / `0x292b8` / `0x296e8` / `0x29aec` |
| `faceverify.y` | `b` / `a` / `a` | `0x2bedc` / `0x2e05c` / `0x30c6c` |

**这 17 个地址都确认是函数入口**（序言 `sub sp,sp,#N` + `stp x19..x30` + 读全局；例：`0x14634: sub sp,sp,#0xd0 … add x29,sp,#0xc0; ldr w8,[x8,#0x10]`）。它们**不在 `.eh_frame` 的 FDE 起始表里**（生成代码未带 unwind 信息），所以按 FDE 找函数会漏 —— 是一个易踩的坑。**【观察】**

### 1.5 为什么没直接破出明文字符串（诚实的边界）

- 字符串池在 `.rodata 0x5b2f0–0x5e5d0`（13,024 B，2,608 个 NUL，熵 8.0 区段）→ **真加密**，不是可打印变换：ROT47、模 95 全 95 个位移、单字节 XOR 全 256 键 **均已试，0 有效命中**（`initApdid`/`(L`/`java/` 等探针全无）。
- **Unicorn 2.1.4 静态仿真已搭好**（`scripts/emu_jni.py`：映射 PT_LOAD、构造 JNIEnv/JavaVM 两层 vtable、实现 malloc/memcpy/strlen/strcmp/snprintf/syscall/fwrite 等 33 个导入、GOT 填桩）：`init_array` 10 个构造器 + `JNI_OnLoad` 共 **52 万条指令**执行完毕，`JNI_OnLoad` 返回 **`0x10006` = `JNI_VERSION_1_6`**（说明主流程走通），但**未触达任何 JNI 调用**（`FindClass/RegisterNatives` 计数均为 0），`.bss` 字符串区仍全 0。
- **判读**：`JNI_OnLoad` 本体的 dispatcher（`cmp w20,#0x42…0x5a` 的 opcode 二分派发 + 命中热点 `0x21cf0`/`0x271a4` 各 1.4–1.9 万次）= 一个**字节码解释器**；注册路径依赖解释器状态，静态仿真缺少它需要的输入（很可能就是 `.rodata` 里那段"加密池"= 字节码/数据）。**要继续静态推进，需要先把 dispatcher 的 opcode 语义表补出来**（约 30–60 个 opcode），属独立课题。
- **动态一步到位（推荐）**：Frida hook `RegisterNatives` 即可拿到 17 组 `(name, sig, fn)`，与本表互为交叉验证：
  ```javascript
  // Android 上 art 内部符号名随版本变化，稳妥做法是 hook JNIEnv 表项
  const sym = Module.findExportByName(null, 'RegisterNatives') // 不存在时用下面的方式
  // 方式 A：hook libart 的 RegisterNatives 实现（Module.enumerateSymbols 搜 'RegisterNatives'）
  // 方式 B：在 java2jni 的 lus.a() 之后，遍历 .bss 0x785d6 起 0x480 字节直接 dump 明文
  //         （模块基址 + 0x785d6 是本 lib 的固定偏移，见 §1.2）
  ```

```javascript
// 方式 B 的最小实现：libzkfv_tj.so 加载后，.bss 字符串区就是明文
const m = Process.findModuleByName('libzkfv_tj.so');
if (m) console.log(hexdump(m.base.add(0x785d6), { length: 0x480, ansi: false }));
// 期望看到：com.dtf.face.api.DTFacadeSec\0initApdid\0(Landroid/...;)Ljava/lang/String;\0...
```

> 该 dump 能**直接验证**本表的长度匹配结论，成本 1 行 Frida。

### 1.6 ② `libAPSE_J.so`（同一 `java2jni` 工具链，同构）

- 同一水印 `…|1754884215.1595547|java2jni-1.0.10.0-(20201217)|`，同一 `.comment`（Alipay clang 6.0.1 / Obfuscator build200917），**导入集合与调用点计数几乎逐项相同**（`syscall` 81、`memset` 47、`malloc` 30、`strerror` 30 …）→ 两者内嵌的是**同一份 java2jni 运行时**。
- `RegisterNatives` vtable 调用点 **2 处**：`0x89df0`、`0x1a8918`；后者上下文与 zkfv 完全同构（`ldr x2,[x23,#8]` / `ldr w3,[x23,#0x10]`）。
- 用同一 `desc` 结构扫描 `.data.rel.ro` → **33 条候选类描述符**，最大类 **13 个方法**（与 Java 侧 `ScanAttack` 的 13 个 native 完全同数：`cy1/cy2/cy3/getInstance/methodToNative/scanPackage/vir1/xp1..xp6`）。
- **但**：APSE_J 的方法名多为 **1 字符**（`a/b`…，混淆后的 apdid 内部类），长度无法唯一定位 → 本轮**只给结构与 fnPtr**，名字标【未知】。
- 若要闭环：同样用 §1.5 的方式 B dump 其 `.bss`（基址偏移需先按同法定位 `desc` 表，描述符里的 `className*` 就是 `.bss` 起点）。

---

## 2. ③④ 容器专题（详见 `scan/native/ucb_notes.md`）

| 对象 | 结论 |
|---|---|
| `libsgmainso.ucb.so` (112 B) / `libsgmiddletierso.ucb.so` (96 B) / `libsgsecuritybodyso.ucb.so` (96 B) | **定长加密配置体**。三者的长度**都是 16 的整数倍**（AES 分组无填充形态）；熵 6.17–6.57（非纯随机、非明文）；无 ELF/ZIP/7z/gzip/ASN.1 魔数；**与外层迷你 APK 内 `lib/arm64-v8a/` 同名条目逐字节相同** → 随 SG 插件分发的加密数据，解密在 `classes.dex`（Java 层）。明文/算法【未知】，需动态 dump 或 Java 侧逆向。 |
| `libWebViewCore_7z_uc_5.5.0.0.so` | **标准 7z v0.4**；`nextHeaderOffset=19,953,605 / size=37`，首字节 `0x17`=`kEncodedHeader`（头部被 LZMA 编码）；全包 4 段熵 **8.00/8.00/8.00/8.00**、`\x7fELF` 与 `PK` **0 命中** → 真压缩，不能 carve。本轮盲试 4 个起点 × 4 种 dict × 3 组 (lc,lp,pb) 的 raw-LZMA 解码均未命中（coder props 需按 `kFolder` 精确取）。**不是私有格式**；在任一有 `7z` 的机器上 `7z l` 即可。 |
| `libWebViewCore_7z_uc_jsi_255.so` | ZIP，8 条目（含 `libwebviewuc.so` 63.5 MB、`libjsi.so` 866 KB），`AndroidManifest` 与 `libfakedexuc.so` 同 CRC/同签名 → UC 的"占位身份 + 运行期装配"两件套。已解包到 `scan/native/unpacked/`。 |

---

## 3. ⑤ SafeGuard 的 inline-hook CRC 检测（详见 `scan/native/safeguard_crc.md`）

**要点**

1. **函数存在且被两处复用**：`imclient::safeguard::HookScanner::InlineHook::GetLibTextSectionCrcInFile(char const*)` 与 `imclient::safeguard::UpgradeSecurity::GetLibTextSectionCrcInFile(char const*)`（RTTI 串 `0x17ee10` / `0x181b60`；连同 `shared_ptr` deleter，说明返回堆上 buffer）。
2. **覆盖名单（8 个库）**：`libsafeguard.so, libc.so, liblog.so, libunwindstack.so, libjavacore.so, libopenjdkjvm.so, libopenjdk.so, libwebviewuc.so`（+ `libmocktest.so` 测试桩；`.rodata 0x1767c8–0x176893`，紧邻 `stat/lstat/fstat`）。**不含 `libart.so`**。
3. **基准来源 = 磁盘文件自身**（函数名 `…InFile` + 同区 `stat/fstat`/`open`）：内存 `.text` 摘要 vs 磁盘 `.text` 摘要的**自比对**，不需要服务端下发。改包（原始 .so 就带补丁）由另一路 `APK Sig Block 42`（v2/v3 签名块）负责。
4. **命中后只上报**：写入 `integrity_tag / hash_ver / hash_sha256`（`.rodata 0x1761b8–0x176205`，同区还有 `install_id(_key)`、`update_tag`、模块标签 `APLST/APKIF/PMDAT/DLPIM/DTLSPV3`、SDK 版本 `2.6.58`），经 `SafeGuardInterface$CppProxy.execCmd(Native)/execCmdV2Native` 回到 Java。**未见本地杀进程/退出**的成组调用 → 后果是**服务端可见**。
5. **绕过（首选）**：**不要改任何名单内库的 `.text`**。
   - Java 层 Frida hook 改的是 `libart.so`（不在名单）→ **天然不被这套 CRC 检出**；
   - 需要拦 `open/read/memcmp` 时用 **GOT/PLT 级 hook**（不改 `.text`）或经 `libbytehook.so`（不在名单）；
   - 直接过滤上报字段：hook `…CppProxy_execCmdV2Native`（6 个 `Java_*` 导出之一，可按名定位）或在 Java 侧 hook `SafeGuardInterface$CppProxy.execCmd*` 的返回值，把 `integrity_tag/hash_*` 摘掉；
   - **不要** patch `libsafeguard.so` 自身代码（它在名单内，自比对会命中）。

---

## 4. ⑥ Gaea / lsquic 的 TLS 验证与 pin 判定

### 4.1 TLS 栈归属**

| 库 | 定义的 openssl 类符号 | 结论 |
|---|---|---|
| `libgaea.so` | **1,750**（`SSL_*/X509_*/EVP_*/OPENSSL_*`，总定义符号 9,180） | **静态内嵌 OpenSSL**（无 `DT_NEEDED libssl.so`），TLS 全在这里 |
| `liblsquic.so` | **0** | 只做 QUIC 传输，TLS 由宿主（gaea）提供 → **分析 gaea 即可** |
| `libxquic.so` | **0** | 同上 |

### 4.2 验证链的真实调用点（用"模块内 PLT thunk → GOT → 符号"解析，`scripts/tlsmap.py`）

| 符号 | 调用点（vaddr） | 含义 |
|---|---|---|
| `SSL_set_verify` | `0x640b3c` | 设置验证模式/回调 |
| `SSL_CTX_set_verify_depth` | `0x63e3f4` | 链深限制 |
| `X509_VERIFY_PARAM_set1_host` | `0x63c630` | **主机名校验参数**（非"仅链校验"） |
| `X509_check_host` | `0x563828`, `0x662efc`, `0x663068` | 主机名匹配执行点 |
| `X509_digest` | `0x51b6dc` | 证书摘要（OpenSSL 内部用途） |
| `i2d_X509_PUBKEY` | `0x51ef34`, `0x555b84`, `0x555cd0`, `0x562f78` | SPKI 序列化（**注意：全部落在 OpenSSL 自身代码区，未发现应用层比对**） |
| `SSL_get_peer_certificate` | `0x62b460` | 取对端证书 |

> 这些地址都在 gaea 的 OpenSSL 区（`0x45xxxx–0x6xxxxx`），即"OpenSSL 自用"；**未发现 gaea 自己的代码去比较 SPKI 哈希**。配合 §4.4 的常量核查 → **没有应用层 pin 的证据**。

### 4.3 应用层开关（可 hook，且**已导出**）

```
0x3839d8  _ZN4gaea3lwp7Setting19set_tls_verify_hostERKNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEE
0x3839e0  _ZN4gaea3lwp7Setting23set_ssl_verify_disabledEb
0x248674  gaea::network::SniConfig::InitDefault()
0x248594  gaea::network::SniConfig::GetSniSuite(std::string const&, std::string*, unsigned*)
0x2488cc  gaea::network::SniConfig::AddSniSuite(std::string const&, std::string const&, unsigned const&)
0x945c08  SniConfig::sni_mapper_   0x945c10  SniConfig::sni_flag_
```

- `set_ssl_verify_disabled(bool)` 的存在说明**产品里本来就有"关闭证书校验"的开关**（预发/内测/自签环境用）——这是最干净的攻击面：不需要任何 patch，只要让它被调用/命中。
- `set_tls_verify_host(string)` 说明 hostname 校验的目标**是可编程设置**的（例如 backup 通道 `sni=backup`）。
- Java 侧检索 `set_ssl_verify_disabled|set_tls_verify_host|ssl_verify` **0 命中**（只有 OkHttp 自己的 `verifyHostName`）→ 开关由 **native 配置链**（`libGaeaConfigJni` / gaea 内部 setting）驱动，非 Java 直接调用。**【观察】**

### 4.4 有没有 pin？（结论：**未见**，非"不存在"）

- 全库**没有** SPKI/证书哈希形式的 pin 常量：`analysis/04-native.md` §6.4 已逐条核对 301 条长十六进制常量，命中项全是 **NDK 工具链 commit hash** 与 **P-256/SM2 曲线参数**；本轮再次确认 `libgaea` 的 12 条长常量同属此类。
- 只有 **135 段完整 PEM 公共根证书**（GlobalSign / DigiCert / VeriSign 等，`bodylen` 1,205–1,428 B，`-----END CERTIFICATE-----` 齐全）→ 这是**内置 CA bundle**（自建信任库），不是 pin 列表。
- `X509_VERIFY_PARAM_set1_host` + `X509_check_host` 的存在表明**至少做了 hostname 校验**（比"只验链"强）。
- **边界**：gaea 可能以"配置项"形式从服务端拉 pin 列表（`analysis/05-network-api.md` 的配置中心），静态看不到 → 标【未知】。

### 4.5 Native hook 方案（按可靠性排序）

```javascript
// ① 直接把验证模式压成 NONE（最低风险，符号已导出，可按名定位）
const base = Module.findBaseAddress('libgaea.so');
const setv = base.add(0x640b3c);            // SSL_set_verify 的模块内 thunk 调用点
// 更稳：hook 导出的实体
const SSL_set_verify = new NativeFunction(
    Module.findExportByName('libgaea.so', 'SSL_set_verify'), 'void', ['pointer','int','pointer']);
Interceptor.replace(Module.findExportByName('libgaea.so', 'SSL_set_verify'),
    new NativeCallback(function (ssl, mode, cb) { SSL_set_verify(ssl, 0 /*SSL_VERIFY_NONE*/, cb); },
    'void', ['pointer','int','pointer']));

// ② 让链校验恒过（连带自签/过期也能过）
Interceptor.replace(Module.findExportByName('libgaea.so', 'X509_verify_cert'),
    new NativeCallback(function (ctx) { return 1; }, 'int', ['pointer']));

// ③ 主机名恒过（只关心 pin/链的人可省）
Interceptor.replace(Module.findExportByName('libgaea.so', 'X509_check_host'),
    new NativeCallback(function () { return 1; }, 'int',
        ['pointer','pointer','size_t','unsigned int','pointer']));

// ④ 结果读取点兜底
Interceptor.replace(Module.findExportByName('libgaea.so', 'SSL_get_verify_result'),
    new NativeCallback(function () { return 0; /*X509_V_OK*/ }, 'long', ['pointer']));
```

**注意**：这样改的是 `libgaea.so` 的 `.text`；`libgaea` **不在** SafeGuard 的 8 库 CRC 名单里（§3），因此不会被 `InlineHook` 检出——这是本轮两个专题的**交叉结论**。
若走"配置优先"路线，可先尝试让 `Setting::set_ssl_verify_disabled(true)` 生效（`0x3839e0`，按名 hook 其调用者），那样完全不动 `.text`。

---

## 5. 未解项 / 下一步

| # | 项 | 现状 | 下一步 |
|---|---|---|---|
| 1 | `libzkfv_tj`/`libAPSE_J` 的加密串池明文 | 变换非 ROT47/Caesar/XOR 单键；Unicorn 仿真跑到 `JNI_OnLoad` 返回 `JNI_VERSION_1_6` 但未触达注册路径（缺 dispatcher 状态/字节码语义） | **首选**：Frida 加载后 dump `.bss`（`base+0x785d6`，0x480 B）；次选：补 dispatcher opcode 语义表再仿真 |
| 2 | `faceverify.y` 的 `a(int)` / `a(byte[])` 顺序 | 两者签名长度同为 6，长度法不可分 | 同上 dump `.bss` 即解 |
| 3 | `libAPSE_J` 33 条描述符的类名/方法名 | 名多为 1 字符，长度法失效 | dump 其 `.bss`（先按 §1.1 同法定位 desc 表，取 `desc->className` 指针即得起点） |
| 4 | 7z 内部文件清单 | 编码头 37 B 需按 `kFolder.props` 精确取 LZMA 参数 | 有 7z 的机器一条 `7z l`；或补全 7z 头解析器（本目录已给出结构路线） |
| 5 | `.ucb` 明文与算法 | 96/112 B 太短，静态不可验证 | hook 插件 `classes.dex` 的解密方法（Java 层）或 `libsg*so` 的 `init_array[0]` |
| 6 | gaea 是否有服务端下发的 pin 列表 | 静态无 pin 常量（只有 CA bundle + hostname 校验） | 交叉 `analysis/05-network-api.md` 的配置键；或动态 hook `X509_check_host`/`X509_verify_cert` 看是否被调用 |

---

## 6. 复现命令

```bash
export PATH="/c/Users/ROG STRIX/AppData/Local/Microsoft/WinGet/Packages/BrechtSanders.WinLibs.POSIX.MSVCRT.LLVM_Microsoft.Winget.Source_8wekyb3d8bbwe/mingw64/bin:$PATH"
cd /d/Deepseek-Harness-workspace/re/base_apk3/scan/native

# ① zkfv：定位 RegisterNatives 调用点（vtable 索引 215）
python - <<'PY'
import sys; sys.path.insert(0,'scripts')
from elfcore import ELF; import deep
e=ELF(deep.LIB+r'\libzkfv_tj.so')
print([(hex(a),hex(c)) for a,c in deep.find_vtable_calls(e,215)])   # → 0x3efe0
PY

# ① 类描述符表 + 方法表 + 名字/签名长度（生成 zkfv_jni.tsv 的同款逻辑）
python - <<'PY'
import sys; sys.path.insert(0,'scripts'); import jev, deep
LIB = r'D:\Deepseek-Harness-workspace\re\base_apk3\unpacked\native\lib\arm64-v8a'
for lib in ('libzkfv_tj.so','libAPSE_J.so'):
    e,descs,rel = jev.analyze(LIB + '\\' + lib)
    L = jev.lengths(descs, rel)
    print('==', lib, 'classes', len(descs))
    for d in descs:
        print(' ', hex(d['cls']), 'clslen', L.get(d['cls']), 'n', d['n'])
        for m in d['methods_list']:
            print('    name_len', L.get(m['name_addr']), 'sig_len', L.get(m['sig_addr']), 'fn', hex(m['fn']))
PY

# ① 仿真（已实现，本轮已跑到 JNI_OnLoad 返回）
python scripts/emu_jni.py libzkfv_tj.so - 20000000

# ③④ 容器
python - <<'PY'
import struct
z=open(r'D:\Deepseek-Harness-workspace\re\base_apk3\unpacked\native\lib\arm64-v8a\libWebViewCore_7z_uc_5.5.0.0.so','rb').read()
print(z[:6].hex(), struct.unpack_from('<QQI',z,12))
PY

# ⑤ SafeGuard：RTTI 函数名 / 覆盖名单 / 报告字段
python - <<'PY'
d=open(r'D:\Deepseek-Harness-workspace\re\base_apk3\unpacked\native\lib\arm64-v8a\libsafeguard.so','rb').read()
print(d[0x1761b8:0x176210].replace(b'\0',b'|').decode('latin-1'))
print(d[0x1767c8:0x1768a0].replace(b'\0',b'|').decode('latin-1'))
PY

# ⑥ gaea：模块内 PLT thunk → 符号 → 调用点
python - <<'PY'
import sys; sys.path.insert(0,'scripts')
from elfcore import ELF; import deep, tlsmap
want={'SSL_set_verify','X509_check_host','X509_verify_cert','X509_digest','i2d_X509_PUBKEY','X509_VERIFY_PARAM_set1_host'}
e=ELF(deep.LIB+r'\libgaea.so'); sm=tlsmap.stub_map(e,want)
for n,v in tlsmap.bl_to(e,sm).items(): print(n,[hex(x) for x in v])
PY
```
