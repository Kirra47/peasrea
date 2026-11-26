# 07 · 开锁：把"硬门控"变成可执行补丁

目标：`re/base_apk3/target.apk`（IM 8.2.2.1 专属版，`<PKG>`）。
前置：`analysis/03-security.md` 判定的 5 处"硬门控"。本轮把它们全部做成**指令级可执行**补丁，并把 Surgeon 的 id 表挖出来（Lead 指定的重点交付）。

证据口径同前：**〔观察〕**= 直接从 dex/smali/ELF 读出；**〔推断〕**= 语义推导；**〔未知〕**= 证据不足。

---

## 0. TL;DR

| 结论 | 内容 |
|---|---|
| **Surgeon 契约** | Lead 给的整体模型正确，但有 **2 处必须修正**（见 §1.2）：补丁文件是 `surgeon<i>.jar`（不是 `.dex`）；且 `SecurityChecker` 校验补丁签名时用的是**运行时 APK 自己的签名公钥** → 官方包上 patch 通道**不可用**，只有重签名后的包才可用。 |
| **id 表规模** | 全包 **31,430 个插桩类 / 583,595 个 (方法,id) 对 / 317,536 个不同 id**；本报告给出与门控相关的 **49 条**精确映射（§2），全量在 `tools/patches/data/`。 |
| **最省事的开锁** | 不是改 dex，而是 **Frida 注入一个合法 `ISurgeon` 实现**（`tools/patches/frida_isurgeon.js`）——因为每处门控的方法头都是 `if (InstrumentAPI.support($surgeonFlag, id)) { dispatch; return; }`，只要 `$surgeonFlag` 非空且 `support` 认这个 id，就走我们的返回值。**不需要改 dex、不需要重打包、不需要改签名。** |
| **必须改 dex 的话** | 两条指令就够：`ywm` 的字段初值 `false→true`；`Doraemon.getRunningMode()` 的 fallback `sget sMode` → `const/4 0x1`。`DevSettingActivity.onCreate` 的门控甚至可以不动（它第一个条件就是 `mode==1`）。 |
| **最大反作用** | 重签名会打断 SecurityGuard 的签名校验与全部 `signature` 级权限/共享 UID → 支付、人脸、扫码、推送等依赖服务端 `wua` 的能力大概率失效。补丁只对**研究设备 + 测试账号**有意义。 |

三条路线对比：

| 路线 | 改 dex | 重签名 | 触发条件 | 适用 |
|---|---|---|---|---|
| **A. Frida `ISurgeon` 代理** | 否 | 否 | 能 attach（spawn） | **首选**。官方包直接可用 |
| **B. Surgeon patch jar** | 否 | **是**（否则 `SecurityChecker` 拒签） | SP `_andfix_` 里要有 `baseVersion == versionName` | 需要"一次重签、后续无限热更" |
| **C. smali 补丁重打包** | 是 | 是 | 装即生效 | 要交付"一个改好的 APK"时用 |

---

## 1. Surgeon 契约复核（逐指令）

### 1.1 已经验证成立的部分

〔观察〕`com.alibaba.surgeon.bridge.ISurgeon` 是**接口**，只有 2 个方法（smali 原文）：

```
.class public interface abstract Lcom/alibaba/surgeon/bridge/ISurgeon;
.method public abstract surgeon$dispatch(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;
.end method
.method public abstract surgeon$support(Ljava/lang/String;)Z
.end method
```

〔观察〕`InstrumentAPI.support`（classes17.dex）——**这就是整个门控体系的唯一开关**：

```
.method public static support(Lcom/alibaba/surgeon/bridge/ISurgeon;Ljava/lang/String;)Z
    .locals 0
    if-nez v0, :cond_4          # iSurgeon == null -> 直接 false
    const/4 v0, 0x0
    return v0
    :cond_4
    invoke-interface {v0, v1}, Lcom/alibaba/surgeon/bridge/ISurgeon;->surgeon$support(Ljava/lang/String;)Z
    move-result v0
    return v0
.end method
```

〔观察〕每个插桩方法的固定形态（以 `ywm.a()` 为例，`classes8.dex` / `ywm.smali` L30-63）：

```
.method public static a()Z
    .locals 3
    sget-object v0, Lywm;->$surgeonFlag:Lcom/alibaba/surgeon/bridge/ISurgeon;
    const-string v1, "1669440712"
    invoke-static {v0, v1}, Lcom/alibaba/surgeon/instrument/InstrumentAPI;->support(...)Z
    move-result v2
    if-eqz v2, :cond_18                  # support=false -> 走原实现
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Object;
    invoke-interface {v0, v1, v2}, ...ISurgeon;->surgeon$dispatch(...)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/Boolean;
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z     # 返回值类型由此处决定
    move-result v0
    return v0
    :cond_18
    sget-boolean v0, Lywm;->a:Z                                  # 原实现
    return v0
.end method
```

〔观察〕`Surgeon.e(I)Z`（classes17.dex，638 行）关键指令序列（`tools/patches/smali_extract.py` 抽取）：

| smali 偏移 | 指令 | 含义 |
|---|---|---|
| `#@0`~`#@1a` | `new File(this.b, "surgeon" + i + ".jar")` | 路径 = `filesDir/surgeon/surgeon<i>.jar` |
| — | `File.exists()` | 不存在就 `Log` "patch file is not exist" 并返回 |
| `#@1d` 后 | 复制到 `lib` 目录 | 二次落盘 |
| 229 | `new-instance v2, Ldalvik/system/DexClassLoader;` | |
| 289 | `DexClassLoader.<init>(String,String,String,ClassLoader)` | parent = 宿主 ClassLoader |
| 295/314 | `Class.forName("com.alibaba.surgeon.patch.generated.PatchClassProvider").newInstance()` | |
| 329 | `IPatchClassProvider.patchedClasses()[Ljava/lang/String;` | |
| 378/409 | `Class.forName(<类名> + "$surgeon").newInstance()` | 生成代理实例 |
| 429/434/444/454 | `getDeclaredField("$surgeonFlag")` → `setAccessible(true)` → `Field.set(null, inst)` | **静态字段替换** |
| 471 | `Log "Finish patch class: "` | |
| 533/593 | `"Exception while patching class: "` / `"Failed to load patch: "` | 失败只打日志，不崩 |

### 1.2 对 Lead 结论的两处修正

**修正 1（文件名与格式）：不是 `.dex`，是 `.jar`**
〔观察〕`Surgeon.smali#@0`：`const-string v3, "surgeon"` + `append(i)` + `const-string v11, ".jar"`。
→ 落地文件名必须是 `files/surgeon/surgeon<N>.jar`（`IBundleOperator.EXTENSION` = `".jar"`）。
另外它走 `DexClassLoader` + 先复制到 `lib` 目录，说明这个 jar 里可以有 `classes.dex`，也可以带 `.so`。

**修正 2（patch 通道被封的前提）：`SecurityChecker` 用"自身 APK 签名"验签**
〔观察〕`com/alibaba/android/imclient/instant/utils/SecurityChecker.java`：

```java
private void init(Context context) {                       // :55
    PackageInfo pi = pm.getPackageInfo(context.getPackageName(), 64);
    this.mPublicKey = ((X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(pi.signatures[0].toByteArray()))).getPublicKey();
}

public boolean verifyApk(File file) throws Throwable {     // :90
    JarFile jar = new JarFile(file);
    JarEntry e = jar.getJarEntry("classes.dex");
    if (e == null) return false;
    loadDigestes(jar, e);                                  // 触发 JarVerifier
    Certificate[] cs = e.getCertificates();
    if (cs == null) return false;
    return check(file, cs);                                // check(): cs[i].verify(this.mPublicKey)
}
```

而 `BaseHotPatchProcessor.patchVerify(file)` → `mSecurityChecker.verifyApk(file)`，被
`InstantRunProcessor.<init>` 装成 `IPatchVerifier`，`InstantPatcher.handlePatches` 里
`if (iPatchVerifier != null && !iPatchVerifier.authenticate(file)) { resCode = 2; return; }`。

**推论（关键）**：
- 在**官方签名的 APK** 上，`mPublicKey` = IM官方证书公钥 → 我们没有私钥 → **任何自签 patch jar 都会被 `authenticate` 拒掉（resCode=2）**。Lead 说的"不需要改 dex 就能改返回值"在**逻辑上成立，但在官方包上被签名闸挡死**。
- 在**自己重签名的 APK** 上，`mPublicKey` = 我们的证书公钥 → **用同一把 key 签的 patch jar 能通过**。形成一个"重签一次、之后无限热更"的通道。
- 附带发现：`InstantPatcher.isApkInDebug()`（读 `ApplicationInfo.FLAG_DEBUGGABLE`）**存在但在 patch 流程里没有被调用** → patch 通道**不要求 debuggable**，只要求同签。

**修正 2 的直接后果**：路线 B 必须先做一次路线 C（重打包+重签）。所以真正的"零改动"路线是 **A（Frida 代理）**。

### 1.3 `applyPatch()` 的前置（若走路线 B）

〔观察〕`InstantPatcher.applyPatch(PatchListener)`：
```java
PatchInfo pi = getPatchInfo();                                  // 从 SP 读
if (TextUtils.isEmpty(pi.baseVersion)) { Log.e("InstantPatcher","no patch"); return; }
if (!currentVersionName().equals(pi.baseVersion) && isMainProcess(ctx)) { purge(); return; }
...
boolean ok = this.surgeon.a(pi.patchVersion);                    // -> e(version) -> 加载 surgeon<version>.jar
if (!ok) { Log.e("InstantPatcher","patch failed and clear patch."); purge(); }
```
- SP 名：`PreferencesUtils`（`SecurityChecker` 里的 `SP_NAME = "_andfix_"`，键 `instant_base_Version` / `instant_patch_version` / `instant_patch_priority`）。
- 〔观察〕`baseVersion` 必须 **严格等于 `versionName`**，本包 `versionName = 8.2.2.1`。
- 〔推断〕写这个 SP 需要 root（app 私有目录），或让 App 自己走 `handlePatches(path, info)`。
  → 路线 B 的实际操作 = 重签 APK + root 设备写 SP（`/data/data/<pkg>/shared_prefs/_andfix_.xml`）+ 放 jar。
  **成本高于路线 A 和 C**，只在需要"一次性铺好、后续频繁改行为"时才值得。

---

## 2. Surgeon id 表（本轮核心交付）

### 2.1 生成方法与口径

`tools/patches/extract_surgeon_ids.py`：解析 jadx 反编译源码，按方法边界抓取
`InstrumentAPI.support(iSurgeon, "<id>")` 与 `surgeon$dispatch("<id>", …)`，映射为
`类 → 方法签名 → id → 方言(if / ternary / dispatch-reuse) → 源码行`。

三条产物：

| 文件 | 规模 | 内容 |
|---|---|---|
| `tools/patches/data/surgeon_ids_gate.tsv` | 676 行 / 366 个 id | 18 个**门控相关类**的完整映射 |
| `tools/patches/data/contactinterface_impl_ids.tsv` | 1,403 行 / 774 个 id | `ContactInterfaceImpl`（`y0/e1/G3` 就在这里） |
| `tools/patches/data/surgeon_ids_all.tsv.gz` | **583,596 行** / **317,536 个 id** / 31,430 个类 | **全包** id 表（gzip 7.4 MB，解开约 66 MB） |
| `tools/patches/data/gate_table.md` | 49 行 | 已筛选成 markdown 表，可直接贴文档 |

> 口径说明：`kind` 列区分两种插桩方言——`if` = 方法头 if-else 型；`ternary` = 一行三元表达式型
> （如 `ywm.a()`、`Doraemon.getRunningMode()`、`j35.e()`、`ContactInterfaceImpl.e1()`）。
> 两种在 smali 里长得一样（都是 `if-eqz` + dispatch + 原实现），**patch 写法不需要区分**。

### 2.2 门控关键 id（正文版，完整 49 行见 `data/gate_table.md`）

**① 开发者入口总开关**

| 类（dex） | 方法 | id | 该 id 覆盖的行为 |
|---|---|---|---|
| `ywm` (classes8) | `public static boolean a()` | **`1669440712`** | 返回 true → `settings_develop` 可见（`CommonSettingActivity:1875`）、`DeveloperOptionsActivity:129` 放行、`CommonSettingActivity:1729` 分支 |

**② Doraemon 运行模式（一切 mode 门控的根）**

| 类 | 方法 | id | 覆盖行为 |
|---|---|---|---|
| `com.alibaba.doraemon.Doraemon` (c14) | `int getRunningMode()` | **`-1919346692`** | 返回 1/2 → 解锁 DevSetting 全量面板、`abg.b()` 首闸、`q01.e()`、`DevSettingActivity.{I,L}` |
| 同上 | `void setRunningMode(int)` | `1549858190` | 覆盖为 no-op → 防 `mode 1→2` 降级 |
| 同上 | `void setDebugMode(boolean)` | `787505523` | 同上（1/4 互转） |
| 同上 | `boolean isDebugMode()` | `1142977677` | `sMode==1` |
| 同上 | `boolean getDebugMode()` | `1054312057` | 同义（@Deprecated） |
| 同上 | `boolean validateMode(int)` | `483462827` | 只放行 1/2/4 |
| 同上 | `Object getArtifact(String)` | `-1517821125` | **决定 TRACE/Holmes artifact 是否加载** → 进而决定 `HttpsTrustAllCertsTrustManager` 是否真的被装配（03 报告的 U10 在这里可以闭合） |

**③ DevSettingActivity 门控**

| 方法 | id | 覆盖行为 |
|---|---|---|
| `void onCreate(Bundle)` | `716893361` | **注意：覆盖它会 return-void → 界面永远空白**，不要用它放行 |
| `boolean E()` | `1850914436` | `v1 == 0`；返回 true → `(mode==2 && E())` 成立 |
| `boolean F()` | `-103809587` | `v1==0 && K1 非空 && K1!="testing-trunk"` |
| `boolean G()` | `198355496` | `v1==0 && K1=="testing-trunk"` |
| `void I(Context)` | `1113375645` | 外部拉起 DevSetting 的唯一入口（内部再判 mode） |
| `void L(Context)` | `-1043729487` | **SP 覆盖 + 改域总入口**（LWS/QUIC/OAUTH/ALADDIN/邮件域/xz6 全部在此） |
| `void T()` | `799106711` | `v1==2 → setAPSecurityEnv(0)`，否则 `1`（切支付安全环境） |
| `void U()` | `-1773765220` | `ALADDIN_URL` = pre-resolver / resolver / null |
| `void O()` | `1955981139` | 重设邮箱 4 个域 + SSO |
| `void Y(Context,int)` | `-869690376` | 环境切换主体（一次性覆盖 12 个静态域） |
| `int t(int)` | `-347205642` | 环境按钮选中态 + `K1` 赋值 |

**④ dev_setting 服务端开关链**

| 类 | 方法 | id | 覆盖行为 |
|---|---|---|---|
| `j35` (c8) | `boolean e(String)` | **`-769036951`** | `ContactInterface.y0(key)` 的落点 → 返回 true 即"服务端下发过" |
| `j35` | `boolean g(String,long,boolean)` | `-309150535` | 同上（带 scope） |
| `j35` | `boolean h(String,boolean)` | `1929703955` | 同上（默认值版） |
| `com.alibaba.android.user.impl.ContactInterfaceImpl` (classes10 + classes8) | `boolean y0(String)` | `-259584662` | DevSetting/About 门控 #2 的直接入口 |
| 同上 | `int e1()` | `-1703260429` | 返回 `DevSettingActivity.v1`；返回 0 → `AboutActivity.z()` 为真 |
| 同上 | `void G3(Context)` | `-1463785684` | 冷启动时调用 `DevSettingActivity.L()` 的那条链（`jmm.d` → `G3`） |

**⑤ WebView / JSAPI 调试**

| 类 | 方法 | id | 覆盖行为 |
|---|---|---|---|
| `abg` (c16) | `boolean b()` | **`1621572248`** | 三闸合一（mode / SP / Gaea `ga_7100x_js_debug_android`）→ 返回 true 开 JSAPI 调试面板 |
| `xz6` (c30) | `void a(int)` | `-1335508869` | 写 `xz6.k`（环境索引缓存） |

**⑥ 内测自动登录闸（Bokui 凭据注入路径）**

| 类 | 方法 | id | 覆盖行为 |
|---|---|---|---|
| `q01` (c4) | `boolean e()` | **`-1007060566`** | `"autokey008".equals(l4r) && mode∈{1,2}`；返回 true 才能让 `BokuiActivity.p()` 吃 Intent 里的 phone/password |
| `q01` | `boolean f()` | `-706382202` | `mode==2 && autokey∈{007,010,101}` |
| `q01` | `void h(String,String)` | `1903368635` | 写入静态 `Account` |
| `BokuiActivity` (c3) | `void p(Intent)` | `1209035644` | 上述凭据路径本体 |

**⑦ 安全侧（**默认保持关闭**，别误开）**

| 类 | 方法 | id | 建议 |
|---|---|---|---|
| `AntiStrategyHandler` (c13) | `boolean isGrayOpen()` | `1943258327` | **返回 false**（默认即 false，显式兜住，防服务端开启后反噬） |
| 同上 | `boolean checkJsApiInvoke(...)` | `-2011429551` | 返回 false |
| 同上 | `Boolean isInited()` | `-2042942162` | 返回 false |

**⑧ 其它顺带挖到的可用 id**

| 类 | 方法 | id | 用途 |
|---|---|---|---|
| `ExportedActivityUtils` (c3/c4) | `void a(Activity)` | `-1526601701` | exported 组件的隐私/位数闸（覆盖为 return-void 可跳过 `System.exit(0)`） |
| 同上 | `void b(Activity,Context,ActivityProxy)` | `-655978266` | `attachBaseContext` 闸 |
| `ExternalProvider` (c4) | `Cursor query(...)` | `103045470` | 覆盖为 null 可关闭该 Provider 的读面 |
| 同上 | `boolean a(long)` | `-816127513` | 微应用启用判定 |
| `BokuiActivity` | `boolean q(String)` | `1807981826` | 路由内部判定 |

---

## 3. 逐项开锁

### 3.1 `ywm.a()` —— 全量确认

**① 方法形态**〔观察〕`ywm.smali`（classes8.dex）：

```
.class public Lywm;                       # 注意: 默认包, dex 里就叫 ywm（jadx 显示为 defpackage.ywm）
.field private static transient synthetic $surgeonFlag:Lcom/alibaba/surgeon/bridge/ISurgeon; = null
.field public static a:Z = false          # 第 9 行
.method public static a()Z                # 第 30 行 —— 静态无参, 返回 boolean
```

结论：**静态方法**，签名 `public static boolean a()`，返回 `Z`。
（jadx 里显示的字段名 `f69400a` 是它给 `a` 字段加前缀后的重命名；dex 真名就是 `a`。）

**② 写入方：确认不存在**〔观察〕
- `grep -rn "f69400a" java/sources` → **2 处**：`ywm.java:11` 声明、`ywm.java:15` 读取。
- `ywm.smali` 全文搜索 `sput[-a-z]* .*Lywm;->a` → 0 处（`<clinit>` 是空体：`.locals 0` / `return-void`，字段初值靠 `.field … = false` 的 encoded value）。
- 反射路径排查：全包 `setStaticBooleanField` / `setBoolean(null` / `Unsafe.putBoolean` 的调用点逐个看过，**没有一处指向 `ywm`**；也没有字符串 `"ywm"` + `"a"` 的拼接式反射（`grep -rn '"ywm"' java/sources` → 0 命中）。
- `$surgeonFlag` 侧：全包除 `Surgeon.e()` 外无写入（见 §1.1）。

→ **写入方确实不存在**。默认值 `false` 是"编译期常量"，唯一改变途径 = 让 `$surgeonFlag` 非空且 `support("1669440712")` 为真。

**③ 所有调用点**〔观察〕`grep -rn "ywm\.a()"` → 3 处：

| 文件:行 | 用法 | 效果 |
|---|---|---|
| `com/alibaba/android/user/settings/activity/CommonSettingActivity.java:1875` | `findViewById(d9k.settings_develop).setVisibility(ywm.a() ? 0 : 8)` | 为 false 时"开发者选项"条目 **GONE** |
| `CommonSettingActivity.java:1729` | `if (ywm.a()) { … }` | 点击构造流程 |
| `com/alibaba/android/user/settings/activity/DeveloperOptionsActivity.java:129` | `if (ywm.a()) { … }` | 面板内容构建 |

**④ 补丁** → `tools/patches/01-ywm-a-true.diff`

```diff
  # classes8.dex / ywm.smali
- .field public static a:Z = false          # L9
+ .field public static a:Z = true           # L9
```
等价方案（改 fallback 指令，保留 `dispatch` 优先级）：
```diff
   :cond_18                                 # L~60
-  sget-boolean v0, Lywm;->a:Z
+  const/4 v0, 0x1
   return v0
```

### 3.2 `Doraemon.getRunningMode() / setRunningMode()`

**① 字段与初值**〔观察〕`Doraemon.smali` / `Doraemon.java`

| 项 | 值 |
|---|---|
| 字段名 | `sMode:I`（`private static int`） |
| 初值 | `4`（`MODE_RELEASE`），在 `<clinit>` 里：`const/4 v0, 0x4` → `sput v0, Lcom/alibaba/doraemon/Doraemon;->sMode:I` |
| 常量 | `MODE_DEBUG=1` / `MODE_GRAY=2` / `MODE_RELEASE=4` |

**② 写入点（全包）**〔观察〕

| 位置 | 形态 | 结论 |
|---|---|---|
| `<clinit>`（L~85） | `const/4 v0, 0x4; sput sMode` | 初值 |
| `setRunningMode(I)` L~2592 | `sput v4, sMode`（前置 `validateMode`） | 唯一运行期写入 |
| `setDebugMode(Z)` | `sMode = z ? 1 : 4` | 第二写入点 |
| `defpackage/f6.java:489` | `if (getRunningMode()==1) setRunningMode(2);` | **只会 1→2** |
| `com/alibaba/lightapp/runtime/view/AIBallPublisherHelper.java:195` | 同上 | **只会 1→2** |
| `Surgeon` dispatch | `1549858190` | 外部覆盖通道 |

→ **`sMode` 从 4 变 1/2 的代码路径不存在**；能从 1 变 2（降级）。

**③ 读取点**〔观察〕`getRunningMode()` 的直接调用点 60+；作为对照，同级的 `ContactInterface.v1()` 在全包被引用 **3,136 次**（说明这类"运行模式/全局开关"被大量消费）。关键消费方：
`DevSettingActivity.onCreate/E/F/G/I/L/Y`、`abg.b()`、`q01.e/f`、`j35.g/h`、`EventButlerImpl.isDebuggerConnected`、`DevSettingActivity.onCreate` 的异常复抛分支、`AboutActivity.z()`。

**④ 补丁** → `tools/patches/02-doraemon-runmode.diff`

```diff
  # classes14.dex / com/alibaba/doraemon/Doraemon.smali  (getRunningMode 尾部, L886-889)
   :cond_18
-  sget v0, Lcom/alibaba/doraemon/Doraemon;->sMode:I
+  const/4 v0, 0x1
   return v0
```
**为什么改这里而不是改 `<clinit>` 的 `0x4`**：改初值后，`f6.java:489` 与 `AIBallPublisherHelper:195` 那两行会在首次调用语音转写时把 `sMode` 降成 2；而改 `getRunningMode()` 本身后它是纯函数，降级影响不到它。
（`Doraemon.isDebugMode()` 读的是 `sMode`，若要它也为 true，则需 `<clinit>` 改 `0x1` **并**把 `setRunningMode` 改成 no-op，见 `05-doraemon-setrunmode-noop.diff`。三者择一，不要叠。）

### 3.3 `DevSettingActivity` 门控

**① 门控分支（精确到行）**〔观察〕`DevSettingActivity.smali`，`onCreate` 起于 **L16325**：

| smali 行 | 指令 | 逻辑 |
|---|---|---|
| 16335 | `const-string v1, "716893361"` | Surgeon 前置 |
| 16350 / 16354 | `const/4 v3, 0x2` / `const/4 v4, 0x1` | v3=2, v4=1 |
| 16362 | `if-eqz v2, :cond_17` | support 为真 → dispatch 并 `return-void` |
| 16392 | `:cond_17` | 原实现入口 |
| 16399 | `invoke-static Doraemon.getRunningMode()` | 取 mode |
| **16409** | **`if-eq v7, v4, :cond_c5`** | **门控 #1：mode==1 → 全量面板** |
| 16424 | `const-string v0, "dev_setting"` | 门控 #2 的 key |
| **16439** | **`if-nez v7, :cond_c5`** | **门控 #2：`y0("dev_setting")` 为真 → 全量面板** |
| 16444 / **16454** | 再取 mode → **`if-ne v7, v3, :cond_3a`** | **mode != 2 → 直接去 `:cond_3a`（其内部会再判一次，非 2 就落到 finish）** |
| 16459 / **16469** | `DevSettingActivity.E()` → **`if-eqz v7, :cond_3a`** | **门控 #3：`E()`(=v1==0) 假 → 去 `:cond_3a`** |
| 16479-16490 | `:cond_3a` → 重取 mode → `if-ne v7, v3, :cond_b5` | 到这里说明"mode==2 但 E() 假"或"mode!=2" |
| 16500 | `setContentView(...)`（经 `:cond_3a` 落入） | **mode==2 精简面板**（`open_constant_key_check` 开关） |
| 16762 | `:cond_b5` | **else 分支**（既非 1、非 y0、也非 2） |
| 16789 | `Handler.postDelayed(new DevSettingActivity$h(), 1000L)` | **1 秒后 `finish()`**（`h.run()`） |
| **16800 / 16807** | `:cond_c5` → `setContentView(kck.dev_setting)` | **全量面板** |

> 分支落点容易记错，这里以实测行号为准：**`cond_c5` = 全量 · `cond_3a` = 精简（mode==2）· `cond_b5` = finish**。
> 校验方式：`awk 'NR>=16325 && NR<=17393' DevSettingActivity.smali | grep -nE ':cond_|:goto_|setContentView|postDelayed'` 后加回 16324 偏移。

**② `v1` / `e1()` 初值**〔观察〕
- `DevSettingActivity.v1` 声明在 **L154：`public static int v1 = 2;`**（0=日常 1=预发 2=线上）。
- 写入点：`L()` 里 `v1 = sp.getInt("DevSettingActivity_ENV", v1)`、`Y()` 里 `v1 = xn5.j(k1.get(i), 2)` —— **都在 `mode∈{1,2}` 门控内**。
- `ContactInterfaceImpl.e1()` → `DevSettingActivity.v1`（id `-1703260429`）；`AboutActivity.z()` = `e1()==0 || Gaea("general","dev_setting_for_gray_android",false)`。
- **`v1` 默认 2 → `e1()==0` 恒假**，所以 About 的灰测分支只剩 Gaea 键。

**③ "门控恒真"的最小补丁集**

只需要 **1 处**（三选一）：

| 方案 | 改动 | 覆盖范围 |
|---|---|---|
| **m1（推荐）** | `Doraemon.getRunningMode()` → 1（即 §3.2 的补丁） | 门控 #1 恒真 → 全量面板；`abg.b()`/`q01.e()`/`L()` **一并**解锁 |
| m2 | `DevSettingActivity.smali:16409` `if-eq v7, v4, :cond_c5` → `goto :cond_c5` | **只**解锁本页 |
| m3 | `ywm` 字段 + `e1()` 返回 0 | 解锁"开发者选项"入口 + About 灰测，但 DevSetting 页本身仍看 mode |

**明确不需要动的**：
- **`v1` 不要改**。改成 0 会让 `T()` 走 `setAPSecurityEnv(1)`（把支付安全环境切到非线上）、`U()` 把 `ALADDIN_URL` 置 `null` —— 副作用远大于收益。
- **不要覆盖 `onCreate` 的 surgeon id**（`716893361`）：dispatch 分支是 `return-void`，会让页面永远空白（比 finish 更糟）。
- **不要删 `postDelayed(finish)` 兜底**：异常路径会留下悬挂的空白 Activity。

→ `tools/patches/03-devsetting-gate.diff`（m2 版本，含指令宽度说明）

### 3.4 WebView 调试

见 **`tools/patches/06-webview-debug-notes.md`**（完整 18 条清单）。要点：

- **硬编码 `setWebContentsDebuggingEnabled(true)` 共 18 处**（邮件签名/详情/富文本、小程序容器 `<pkg>WebViewWrapper:57/61`、动态 `OdysseyFeedWebView:659`、Nebula `H5WebView:640` 等），**已经生效**，不需要补丁。
- `WebView.setWebContentsDebuggingEnabled` 是**静态、进程级**开关 → 只要任一调用点跑过一次，整进程 WebView 都能被 `chrome://inspect`。
- **最省事开法**：① 不改任何东西，进"邮件详情"或打开任意小程序触发一次；② Frida 一行 `Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true)`（必须 spawn 注入）。
- **受门控的那条链**（`abg.b()`）控制的是 **JSAPI 调试面板**，不是 WebView 远程调试 —— 用 `04-abg-jsdebug.diff`。

---

## 4. 推荐补丁组合

| 目标 | 组合 | 说明 |
|---|---|---|
| 只想看到"开发者选项"入口 | `01` | 1 处字段 |
| 想进 DevSetting 全量面板 | `02` | 1 条指令，顺带解锁 abg/q01/L |
| 想要 JSAPI 调试面板 | `02` + `04` | `abg.b()` 另有三道闸，直接短路更稳 |
| 想让 `isDebugMode()` 也为真 | `<clinit> 0x4→0x1` + `05` | 与 `02` 二选一 |
| 完全不动 dex | `frida_isurgeon.js` | 覆盖上表全部 |

---

## 5. 构建流水线（路线 C）

`tools/patches/build_patch.sh`（已写好，幂等）：

```bash
# 依赖: JDK(Android Studio jbr) + Android Studio 自带 smali 3.0.9 + build-tools 36.0.0
export JAVA_HOME=/d/Android-studio/jbr
./tools/patches/build_patch.sh \
    re/base_apk3/target.apk \
    /tmp/<pkg>-unlocked.apk \
    my.jks research mypass
```

步骤：解包取 `classes*.dex` → `baksmali d` → 按 `.diff` 文本做**唯一匹配**替换（不唯一就报错退出）→ `smali a --api 33` → `zip -0` 回填 → `zipalign -p -f 4` → `apksigner sign` → `apksigner verify --print-certs`。

**为什么要 `smali a` 而不是 hex 改**：`if-eq`（format 22t，2 code units）换成 `goto`（format 10t，1 code unit）会改变方法长度，必须在 smali 层重汇编。字段初值（`01`）与 `const/4` 替换（`02`）虽然是等长的，但为了统一流程也走同一条路。

**工具链落地细节**（踩坑记录）：
- Android Studio 自带的是 **smali 3.0.9**：`/d/Android-studio/plugins/android/lib/smali-{baksmali,dexlib2,util}-3.0.9.jar`。
- **CLI 用不了**：`baksmali Main` 依赖 `jcommander`，本机没有 → 改走 API。`tools/patches/Dex2Smali.java`（已编译到 `tools/patches/classes/`）直接调 `Baksmali.disassembleDexFile`，绕开 CLI 依赖。
- classpath 需要额外补 `intellij.libraries.guava.jar`（Android Studio `lib/`）与 `jsr305-2.0.1.jar`。
- 5 参 `disassembleDexFile(..., List<String>)` 的第 5 参**不是** class filter（传了会静默输出 0 个文件）→ 用 4 参版本全量反汇编。单个 dex 约 12 秒。

---

## 6. 验证方法

| 项 | 命令 / 操作 | 期望 |
|---|---|---|
| **01 ywm** | 设置 → 通用 → 找"开发者选项" | 条目**存在**（未打补丁时为 GONE） |
| | `adb logcat -s DeveloperOptionsActivity` | 有该 Activity 的日志 |
| **02 Doraemon** | `adb shell am start -n <PKG>/com.alibaba.android.user.devset.DevSettingActivity` | 直接出现全量面板（ENV / LWS_URL / OAUTH_URL / 邮件域 等） |
| | `adb logcat -s DevSettingActivity` | `ENV=2,LWS_URL=…,LWS_SHORT_URL=…,OAUTH_URL=…,ALADDIN_URL = …`（`DevSettingActivity.java:758` 的 `Log.e`） |
| | 反例（未打补丁） | 界面空白 ≈1s 后自动退出，logcat 只有 `DevSettingActivity, onCreate` 紧跟 `onDestroy` |
| **03 门控跳转** | 同上 | 同上（仅本页生效） |
| **04 abg** | 打开任意小程序 / H5，观察调试面板入口 | JSAPI 调试按钮出现 |
| | `adb logcat \| grep -i "jsapi.*debug\|H5DevSetting"` | 相关日志 |
| **WebView** | `adb shell cat /proc/net/unix \| grep webview_devtools` | 出现 `@webview_devtools_remote_<pid>` |
| | `adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>` 然后 `curl http://127.0.0.1:9222/json/version` | 返回 JSON |
| | Chrome → `chrome://inspect` → Configure 加 `localhost:9222` | 列出IM WebView 页面与 URL |
| **Frida 代理** | `frida -U -f <pkg> -l tools/patches/frida_isurgeon.js --no-pause` | 控制台打印 `[isurgeon] OK <类> $surgeonFlag = injected` ×8，以及 `ywm.a() = true` / `Doraemon.getRunningMode() = 1` / `abg.b() = true` |
| **签名** | `apksigner verify --print-certs <out.apk>` | 显示自定义证书（不是 `CN=ninebot`/阿里） |

---

## 7. 风险与边界（务必先读）

1. **重签名 = 与官方签名体系脱钩**（路线 B/C 共有）：
   - SecurityGuard `staticDataReport`/`wua` 的签名校验会失败 → 服务端可能拒绝请求、降级或风控。
   - 所有 `protectionLevel=signature` 的权限失效（`PUSH_PROVIDER`、`MIPUSH_RECEIVE`、`external.provider.WRITE` 等）。
   - 与支付宝/微信/华为推送等"按签名绑定"的 SDK 断链。
   - **`ExternalProvider` 的 read 权限是 `normal`**，不受影响（这一点在 03 报告里已判定）。
2. **打开 mode=1 会真的改域**：`DevSettingActivity.L()` 一旦跑起来，`o1/p1/q1/r1/s1/B1..G1/v1` 会从 SP 覆盖，`T()` 还会把 `setAPSecurityEnv` 切到测试。**离线/一次性测试设备专用**，用完把 `DevSettingActivity.v1` 复位、清 SP。
3. **`03` 的 `goto :cond_c5` 跳过 `y0("dev_setting")` 与 E() 判定**，但不跳过 `onCreate` 后续的 `findViewById` 链。〔推断〕全量面板分支（16500 之后的 `16800+`）自建它要用的全部 view，因此不会 NPE —— 但**本项未逐 view 核对**。若实测出现 `findViewById` 返回 null 导致的 NPE，改用 m1（改 `getRunningMode()`）方案：那条路径走的是原有的"mode==1"分支，view 装配顺序与官方逻辑完全一致。
4. **Frida 路线也有代价**：`libfacedevice`/`libzkfv_tj` 在刷脸链会检测注入（03 报告 §3.4）；只要不触碰人脸，风险很低。
5. **`AntiStrategyHandler` 默认关闭**，但服务端可开。补丁里显式让它返回 false，避免"越开越被拦"。

---

## 8. 未解项

| # | 项 | 现状 | 下一步 |
|---|---|---|---|
| U1 | `PatchClassProvider` 的完整类名/包名约定 | 只有 `com.alibaba.surgeon.patch.generated.PatchClassProvider` 与 `"$surgeon"` 后缀 | 写一个最小 patch jar 实测（需先重签 APK） |
| U2 | `surgeon<i>.jar` 里是否必须含 `classes.dex` | `SecurityChecker` 强制 `getJarEntry("classes.dex") != null` | 同理实测 |
| U3 | `_andfix_` SP 的写入是否有非 root 路径 | 只看到 `handlePatches()`（需 App 内部调用） | 找 `InstantRunProcessor` 的上游触发（是否由 LWP 下发） |
| U4 | 全量 id 表未做"id → 语义"的自动摘要 | 只有 (类,方法,id) 三元组 | 需要时按包名过滤 + 人工命名 |
| U5 | `Doraemon.getArtifact` 覆盖后 TRACE artifact 是否真加载 | 03 报告 U10 | 用 id `-1517821125` 返回指定 artifact 实测 |
| U6 | `ywm` 之外的第二个开发者入口 `DevRealmConfigActivity` | 03 报告未复核 | 本轮未涉及 |

---

## 9. 产物清单

```
tools/patches/
├── 01-ywm-a-true.diff              # ywm.a() 恒 true（字段初值 / fallback 指令 两版）
├── 02-doraemon-runmode.diff        # getRunningMode() 恒 1（含"为什么不改 sMode 初值"）
├── 03-devsetting-gate.diff         # onCreate 门控跳转（含指令宽度说明、不该改的三处）
├── 04-abg-jsdebug.diff             # abg.b() 恒 true（JSAPI 调试面板）
├── 05-doraemon-setrunmode-noop.diff# setRunningMode 空实现（防降级，可选）
├── 06-webview-debug-notes.md       # 18 处硬编码点 + 33 处参数化点 + 三种开法 + 排错
├── frida_isurgeon.js               # ★ 零重打包开锁脚本（ISurgeon 代理）
├── build_patch.sh                  # 解包→baksmali→打补丁→smali→zipalign→签名
├── Dex2Smali.java                  # baksmali API 驱动（绕开 jcommander 缺失）
├── classes/                        # 已编译的 Dex2Smali.class
├── extract_surgeon_ids.py          # 契约抽取器（类/方法/id/方言/行号）
├── smali_extract.py                # 按签名抽 smali 方法体
└── data/
    ├── surgeon_ids_gate.tsv        # 676 行 / 366 id（18 个门控类）
    ├── contactinterface_impl_ids.tsv # 1403 行 / 774 id
    ├── surgeon_ids_all.tsv.gz      # ★ 583,596 行 / 317,536 id（全包）
    └── gate_table.md               # 49 行 markdown 版门控 id 表（可直接引用）
```

复现关键命令：

```bash
# 1) 全量 surgeon id 表（约 3 分钟，31,430 个含插桩的类）
cd java && grep -rl 'surgeon\$dispatch' sources --include=*.java > /tmp/sf.txt && cd ..
python tools/patches/extract_surgeon_ids.py /tmp/sf.txt java tools/patches/data/surgeon_ids_all.tsv

# 2) 单类精确抽取（快）
printf 'sources/defpackage/ywm.java\n' > /tmp/one.txt
python tools/patches/extract_surgeon_ids.py /tmp/one.txt java /tmp/one.tsv

# 3) 反汇编单 dex 并抽方法体（baksmali 3.0.9 API）
java -cp "<smali jars>;tools/patches/classes" Dex2Smali unpacked/dex/classes8.dex /tmp/c8
python tools/patches/smali_extract.py /tmp/c8/ywm.smali "a()Z"
```
