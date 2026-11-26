# 11 · 解锁实战：Surgeon 热修契约 + 字节级补丁 + 真机验证

> 目标：`<PKG>` 8.2.2.1（arm64-v8a，v1+v2）
> 本文全部操作都在本机副本上完成，原件 `target.apk` 未改动。
> 产物：`tools/patch/patch_dex.py`、`tools/patch/rebuild_apk.py`、`tools/frida/unlock.js`、`tools/patch/out/imclient_unlocked_signed.apk`、`tools/patch/shots/*.png`

---

## 0. 结论

| # | 结论 | 状态 |
|---|---|---|
| 1 | IM的 `Surgeon` 是一套**官方热修框架**：`Surgeon.e(i)` 会加载 `files/surgeon/surgeon<i>.jar`（`IBundleOperator.EXTENSION = ".jar"`，DexClassLoader 同样吃 jar），反射把目标类的 `$surgeonFlag` 设成补丁实例，之后该类所有方法首行的 `InstrumentAPI.support($surgeonFlag, "<id>")` 分支就会走补丁实现 | **〔观察〕契约完整还原** |
| 2 | 装载入口是 `com.android.alibaba.ip.server.InstantPatcher.handlePatches(path, PatchInfo)`，它把外部 dex 复制进应用私有目录再调 `Surgeon.d/e`，**默认没有 `IPatchVerifier`（无签名校验）** | 〔观察〕 |
| 3 | 但 release 包内**没有任何调用方**去触发 InstantPatcher（只有 Doraemon 热修服务端流程会），所以"官方通道"要能用必须先让应用自己加载我们的 dex → 需要额外注入 | 〔观察〕 |
| 4 | 更直接的路：**两个字节级补丁**（不改方法长度、不重排 dex）——`ywm.a()` 恒真 + `Doraemon.sMode=1` | **〔已实现并真机验证〕** |
| 5 | 打补丁后的 APK 已重签（v1+v2+v3）并成功安装到 S10，冷启动、隐私协议、登录 WebView 全部正常，**无 VerifyError**；且 `@webview_devtools_remote_26230` 套接字出现 → **WebView 远程调试已被解锁**（门控 dependent on `getRunningMode()==1`） | **〔真机证据〕** |
| 6 | 副作用红利：`Doraemon` 进入 mode 1 后，`ContactInterfaceImpl.X4` 的 `getRunningMode()==4` 提前返回失效 → `mock_nologin_switch` 路由从"不可达"变成"可达" | 〔推断，待登录后验证〕 |

---

## 1. Surgeon 热修框架（完整契约）

### 1.1 类图

```
com.alibaba.surgeon.bridge.ISurgeon          ← 补丁接口
    boolean  surgeon$support(String id)
    Object   surgeon$dispatch(String id, Object[] args)

com.alibaba.surgeon.instrument.InstrumentAPI ← 静态门面
    static boolean support(ISurgeon s, String id) { return s != null && s.surgeon$support(id); }

com.alibaba.surgeon.bridge.Protocol           ← 常量
    PATCH_CLASS_PROVIDER   = "com.alibaba.surgeon.patch.generated.PatchClassProvider"
    PATCH_CLASS_NAME_SUFFIX= "$surgeon"
    PATCH_FLAG_FIELD_NAME  = "$surgeonFlag"

com.alibaba.surgeon.Surgeon                   ← 补丁装载器
    Surgeon(Context)                    // filesDir/surgeon、cacheDir/surgeon-opt
    boolean a(int i)  -> e(i)           // 装载 surgeon<i>.dex
    boolean d(File,int i)               // 把外部 dex 拷成 surgeon<i>.dex 再 e(i)
    void    b()                         // purge
    private boolean e(int i) {
        DexClassLoader cl = new DexClassLoader(files/surgeon/surgeon<i>.dex, cache/surgeon-opt, libDir, getClass().getClassLoader());
        IPatchClassProvider p = (IPatchClassProvider) Class.forName("...PatchClassProvider", true, cl).newInstance();
        for (String cls : p.patchedClasses()) {
            Object patch = cl.loadClass(cls + "$surgeon").newInstance();
            Field f = cl.loadClass(cls).getDeclaredField("$surgeonFlag");   // parent-first → 拿到应用里的真实类
            f.setAccessible(true); f.set(null, patch);
        }
    }
```

### 1.2 每个方法长什么样（`ywm` 实例）

```java
public class ywm {
    private static transient /* synthetic */ ISurgeon $surgeonFlag = null;
    public static boolean f69400a = false;

    public static boolean a() {
        ISurgeon s = $surgeonFlag;
        return InstrumentAPI.support(s, "1669440712")
             ? ((Boolean) s.surgeon$dispatch("1669440712", new Object[0])).booleanValue()
             : f69400a;
    }
}
```

- release 下 `$surgeonFlag == null` → `support()` 恒 false → 走原逻辑。
- 只要把 `$surgeonFlag` 设成我们的实现，并让 `surgeon$support("1669440712")` 返回 true，就能**整段替换** `a()` 的行为。
- 全包 30 个 dex 都有这种桩；`$surgeonFlag` 字符串出现在 **27 个 dex**（除 dup 外全部）。

### 1.3 装载链路（谁会把 dex 塞进去）

```
com.android.alibaba.ip.server.InstantPatcher
    create(Context)                      // 单例，内部 new Surgeon(context)
    PatchResult handlePatches(String path, PatchInfo info)
        ├─ hasPatched(info)? 已打过 → resCode=1
        ├─ info.baseVersion != versionName → resCode=5
        ├─ patchVerifier != null && !authenticate(file) → resCode=2   ← 默认 verifier 为 null
        └─ surgeon.d(file, info.patchVersion) → 复制到 files/surgeon/surgeon<v>.dex → 装载
    applyPatch(listener)                 // 走 SP 里保存的 PatchInfo（本地没有就不做事）
```

`PatchInfo` 三个字段：`baseVersion`（必须等于 `8.2.2.1`）、`patchVersion`（决定文件名）、`priority`（0=后台线程，1=同步）。

**关键观察**：`patchVerifier` 默认为 `null` → **没有签名校验**；门槛只有「baseVersion 匹配」和「文件存在」。唯一缺的是**调用方**——release 包里只有 Doraemon 的远端热修流程会调它，本地无入口（`InstantRunContentProvider` 是 instant-run 残留，未在清单注册）。

---

## 2. 路线选择

> **修订（见 `analysis/07-unlock.md` §1.2/§3）**：① 补丁文件名是 `surgeon<i>.jar`（`IBundleOperator.EXTENSION=".jar"`），不是 `.dex`；② `InstantRunManager` 的 `BaseHotPatchProcessor` 会先过 `SecurityChecker.verifyApk(file)`，它比对的是**当前运行 APK 自己的签名** → 官方包上第三方补丁 jar 会被拒；重签名后的包才会通过（此时它验的是我们自己的证书）。所以"官方包 + 零改包"的最优解是 **Frida 注入 ISurgeon 实现**（`tools/patches/frida_isurgeon.js`），而不是去喂 jar。

| 路线 | 可行性 | 代价 |
|---|---|---|
| A. 字节级补丁 + 重签（本次采用） | **已成功** | 需重装（签名变化），服务端是否校验签名未知 |
| B. Frida 注入 ISurgeon（`frida_isurgeon.js`） | 需 attach（root/gadget），**官方包可直接用、不改 dex/不重签** | 需能 spawn 注入；`$surgeonFlag` 要在门控被调用前装好 |
| C. Surgeon patch jar | 需要 `SecurityChecker` 通过（官方包拒第三方签名）+ SP 里 `baseVersion` 匹配 | 一次重签后可无限热更 |
| D. Frida 直接改静态字段 | 需 root/gadget | 最省事，不落盘 |

A 的脚本见 §3，B/D 见 §4，C 的契约见 §5。

---

## 3. 路线 A：两个字节补丁

### 3.1 补丁定义

| # | 目标 | dex | 原始 | 补丁后 | 效果 |
|---|---|---|---|---|---|
| 1 | `Lywm;->a()Z` | `classes8.dex` | `sget-object $surgeonFlag … ; sget-boolean a; return` | `const/4 v0, #1` + `return v0`（其余 25 个 unit 填 `nop`） | 设置页「开发者选项」入口可见；`DeveloperOptionsActivity.onCreate` 门控放开 |
| 2 | `Lcom/alibaba/doraemon/Doraemon;-><clinit>` | `classes14.dex` | `const/4 v0, #4` → `sput sMode, v0` | `const/4 v0, #1` | 初始 `mode=1` |
| 3 | `Doraemon->setRunningMode(I)V` | `classes14.dex` | 33 个 unit（含 `sput sMode`） | 整段替换为 `return-void` + `nop` | **防降级**：包内 `f6.java:489`、`AIBallPublisherHelper:195` 有 `if(mode==1) setRunningMode(2)`，不堵住会把 1 改回 2 |

> 为什么补丁 2 必须配补丁 3：`analysis/07-unlock.md` §2 复核发现——只把 `<clinit>` 改成 1，运行期会被上面两处调用**降级成 2**（MODE_GRAY），`DevSettingActivity` 的 `mode==1` 分支就不成立了。把 `setRunningMode` 变 no-op 后 `sMode` 恒为 1，`getRunningMode()`/`isDebugMode()` 都是纯读字段，降级影响不到。
> 另一处可选改法（`07` 推荐）是把 `getRunningMode()` 的 fallback `sget v0, sMode` 换成 `const/4 v0,#1`；两种做法等价，本次选了「改初值 + 堵 setter」。

为什么能直接改字节：两处都不改变方法长度、不改变寄存器数、方法内没有分支跳进被覆盖区；补丁后重算 dex 的 `checksum`(adler32) 与 `signature`(SHA-1)。

### 3.2 脚本

```bash
python tools/patch/patch_dex.py tools/patch/out
#  patch ywm.a()      -> out/classes8.dex  (27 insns, 3 regs)
#  patch Doraemon mode-> out/classes14.dex (const/4 at unit 7)

python tools/patch/rebuild_apk.py target.apk tools/patch/out tools/patch/out/imclient_unlocked.apk
# 替换 2 个 dex，剔除旧 META-INF 签名

apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey --v1-signing-enabled true --v2-signing-enabled true \
    --min-sdk-version 21 --out imclient_unlocked_signed.apk imclient_unlocked.apk
```

### 3.3 静态验证

补丁后对 `out/classes8.dex` 单类反编译：

```java
public class ywm {
    public static boolean f69400a = false;
    public static boolean a() { return true; }     // ← 原逻辑已被替换
}
```

对 `out/classes14.dex`：

```java
public class Doraemon {
    public static final int MODE_DEBUG = 1;
    private static int sMode = 1;                  // ← 原值 4
}
```

`apksigner verify`：v1 / v2 / v3 **全部通过**；`aapt2 dump badging` 包名版本不变。

### 3.4 真机验证（Samsung SM-G9730 / Android 12）

```text
adb install -r -d imclient_unlocked_signed.apk   → Success
monkey -p <PKG>  → 启动
logcat: "checkExportedActivityStartup and exit in LaunchHomeActivity" → 转 PrivacyPolicyActivity（首次启动正常流程）
点击「同意」→ 进入 NoLoginCommonWebViewActivity（登录 H5）
无 VerifyError / 无 ClassNotFound / 无 FATAL EXCEPTION
```

**解锁证据**：登录页是 WebView，其调试开关由 `Doraemon.getRunningMode()==1/2` 门控。补丁后：

```text
adb shell cat /proc/net/unix | grep devtools
@webview_devtools_remote_26230        ← 出现，说明 setWebContentsDebuggingEnabled(true) 已被调用
```

原版（mode=4）该套接字不会出现（`Available<pkg>WebView.H3()` / `RuntimeWebViewLayout.D0()` 的门控 return）。
截图：`tools/patch/shots/s2.png`（隐私协议）、`s5.png`/`s6.png`（登录 WebView）。

> 仍未验证：登录后「设置 → 开发者选项」与 `DevSettingActivity` 的完整界面（需账号）。静态门控已全部打通，运行期只剩服务端 `dev_setting` 灰度这一层。

---

## 4. 路线 C/D：Frida（root / gadget）

`tools/frida/unlock.js`（直接改字段/方法，最省事）：

```js
Java.perform(function () {
  Java.use('ywm').a.overload().implementation = function () { return true; };
  var D = Java.use('com.alibaba.doraemon.Doraemon');
  D.getRunningMode.overload().implementation = function () { return 1; };
  D.sMode.value = 1;
  var WV = Java.use('android.webkit.WebView');
  var m = WV.setWebContentsDebuggingEnabled.overload('boolean');
  m.implementation = function (b) { return m.call(WV, true); };   // .call 走原实现，避免递归
});
```

用法：`frida -U -f <PKG> -l unlock.js --no-pause`。
注：S10 未 root，需先重打包注入 frida-gadget（会破坏官方签名，触发 SecurityGuard 的概率未知）。

**更强的一条**：`tools/patches/frida_isurgeon.js` —— 在 Frida 里 `Java.registerClass` 实现 `ISurgeon`，把目标类的 `$surgeonFlag` 反射设为该实例，再按 `id → 返回值` 表拦截。**不改 dex、不重打包、官方包可直接用**；id 表见 `tools/patches/data/surgeon_ids_gate.tsv`（全包 31,430 个插桩类 / 583,595 个 (方法,id) 对 / 317,536 个不同 id，其中与门控相关的 49 条已人工核对）。

---

## 5. 路线 B：Surgeon 通用补丁（可替换任意 instrumented 方法）

### 5.1 构建一个补丁 dex

```
src/com/alibaba/surgeon/patch/generated/PatchClassProvider.java
    public class PatchClassProvider implements IPatchClassProvider {
        public String[] patchedClasses() { return new String[]{"ywm", "com.alibaba.doraemon.Doraemon"}; }
    }
src/ywm$surgeon.java            // 默认包，类名必须带 $surgeon
    public class ywm$surgeon implements ISurgeon {
        public boolean surgeon$support(String id) { return "1669440712".equals(id); }
        public Object surgeon$dispatch(String id, Object[] a) { return Boolean.TRUE; }
    }
src/com/alibaba/doraemon/Doraemon$surgeon.java
    public class Doraemon$surgeon implements ISurgeon {
        public boolean surgeon$support(String id) { return "-1919346692".equals(id); }
        public Object surgeon$dispatch(String id, Object[] a) { return Integer.valueOf(1); }
    }
```

编译（stub 只需 `ISurgeon` / `IPatchClassProvider` 两个接口，可用同签名空接口占位）：

```bash
javac -source 8 -target 8 -d build src/**.java
d8 --lib $ANDROID_HOME/platforms/android-35/android.jar --min-api 21 --output out/ build/**
# out/classes.dex → surgeon1.dex
```

### 5.2 触发（需能执行代码）

```js
// Frida：把 dex 推进应用私有目录并装载
var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var info = Java.use('com.android.alibaba.ip.common.PatchInfo').$new();
info.baseVersion.value = '8.2.2.1'; info.patchVersion.value = 1; info.priority.value = 1;
Java.use('com.android.alibaba.ip.server.InstantPatcher').create(ctx)
    .handlePatches('/data/local/tmp/surgeon1.dex', info);
```

或无 root 时：改包时把 `surgeon1.dex` 放进 `assets/`，在 `LauncherApplication.onCreate` 里加大约 6 行 smali（copy asset → `handlePatches`）。

### 5.3 为什么值得留这条线

- 目标方法只要带 `<id>` 桩就能被整体替换 —— 包括我们还没挖到的门控（`DevSettingActivity` 的 93 个控件、`ContactInterfaceImpl.X4`、`SecureLink` 等）。
- `surgeon$dispatch` 的 id 是方法级唯一常量，**一个 dex 可以同时覆盖成百上千个方法**，比逐条 smali patch 稳。

---

## 6. 副作用与联动

| 联动点 | 说明 |
|---|---|
| `mock_nologin_switch` | `ContactInterfaceImpl.X4` 首行 `if (Doraemon.getRunningMode()==4) return;`（见 10-poc §1）→ mode=1 后该 return 不成立，路由 `imclient://imclientclient/action/mock_nologin_switch?key=&value=` 从"不可达"变"可达"，写入 SP `mock_no_login_key_prefix_*` |
| WebView 调试 | 主链路门控（mode + SP/Gaea 键）已开；邮件/文档模块本来就有硬编码 `setWebContentsDebuggingEnabled(true)`（见 07-unlock） |
| 环境切换 | `DevSettingActivity` 内 `DevSettingActivity_ENV`(0 日常/1 预发/2 线上) 可改；`setAPSecurityEnv` 一并切换 SG 环境 |
| 风险 | 改包后签名变化：SecurityGuard 的 `wua`/`securitybody` 会带上"非官方签名"这一事实，服务端是否拒绝登录/降级功能**未验证**（需账号，见 09 未解项） |

---

## 7. 复现清单

| 步骤 | 命令 |
|---|---|
| 打补丁 | `python tools/patch/patch_dex.py tools/patch/out` |
| 重打包 | `python tools/patch/rebuild_apk.py target.apk tools/patch/out out/imclient_unlocked.apk` |
| 签名 | `apksigner sign … --out imclient_unlocked_signed.apk imclient_unlocked.apk` |
| 校验 | `apksigner verify --print-certs --verbose`；jadx 单类反编译确认 |
| 安装 | `adb install -r -d imclient_unlocked_signed.apk` |
| 验证 | `adb shell cat /proc/net/unix \| grep devtools`；`chrome://inspect` |
| 回滚 | 卸载后重装官方包（`adb uninstall <PKG>`） |

> 产物仅用于本地样本研究；原包与签名保持只读。
