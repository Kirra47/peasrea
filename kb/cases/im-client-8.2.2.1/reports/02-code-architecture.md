# 02 · 代码架构、启动链与核心框架

> 目标：`re/base_apk3/target.apk`（IM 8.2.2.1 专属版 `<PKG>`）
> 输入：`unpacked/dex/`（30 dex / 180,864 类）、`java/sources/`（jadx 全量 84,971 文件）、`scan/dex-index/`（本轮产物）
> 标记：**〔观察〕**=文件/行号可直接复核；**〔推断〕**=由调用关系推导；**〔未知〕**=静态不可判定
> 说明：本报告在 4 个并行分析任务中由 Lead 收口；`scan/dex-index/` 的索引与统计由 code-analyst 生成，结论由 Lead 复核后写入。精确调用链处均给出可复核的文件与行号，未定位到的一律标 〔未知〕。

---

## 0. 结论摘要

| # | 结论 |
|---|---|
| 1 | 全包 **180,864 类**、1,233,999 方法；按包归属可分 27 个功能组，但 **50,294 类（27.8%）落在 R8 短名空间**，只能靠调用关系反推，不能靠包名归类 |
| 2 | 启动链是**分阶段任务框架**：`LauncherApplication` → `DDApplication`(SplitCompatApplication) → `DDLaunchContext` → 按 `attach / create / preload / provider / idell1 / mainlooper / safe / statistic / delegate` **9 个阶段**执行 `ILaunchTask`，任务基类是被混淆的 `tf`（实现 `vf.d(LaunchContext)` 与 `ch.b()` 进程过滤） |
| 3 | 全包被 **Surgeon 插桩**包裹：每个方法开头 `ISurgeon s = $surgeonFlag; if (InstrumentAPI.support(s,"<id>")) { s.surgeon$dispatch("<id>", args); return; }`，release 下 `$surgeonFlag=null` 恒走原逻辑；**单 `LauncherApplication` 一个文件就有 75 处**。这是理解全包分支结构的钥匙，也是全部 dev 门控的开关载体 |
| 4 | 插件化不是"动态加载 dex"，而是 **UI 槽位/插件模型**：`META-INF/dt_plugin_config/*.xml` **28 个**配置文件定义 `container/slot/plugin + condition`，运行时按灰度条件装配首页、会话菜单、Ding、邮件、直播等界面 |
| 5 | 路由有 **2,604 条**（`scan/dex-index/routes.tsv`），落在 **681 个组件**上；三套 scheme 抢同一批 host：`https/http/imclient://qr.<host>` 共 1,679 条，`imclient://imclientclient` 200 条 |
| 6 | 多进程 **22 个**：主进程 1,183 组件；`:lite1`…`:lite5`（mPaaS H5 多开）、`:push`/`:pushservice`（推送）、`:mcs`（会议）、`:normal_render_proc0`/`:isolate_render_proc0`/`:gpu_process`（小程序沙箱渲染） |
| 7 | 数据层三套并存：**MMKV**（`<PKG>`）、**SharedPreferences 100+ 个命名空间**（`scan/dex-index/sp-names.txt`）、**加密 SQLite**（`com.alibaba.sqlcrypto` + `bee` + `ormlite`）；DAO 的 `CREATE TABLE` 不在 Java 层，**表结构〔未知〕** |

---

## 1. 类-包索引与功能分组

统计口径：`scan/lead/classes_unique.txt`（180,862 个唯一类描述符）与 `scan/dex-index/functional-groups.tsv`（按命名空间前缀归类，含方法/字段计数）。

| 功能组 | 类数 | 方法数 | 主要命名空间 |
|---|---|---|---|
| 支付宝容器 / 支付 msp | 16,548 | 98,138 | `com.alipay.mobile`(7,615)、`com.alipay.android`(6,116) |
| RTC / 音视频 | 11,886 | 70,692 | `com.alibaba.android`(6,377)、`com.taobao.taopai`(3,078)、`org.webrtc.mozi`(806)、`tv.danmaku.ijk`(179) |
| IM 业务 | 8,562 | 50,586 | `com.alibaba.android.imclientim` |
| 三方通用库 | 8,483 | 57,139 | guava / glide / bouncycastle / gson |
| 组织 / 通讯录 / 用户 | 6,316 | 34,361 | `com.alibaba.android.user.*` |
| 会议 / 直播 / 圈 | 5,886 | 37,786 | `com.alibaba.android.teleconf`、`com.rokid.sdk` |
| 小程序运行时 | 5,610 | 33,473 | `com.alibaba.lightapp` |
| H5 容器 nebula/UC | 5,526 | 34,074 | `com.alipay.mobile.nebula*`、`com.uc.webview` |
| 邮箱 alimei | 5,344 | 36,594 | `com.alibaba.alimei` |
| 小程序容器 ariver | 3,380 | 16,104 | `com.alibaba.ariver` |
| 钉盘 / 文档 | 2,181 | 11,627 | `com.alibaba.imclient.cspace`、`cn.wps.moffice` |
| 网络 MTOP/ANet/Gaea | 2,152 | 13,519 | `mtopsdk`(783)、`com.alibaba.wireless`(270)、`com.imclient.gaea`(109) |
| 推送通道 | 2,006 | 12,293 | 华为 704 / vivo 269 / 小米 266 / FCM 171 / 荣耀 150 |
| 调试面板 Doraemon | 1,872 | 11,997 | `com.alibaba.doraemon` |
| IM 协议 laiwang/LWP | 1,769 | 11,414 | `com.alibaba.laiwang`、`com.laiwang.protocol` |
| IM 内核 wukong | 1,756 | 9,840 | `com.alibaba.wukong` |
| 人脸 / 风控 Zoloz | 1,598 | 9,928 | `com.alibaba.security`、`com.dtf.face`、`com.alipay.zoloz` |
| 地图 / 定位 | 1,452 | 12,395 | `com.amap.api`(1,227)、`com.autonavi.*` |
| 日历 | 1,295 | 7,954 | `com.alibaba.android.calendar` |
| 首页 / 主框架 UI | 1,265 | 7,942 | `<PKG>` 等 |
| 数据层 | 578 | 5,723 | `com.alibaba.bee`、`com.alibaba.sqlcrypto`、`com.j256.ormlite` |
| Flutter | 448 | 2,939 | `io.flutter.embedding` |
| Nest / dtnest 新框架 | 385 | 2,462 | `com.imclient.nest` |
| 启动框架 | 119 | 608 | `com.alibaba.imclient.startup`、`<PKG>` |
| Surgeon 插桩框架 | 8 | 20 | `com.alibaba.surgeon` |
| **R8 短名空间（无法按包归类）** | **50,294** | **252,803** | `a/b/c…`、`defpackage`、单字母包 |

> 〔推断〕27.8% 的类落在短名空间，说明IM把**业务模块的包名整体混淆**、只保留框架/SDK 命名空间。定位业务逻辑必须走"入口类 → 调用图"，不能靠包名。

---

## 2. 启动链

### 2.1 继承与入口 〔观察〕

```
android:name = <PKG>
  extends com.alibaba.android.imclientbase.multidexsupport.DDApplication   (classes30.dex)
    extends com.google.android.play.core.splitcompat.SplitCompatApplication
      extends android.app.Application
  implements HWRegisterReceiverANRCompat.IContextWrapper,
             StartServiceANRCompat.IContextWrapper,
             BindServiceANRCompat.IContextWrapper
```

- `LauncherApplication.onCreate()`（`java/sources/com/alibaba/android/<pkg>/LauncherApplication.java`，全文 1,561 行）：只做三件事 —— 记录 `sOnCreateStartTime`、调 `super.onCreate()`、对 `Build.BRAND == "YOUXUEPAI"`（有道派？）移除 `MesaLinkSSLProvider`。**真正的初始化在 `DDApplication` / `DDLaunchContext` 里**。〔观察〕
- `DDApplication` 持有 `DDContext`，并实现 `ViewModelStoreOwner`；`attachDDContext()` 里 `dDContext.attachBaseContext()` 后建 `ViewModelStore`。〔观察〕
- `DDApplication` 已是 **SplitCompatApplication** → 支持 Play Feature Delivery / 动态模块（`com.google.android.play.core.assetpacks.AssetPackExtractionService` 也在清单里）。

### 2.2 分阶段任务框架 〔观察〕

`com.alibaba.imclient.startup` 提供骨架，`<PKG>` 提供实现，按阶段分目录：

| 阶段 | 目录 | 任务类数 | 代表任务 |
|---|---|---|---|
| attach | `startup/attach/tasks` | 11 | `LifeCycleLoggerTask`、`AopFrameworkCrashFix`、`ComponentLifecycleEventCallback`、`LemonMockReceiver`、`auth/WKCustomWrapper` |
| create | `startup/create/tasks` | 4 | `core/HealthChildTask`、`AdbPullHolmesReceiver` |
| preload | `startup/preload` | 2 | `PreloadDDContext`、`FakeEmptyDDContext` |
| provider | `startup/provider/tasks` | 5 | `DiagnosisStatisticTaskV2` |
| idell1 | `startup/idell1/tasks` | 2 | `MMKVStatisticTask`（`Process = m/d/h/b` 过滤） |
| mainlooper | `startup/mainlooper` | 3 | `LaunchMessageCostObserver` |
| safe | `startup/safe/tasks` | 5 | `SafeModeTask`、`SafeStatistic` |
| statistic | `startup/statistic` | 7 | `ANRCanaryStatisticTask`、`ANRStatisticModel` |
| delegate | `startup/delegate` | 12 | `LaunchReceiverDelegate`、`receivers/WebviewDebugModeReceiver` |

任务契约（混淆名）〔观察〕：

```java
// defpackage.vf —— 执行入口
public void d(LaunchContext ctx);
// defpackage.ch —— 进程过滤
public List<Process> b();          // 例：k3o.a(Process.m, Process.d, Process.h, Process.b)
// 任务基类 tf 同时实现两者，子类只覆盖 d()/b()
```

`HealthChildTask` 实例（`startup/create/tasks/core/HealthChildTask.java`）〔观察〕：
- `b()` 返回 `Process.m, Process.d, Process.h, Process.b` → **同一任务按进程分别调度**
- `d(LaunchContext)` 里读 SP `trace_fold_name`、注册 `com.alibaba.<pkg>.updateUserAccount` 广播、按条件启动 `Doraemon.getArtifact(Health.HEALTH_ARTIFACT).startHealthStatistics()`

**[推断]** 这套框架等价于"多进程 × 多阶段"的任务图：同一份任务表按进程过滤、按阶段串/并行执行；`LaunchContext` 是唯一的跨任务上下文（含 Application、进程名、启动原因）。具体任务的注册表（谁把任务塞进调度器）在混淆代码里，**未完整还原**（见 §6 U1）。

### 2.3 冷启动到首页 〔观察 + 推断〕

```
Zygote → LauncherApplication.<init> → attachBaseContext(DDContext) → onCreate
   └─ DDApplication.onCreate → DDLaunchContext(attach/preload/create/…) 任务
        └─ 首帧后 mainlooper 阶段任务（LaunchMessageCostObserver 监控主线程消息耗时）
             └─ LaunchHomeActivity(extends HomeActivityV2).onCreate(:826)
                  └─ HomeTabAppManager / Tab 容器 + dt_plugin_config 槽位装配首页
```

`LaunchHomeActivity` 是 `HomeActivityV2` 子类，`onCreate` 在 `LaunchHomeActivity.java:826`（前置 700+ 行是同文件的内部类/工具方法）。〔观察〕

---

## 3. 多进程模型

`scan/dex-index/processes.tsv`（22 进程 / 1,252 组件）摘要：

| 进程 | 组件 | 职责推断 |
|---|---|---|
| 默认 | 1,183 | 主 UI + `LWPService`（IM 协议）+ `NetworkService`/`XStateService`（网络）+ `APSService`（定位） |
| `:lite1`…`:lite5` | 各 7 | mPaaS Nebula 多开 H5 容器（`H5Activity$H5ActivityN`、`LiteProcessService`、`LogServiceInliteN`） |
| `:push` / `:pushservice` | 4 / 4 | `PushCoreService` 长连接推送 + 厂商通道（HMS/XM） |
| `:mcs` | 3 | 会议 `OwtRemoteService` + `TracingBroadcastReceiverMcsProcess` |
| `:normal_render_proc0` / `:isolate_render_proc0` / `:gpu_process` | 1 / 1 / 1 | 小程序沙箱渲染三件套（`SandboxedPrivilegedProcessService0` / `SandboxedProcessService0` / `GpuProcessService0`） |
| `:tools` / `:reboot` / `:preload` / `:misinstall` | 4 / 3 / 3 / 1 | 日志开关&视频扩展 / 重启恢复 / 预加载（隐私政策、广告）/ 安装引导 |
| `:channel` / `:rklite` / `:heap_analysis` / `:dex2oat` | 3 / 3 / 1 / 1 | 埋点通道 / Rokid AR / Java OOM 分析 / dex2oat |

**[推断]** 动态分析要点：Frida 只挂主进程会漏掉 **H5（lite1-5）**、**小程序渲染（render_proc0/gpu_process）**、**会议（mcs）** 四类关键行为；`frida -U -f <pkg>` 需配合 `--runtime=v8` + 对子进程 spawn 拦截。

---

## 4. 核心框架

### 4.1 Surgeon 插桩（全包骨架）〔观察〕

模式（每个方法、每个构造器、每个匿名类都有）：

```java
private static transient /* synthetic */ ISurgeon $surgeonFlag = null;

public void foo(...) {
    ISurgeon s = $surgeonFlag;
    if (InstrumentAPI.support(s, "1234567890")) {
        s.surgeon$dispatch("1234567890", new Object[]{this, ...});
        return;
    }
    ... 原始逻辑 ...
}
```

- release 下 `$surgeonFlag` 恒 `null` → `InstrumentAPI.support(null, id)` 恒 false → **直走原逻辑**；插桩是"预留的可编程切面"，不是运行时依赖。
- 覆盖面：`LauncherApplication` 单文件 75 处；`HealthChildTask`、`DDLaunchContext` 等全部命中；匿名内部类甚至 `BroadcastReceiver.onReceive` 里也有（见 `HealthChildTask$1`）。
- **价值**：① 它是"阿里内部动态下发逻辑"的载体（`surgeon$dispatch(id, args)` 可按 id 替换整段方法实现）；② dev 门控的开关（`ywm.a()`/`Doraemon.getRunningMode()`）都挂在 `$surgeonFlag` 的注入路径上 —— 见 03-security §6.1/§6.2。

### 4.2 插件化 = UI 槽位/插件模型（不是 dex 插件）〔观察〕

`META-INF/dt_plugin_config/` 共 **28 个 XML**（base/circle/ding/ding_main/home/im/im_fp_configs/lightapp/live/mail/mail_fp_configs/photo/module/…），结构：

```xml
<configs>
  <container className="chat_sessionHome_page">
    <slot name="topStickHeader">
      <plugin className="chat_sessionSearch_stickHeader"/>
    </slot>
    <slot name="session_item_long_click_menus">
      <plugin className="im_session_long_click_menu_list" condition="isFuncAccountConv">
        <plugin className="im_session_menu_stick_on_top"/>
        ...
      </plugin>
    </slot>
  </container>
</configs>
```

- `container`（页面/区域）→ `slot`（插槽）→ `plugin`（插件）+ `condition`（灰度/账号类型条件）。
- **[推断]** 这是"同一份 APK 按组织/灰度装配不同 UI"的机制：改 `condition` 或替换 `plugin` 就能改变首页与会话菜单 —— 动态分析时可作为"看到不同 UI 的原因"的解释，也是改包的合法切入点（不涉及 dex 加载）。
- 真正的**小程序/动态包**走 ariver（`com.alibaba.ariver`）+ `assets/miniapp` 离线包 + `com.alibaba.lightapp` 运行时，与 `dt_plugin_config` 是两套东西。

### 4.3 路由 〔观察〕

`scan/dex-index/routes.tsv`：**2,604 条**路由 / **681 个目标组件**。

| scheme + host | 条数 |
|---|---|
| `https://qr.<host>` | 608 |
| `http://qr.<host>` | 597 |
| `imclient://qr.<host>` | 474 |
| `imclient://imclientclient` | 200 |
| （无 scheme，仅 path 前缀） | 400 |

- 分发器：`<PKG>`（+ `BokuiFullScreen`/`BokuiTransfer`/`BokuiRouter`）〔观察，见 03-security §7.3〕
- `META-INF/dt_plugin_config/dt_scheme_handler.xml` 另有 scheme → handler 映射表。〔观察〕
- **[推断]** 681 个组件暴露在 2,604 条路由上，但 `q01.e()` 对 `phone/password-from-Intent` 类参数做了三重门控（Doraemon mode + 测试账号文件），release 下大多数路由只能"打开页面"不能"带凭据登录"。

### 4.4 数据层 〔观察 + 未知〕

| 层 | 证据 | 状态 |
|---|---|---|
| MMKV | `<PKG>`、`startup/idell1/tasks/MMKVStatisticTask` | 观察 |
| SharedPreferences | `scan/dex-index/sp-names.txt`（100+ 命名空间：`AdvertiseSp`、`AppRegister`、`ControlConfigSP`、`DiagnoseSP`、`DynamicReleaseSG`、`FlutterSharedPreferences`…） | 观察 |
| 加密 SQLite | `com.alibaba.sqlcrypto`(68 类)、`com.alibaba.bee`(72 类)、`com.alibaba.j256`(208 类)、`com.j256.ormlite`(230 类) | 观察 |
| 表结构 / DAO SQL | 全量反编译中 **`CREATE TABLE` 0 命中** | **未知**：建表 SQL 在 native 或运行时拼接 |

**[推断]** 敏感数据（session/token）不落明文 SP：`CookiesIService`/`CookieModel` 走 IDL 服务（05-network §8.2），DB 由 `sqlcrypto` 加密。要拿落盘数据，得先拿 SQLCipher key（`libsg*`/native 侧），这也是抓包之外的第二个"高门槛点"。

### 4.5 线程 / 调度 〔观察〕

- `Doraemon.getArtifact("THREAD")` → `Thread` 对象（`DDApplication.getThread()`），按 `Priority.LOW` 起 `ApplicationMemTrim` 线程组。
- `maf.a().post(runnable)` 是 `DDLaunchContext` 里的默认 Executor（主线程 Handler）。
- 协程：`kotlinx.coroutines.flow/channels` 共 349 类，与 RxJava（`io.reactivex.internal` 471 类）并存。

---

## 5. 三条端到端链路（已定位到入口，字段级未穷尽）

### 5.1 IM 消息 → 通知 〔观察，定位到方法〕

```
LWP/LWS 长连接（laiwang，见 05-network §6）
  → wukong 消息分发（com.alibaba.wukong.*）
    → imclientim 通知层：com.alibaba.android.imclientim.notification.IMNotificationManager
         :103  class IMNotificationManager extends mj1
         :436  buildTextAsync(...)   // 通知文案异步构建，含过期/内容非法分支
         :809  Q(NotificationCompat.Builder, Message)  // 组装：铃声/震动/channel/静默
      + IMNotificationTextBuilder / IMSuccessNotificationManager / MsgNotificationMonitor
```

**关键分支**（`Q()` 内）：`setDefaults(0)` / `setVibrate` / `setSound(Uri)` / `setSound(null)` / `setNotificationSilent()` / `setChannelId(dtChannelA)` —— 即**通知是否响铃/震动完全由消息属性 + 会话设置决定**，改客户端通知行为应改这里而非系统设置。〔推断〕

### 5.2 H5 / 小程序容器 〔观察，定位到组件〕

```
路由（qr.<host> / imclientclient）→ BokuiActivity
  → 判断 URL 类型
     ├─ H5：com.alipay.mobile.nebulacore.ui.H5Activity（进程 :lite1…:lite5）
     │        + nebula/UC WebView 内核（libWebViewCore_7z_uc_*）
     └─ 小程序：com.alibaba.ariver.*（TinyApp）→ com.alibaba.lightapp 运行时
                 渲染进程 :normal_render_proc0 / :isolate_render_proc0 / :gpu_process
```

`available_modules.json`（`res/raw/`）给出的 JSAPI 白名单（`network.request`/`mtop.request`/`user.login`）就是这条链路的**能力边界**。〔观察〕

### 5.3 冷启动 → 首页

见 §2.3。首页装配依赖 `dt_plugin_config/home.xml` + `im.xml` 的槽位与 `condition`。

---

## 6. 未解项

| # | 未解 | 说明 / 下一步 |
|---|---|---|
| U1 | 启动任务注册表（谁把 `ILaunchTask` 塞进调度器） | 混淆在 `defpackage` 里；可在 `com.alibaba.imclient.startup.scheduler.ILaunchTaskScheduler` 的实现类上打断点/找 `add` 调用 |
| U2 | `tf` 基类的阶段/优先级语义 | 目前只确认 `d()`/`b()` 两个契约；`h()` 等 hook 方法语义未还原 |
| U3 | DB 表结构与 SQLCipher key | Java 层无 `CREATE TABLE`；建议从 `com.alibaba.bee` 的 DAO 生成器 + native 侧 `sqlcrypto` 入手 |
| U4 | 50,294 个 R8 短名类的归属 | 需要调用图/字符串交叉；本次只做了入口级定位 |
| U5 | `surgeon$dispatch` 的 id 表与语义 | id 是 10 位有符号整数散列，无明文映射；属 03-security U3（最高价值） |

---

## 7. 产物

| 路径 | 内容 |
|---|---|
| `scan/dex-index/classes.tsv` | 184,177 行类索引（class / dex / 包） |
| `scan/dex-index/package-stats.tsv` | 61,522 行包统计 |
| `scan/dex-index/functional-groups.tsv` | 42 个功能组（类/方法/字段/占比/Top 子包） |
| `scan/dex-index/processes.tsv` | 22 进程 × 组件明细 |
| `scan/dex-index/routes.tsv` | 2,604 条路由 → 681 组件 |
| `scan/dex-index/sp-names.txt` | SP 命名空间清单 |
| `scan/dex-index/plugin-config/*.xml` | 28 个 `dt_plugin_config` 副本 |
