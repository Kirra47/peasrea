# 00 · 目标身份、容器与清单（Lead 独立复核）

> 复核方式：本机工具链直接对 `target.apk` 重新取证，不依赖任何既往结论。
> 证据目录：`scan/lead/`（badging.txt、manifest_tree.txt、manifest_summary.json、components.tsv、exports.tsv、permissions.txt、dex_totals.json、classes_unique.txt、dex_class_counts.json）。
> 标注约定：**[观察]** = 直接读到的事实；**[推断]** = 由多处证据推出；**[未知]** = 现有静态证据无法定论。

---

## 1. 文件与哈希

| 项 | 值 |
|---|---|
| 原始路径 | `D:\WeChat\install\xwechat_files\wxid_1xp953fspinu22_aacb\msg\file\2026-10\base.apk(3).1`（只读，未改动） |
| 工作副本 | `re/base_apk3/target.apk`（字节一致） |
| 大小 | 299,485,058 B（285.6 MiB） |
| SHA-256 | `2433588b58436a0e55270f2a66c286f0fe7bc41618d7f5e069fc6ef99d609195` |
| MD5 | `740dd2363f55adfc6e8aa7e97024667b` |
| 容器 | ZIP/APK；21,034 条目，无目录条目、无重名、无大小写冲突 **[观察]**；全部条目时间戳 `2026-01-28`（同一次构建） |

**[观察]** 压缩 295.2 MB → 解压 597.9 MB。条目构成：`.xml` 13,128、`.png` 5,955、`.webp` 509、`.json` 214、`.txt` 175、`.so` 152、`.properties` 116、`.race` 77、`.js` 74、`.dx` 72、`.version` 68、无扩展名 64、`.data` 60、`.mp3` 53、`.html` 36。

---

## 2. 应用身份

| 项 | 值 | 来源 |
|---|---|---|
| 包名 | `<PKG>` | badging / BuildConfig |
| versionName / Code | `8.2.2.1` / `689` | badging |
| 应用名 | `IM`（zh/zh-HK/zh-TW/fr/es/…），`IM`（en/ja/ko/th/vi/…） | badging `application-label-*` |
| 入口 | `<PKG>` + 3 个 launcher alias（Type0/1/2）+ `LaunchHomeForEasyGoActivity` | manifest |
| Application | `<PKG>` | manifest |
| SDK | minSdk **21** / targetSdk **33** / compileSdk **35**（platformBuildVersion 15） | badging |
| ABI | **仅 `arm64-v8a`**（152 个 .so，无 armeabi-v7a/x86） | badging native-code |
| 语言 | 25 locale（含 `mk`/`sr` 等小语种） | badging locales |
| 密度 | 120–640 + anydpi | badging densities |
| uses-feature | 7 条 | manifest |

### 2.1 BuildConfig（`java/sources/com/alibaba/android/<pkg>/BuildConfig.java`）**[观察]**

```
APPLICATION_ID = <PKG>
VERSION_NAME   = 8.2.2.1        VERSION_CODE = 689
BUILD_TYPE     = release        DEBUG = false      IS_DEV/IS_GRAY/IS_OPEN_DEV_VERSION = false
FLAVOR         = enterprise     UA_2ND_TYPE = exclusive     ← 专属IM / OEM
CHANNEL_TYPE   = normal         OUTPUT_TYPE = apk  ABI_TYPE = multi
BUILD_ID       = PIS804274115090441216
BUILD_TIME     = 1769561989873  (2026-01-28 08:59:49 +08:00)
MTOP_APPKEY    = 21811227
HUAWEI_APP_ID  = 106761177      HUAWEI_APP_KEY = 39b9c3fd…c3813d
XPN_APP_ID     = 2882303761520174240   XPN_APP_KEY = 5102017451240
MEIZU_APP_ID   = 149451         MEIZU_APP_KEY = f1e72043…d0e191
OPPO_APP_KEY   = a631f59d…ec201c6      OPPO_APP_SECRET = 5327eabb…6675f3
SUPPORT_FCM    = false          DISABLE_ALERT_NOTIFICATION = true
SUPPORTED_LOCALES = en,zh,zh_TW,zh_HK,ja,vi,th,in,ko,ms,ru,fr,es_US,tr,pt_BR,it,de,hi,hu,pl
```

> **[推断]** 这些是客户端公开的第三方推送 AppKey（随包分发、非机密），但可直接用于伪造对应推送通道的客户端身份。

---

## 3. 签名与完整性

`apksigner verify --print-certs --verbose` **[观察]**：

| 项 | 值 |
|---|---|
| v1 (JAR) | **通过** |
| v2 (APK Signature Scheme v2) | **通过**（整包完整性，改动任一字节即失效） |
| v3 / v3.1 / v4 | 无 |
| SourceStamp | 无 |
| 证书主体 | `CN=alibaba, OU=alibaba, O=alibaba, L=hangzhou, ST=zhejiang, C=86` |
| 算法 | RSA-2048 / SHA1withRSA |
| 证书 SHA-256 | `a680d36e6014d4d7b5ec64dc79b576ebe96a48c6dca9121355c946c900e926f2` |
| 证书 SHA-1 | `14cb01e5ec44af73e5e11deba452a68da114acb2` |
| 公钥 SHA-256 | `431db0c6cc9a73b9d5b06e9b2aae060199b331ef5a5ffc4931cfee4023b7d142` |
| 签名者数 | 1 |

**[推断]** v2 覆盖整包 + 阿里证书 → 这是**阿里官方构建产物**，非二次打包；任何修改都必须重签成自有证书，从而破坏与官方签名的等价性（服务端可据此识别改包，实际是否校验需动态确认）。

---

## 4. 清单关键属性 **[观察]**

| 属性 | 值 | 含义 |
|---|---|---|
| `android:allowBackup` | `false` | 禁 adb backup 导出 |
| `android:debuggable` | 未声明（false） | release，非 debuggable |
| `android:testOnly` | 未声明 | 非测试包 |
| `android:usesCleartextTraffic` | `true` | 允许明文 HTTP |
| `android:networkSecurityConfig` | `@0x7f150014` → `res/xml/network_security_config.xml` | 见 §5 |
| `android:requestLegacyExternalStorage` | `true` | 沿用旧存储模型（targetSdk 33 下仅 Android 10 生效） |
| `android:largeHeap` | `true` | 大堆 |
| `android:appComponentFactory` | `androidx.core.app.CoreComponentFactory` | AndroidX |
| 权限 | 152 条 `uses-permission`（唯一 152） | 其中危险/特殊 45 条（含 21 个 launcher 的 `WRITE_SETTINGS` 变体） |

危险/特殊权限（去厂商噪声后的核心项）：`CAMERA`、`RECORD_AUDIO`、`READ/WRITE_CONTACTS`、`READ/WRITE_CALENDAR`、`ACCESS_FINE/COARSE/BACKGROUND_LOCATION`、`READ/WRITE_EXTERNAL_STORAGE`、`READ_MEDIA_IMAGES/VIDEO/AUDIO`、`ACTIVITY_RECOGNITION`、`BLUETOOTH_SCAN/CONNECT`、`POST_NOTIFICATIONS`、`SYSTEM_ALERT_WINDOW`、`WRITE_SETTINGS`、`QUERY_ALL_PACKAGES`、`REQUEST_INSTALL_PACKAGES`、`SCHEDULE_EXACT_ALARM`、`FOREGROUND_SERVICE`。
**无** `READ_SMS`/`SEND_SMS`/`READ_CALL_LOG`/`CALL_PHONE`/`BIND_ACCESSIBILITY_SERVICE`/`BIND_DEVICE_ADMIN` **[观察]**。

### 4.1 组件面

| 类型 | 数量 | exported | exported 且无 permission |
|---|---|---|---|
| activity | 1,052 | 35 | 大部分 |
| activity-alias | 5 | 4 | 4 |
| service | 125 | 15 | 8 |
| receiver | 43 | 23 | 21 |
| provider | 27 | 2 | 2（`ExternalProvider`、华为 `PushProvider`） |
| **合计** | **1,252** | **79** | **68**（其中「exported + intent-filter + 无权限」= **52**） |

多进程（22 个进程名）**[观察]**：默认进程 + `:preload`、`:push`、`:pushservice`、`:mcs`、`:channel`、`:tools`、`:rklite`、`:reboot`、`:misinstall`、`:heap_analysis`、`:dex2oat`、`:gpu_process`、`:normal_render_proc0`、`:isolate_render_proc0`、`:lite1`…`:lite5`、`:playcore_missing_splits_activity`。→ **[推断]** 渲染/小程序沙箱（`liteN`、`render_proc`）+ 推送 + 工具进程的独立化设计。

重点 exported 组件（详见 03 安全报告）：`BokuiActivity`/`Bokui*Activity`（超大路由面）、`owt.conference.debugger.TracingBroadcastReceiver`（无权限广播）、`ExternalProvider`、`SyncService`、`NfcRouterActivity`、`Office365AuthLoginActivity`、`net.openid.appauth.RedirectUriReceiverActivity`。

---

## 5. 网络安全配置（发布态生效）**[观察]**

`res/xml/network_security_config.xml` 解码：

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>   <!-- 信任用户安装的 CA -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

- **无** `domain-config`、**无** `pin-set`、**无** `debug-overrides` → 全域名统一策略。
- 含义：所有走系统 TLS 栈（OkHttp/HttpURLConnection/WebView）的连接都接受用户 CA，**可 MITM**；明文 HTTP 亦被允许。
- **[未知]** 阿里自研网络栈（MTOP/ANet/Gaea/QUIC）是否绕过 NSC、是否自带 pinning → 见 05 网络报告与 03 安全报告的结论。

---

## 6. 代码规模与反编译覆盖

| 指标 | 数值 |
|---|---|
| dex 文件 | 30（`classes.dex` … `classes30.dex`），220.5 MB |
| class_defs | 180,864（唯一 180,862；跨 dex 重复 2） |
| 方法 / 字段 / 字符串 | 1,233,999 / 1,884,431 / 2,053,806 |
| proto / type | 293,317 / 255,950 |
| 顶层包（按类数） | `com.alibaba` 70,696、`com.alipay` 21,769、`com.taobao` 6,885、`com.google` 4,102、`com.imclient` 1,391、`imclient.alipay` 1,369、`com.amap` 1,228、`com.huawei` 1,049、`org.webrtc` 815、`cn.wps` 769、`com.uc` 746 |

### 6.1 全量反编译结果（`java/`）

- 命令：`jadx -d java -j 24 --no-res unpacked/dex/classes*.dex`（jadx 1.5.6，JDK 25，Xmx20g）
- 结果：**84,971 个 .java，598 MB**；jadx 处理单元 59,379（含匿名类内联），报错 283 个方法级错误（不阻断）。
- 覆盖率复核（`scan/lead/classes_unique.txt` 对 `java/sources` 逐个查文件）：
  - 顶层类 90,131 个 → **命中 81,891，覆盖 90.86%**
  - 未命中的 8,240 个中：**7,668 个是 `ACC_SYNTHETIC`**（编译器产物，jadx 默认跳过）；**572 个非 synthetic** 主要是 Windows 大小写不敏感导致的同名文件覆盖（如 `Lf20;`/`LF20;` → `f20.java`）与个别保存失败。
  - 即：**非 synthetic 顶层类覆盖率 99.37%**。要 100% 覆盖字节码，用 `dexdump -d`（见 README）或把 `unpacked/dex` 拷到大小写敏感文件系统上重跑 jadx。
- **[推断]** 180,862 个类中大量为 R8 混淆后的短名（`a00`、`jln`、`e4l`）+ 阿里 Surgeon 插桩（`ISurgeon.surgeon$dispatch("<id>")`），但**框架与 SDK 命名空间未混淆**（`<PKG>.*` 等可读），故功能面可还原。

---

## 7. 解包产物

```
re/base_apk3/
├─ target.apk                     原始副本（只读语义）
├─ unpacked/dex/                  30 个 classes*.dex（220.5 MB）
├─ unpacked/native/arm64-v8a/     152 个 .so / 容器（244.8 MB）
├─ unpacked/res/                  19,344 个资源
├─ unpacked/assets/               1,148 个资源
├─ unpacked/root/                 AndroidManifest.xml + resources.arsc
├─ java/sources/                  jadx 全量反编译（84,971 文件 / 598 MB）
├─ apktool/                       资源与清单解码（见 01 报告）
├─ analysis/                      00–05 六份分析报告
└─ scan/                          证据（lead / res / dex-index / security / native / net）
```

---

## 8. 结论（本文件范围）

1. **[观察]** 目标是**阿里巴巴官方签名的「专属IM」OEM 客户端**（`FLAVOR=enterprise`、`UA_2ND_TYPE=exclusive`），品牌呈现为 IM/IM，内核IM 8.2.2.1（689），release 构建，arm64-only。
2. **[观察]** 签名 v1+v2 通过、证书为阿里 2014 年签发、全包时间戳同一构建会话、包名后缀 `.w2534344268` 贯穿自定义权限/authority/内部命名空间 → 构建期 applicationId 改名，**不是二次打包**。
3. **[观察]** 最大配置面风险：NSC 全局明文 + 信任用户 CA；1,252 组件 / 79 exported / 68 无权限保护。具体可达性与鉴权强度见 03。
4. **[未知]** 服务端是否校验签名/包名、改包后能否登录 → 只能动态验证（见 03 §Frida 与抓包建议）。
