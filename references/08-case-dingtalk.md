# 08 · 案例复盘：IM / IM 8.2.2.1（180,864 类 / 152 个 .so）

本文件把一次完整逆向的**结论与边界**固化下来，避免重复踩坑。详细证据见该项目的
`analysis/00–14` 与 `scan/`（本技能 `kb/` 里收了摘要并做了全文索引）。

## 目标画像

| 项 | 值 |
|---|---|
| 包 | `<PKG>`（专属IM/OEM 构建，构建期 applicationId 改名） |
| 版本 | 8.2.2.1 (689)，release，arm64-only，minSdk 21 / targetSdk 33 |
| 规模 | 30 dex / 180,864 类 / 1.23M 方法；152 个 so（244 MB）；19,344 资源 |
| 签名 | v1+v2 通过，证书 CN=alibaba；改包必须重签 |
| 反编译 | jadx 全量 84,971 个 .java / 598 MB；非 synthetic 顶层类覆盖 99.4% |

## 做成了什么

1. **无账号进入调试面板**：把 `DevSettingActivity` 的 `android:exported` 用 AXML 字节补丁
   改成 true，`am start` 直启；配合把调试模式常量改成 1 过掉门控。
2. **WebView 远程调试**：触发条件满足后出现 `@webview_devtools_remote_<pid>`，可 `chrome://inspect`。
3. **协议文档化**：MTOP 签名原文 22 字段、LWS 帧格式与 AEAD 算法、Gaea 静态内嵌 TLS。
4. **native 深挖**：SecurityGuard 段表破坏还原、`java2jni` 产物定性、
   RegisterNatives 表用“长度一致性”100% 还原、SafeGuard 的 CRC 自比对模型。
5. **攻击面**：一个 exported 无权限广播（可触发全进程 tracing）、一个 `normal` 级读权限 provider。

## 没做成（重要，别再试）

| 想法 | 结论 | 原因 |
|---|---|---|
| 改包后正常使用 | ❌ | 重签改变客户端指纹 → 长连接被拒、组织侧安全告警 |
| 两台手机同时在线 | ❌ | 服务端会话策略；伪装成平板（型号+屏幕）后仍被踢 |
| 换机免“解绑” | ✅（意外发现） | 其实没有设备绑定，直接登新机、旧机被踢下线即可 |
| 远程打卡 | ❌ | 位置可伪造但 `isFromMockProvider` 会上报；人脸/闸机是硬件+服务端；服务端有轨迹异常模型 |
| 用 Surgeon 热修通道加载自己的补丁 | ❌（官方包） | `SecurityChecker` 用**运行包自己的签名**校验补丁，官方包拒第三方补丁 |

## 机制层面值得记住的几条

- 插桩样板 `if (InstrumentAPI.support($flag, "<id>")) { dispatch; return; }` 是“官方热修”的入口：
  拿到 id 表 + 一个 `ISurgeon` 实现，就能在运行时替换任意方法（本案例 583,595 个 (方法,id) 对）。
- 设备身份：`utdid` 明文存在 `shared_prefs/PreferenceUtils.xml`（`UTDID2`/`utdid`），
  MTOP `deviceId` 在 `MtopConfigStore.xml`，`umid` 在 `app_SGLib/`（加密）。
  克隆身份能“冒充旧设备”，但**不能**让两台设备同时在线（同身份会互踢）。
- 抓包瓶颈不在 pinning，而在 **TLS 是否在平台栈**。

## 教训（写给未来的自己）

1. 先判断“这是服务端策略还是客户端逻辑”，再决定要不要改包；
2. 任何改包都要在**测试账号/备用机**上验证；
3. “能登录”不等于“没被发现”，客户端指纹是最强的一环；
4. 调试面板动完要还原：`DevSetting` 的保存会把空输入框写成空值，直接导致长连接起不来
   （现象是永远「连接中...」，日志里 `Aladdin Force Update Disconnect`）。
