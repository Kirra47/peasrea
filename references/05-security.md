# 05 · 安全栈与风控（改包前必须算清代价）

## 先做“有没有壳”的判断

| 特征 | 结论 |
|---|---|
| 只有 `classes.dex` 很小、`assets/` 里有大文件、`Application` 被替换 | 可能是整体加固（梆梆/爱加密/腾讯乐固/360） |
| dex 完整、方法头有统一插桩样板 | 不是壳，是**字节码插桩**（如阿里 Surgeon），可按 id 运行时替换 |
| `libsgmain*.so` + 签名迷你 APK + `.ucb` 加密体 | SecurityGuard（支付宝安全），反篡改/设备指纹/wua |
| `libsafeguard.so` + `libbytehook.so` | 服务端驱动的 DLP/反 Hook（命令下发式） |
| `libfacedevice.so` + `libtoyger*.so` | Zoloz 人脸/设备风控（检测名单常在这里） |

**检测名单往往不在你以为的库里**：本案例中“安恒 libsafechat”完全没有任何 frida/root 检测，
名单实际在 `libfacedevice.so`（hook 框架 20 项、root 家族 12 项、模拟器 40+ 路径）。

## 三类检测的实际强度（经验）

| 检测 | 常见实现 | 现实强度 |
|---|---|---|
| Java 层反调试 | `Debug.isDebuggerConnected`、`TracerPid` | 很多只是“降噪/埋点”，**不一定退出**；先确认触发后的行为 |
| native 反注入 | `/proc/self/maps` 扫 frida/riru、inline hook CRC | 强；`.text` CRC 自比对（磁盘 vs 内存）不需要服务端就能发现 |
| 完整性 | APK v2/v3 签名 + `wua` 型客户端指纹 | 最强的一环：**改包即改变指纹**，服务端可据此降权/告警 |

## 改包的代价（真实案例结论）

重签后的包：
- 能过**登录**（账号密码/OAuth 都正常）；
- 但客户端指纹（wua/securitybody）带上“非官方签名”，服务端可：
  - 拒绝长连接（表现为一直「连接中...」）；
  - 给组织管理员推送安全告警（DING）；
  - 限制支付/人脸/扫码等 signature 级能力。
- 结论：**“能登录”不等于“没被发现”**。

## 反调试/反注入的绕过优先级

1. 先确认到底哪一层在拦（日志/行为），不要盲 hook；
2. 优先在**不被 CRC 覆盖**的模块上做（本案例 SafeGuard 的 CRC 名单是 8 个库，不含 `libart`）；
3. 不要 patch 保护库自身（自比对会命中）；
4. 服务端侧校验（wua）无法在客户端“绕过”，只能改包后接受降权，或保持官方签名。

## 权限与组件面

评估 exported 组件时，看三件事：
- `exported` 是否 true；
- 是否声明了 `permission`，以及该 permission 的 `protectionLevel`（`normal` = 任何 App 声明即得）；
- 组件内部是否真的校验调用方（很多 `getCallingUid` 根本不调用）。

本案例两个真实风险点：
- 一个 exported 无权限的 `BroadcastReceiver`：任意 App 一条广播即可触发全进程方法级 tracing；
- 一个 `protectionLevel=normal` 的 provider：任意 App 可读登录态相关布尔。

## 复现与取证

- 只读观测脚本见 `scripts/observe_readonly.sh`（不安装、不清数据、不点屏）；
- 关键证据：`dumpsys package`、`pm path` + APK 哈希比对、`/proc/net/tcp` 远端 IP 快照、logcat；
- 抓包现实：先判断 TLS 在不在平台栈（见 `06-protocol.md`），再决定用代理还是 hook。
