# 14 · 真机实测：重签解锁包 + 真实账号登录（成功）

> 设备：`R5CX12GQBZR` / SM-S9280（Galaxy S24 Ultra）/ Android 16（API 36）
> 目标包：`<PKG>` 8.2.2.1(689)
> 结论：**重签（debug 证书）+ 三个 dex 补丁 + manifest 导出补丁的包，可以用真实账号正常登录并加载业务数据；SecurityGuard 未拦截。**
> 证据目录：`scan/runtime/`（logcat_login.txt 93,325 行、截图、tcp 快照、官方 APK 备份）

---

## 0. 时间线

| 时间 | 动作 | 结果 |
|---|---|---|
| 20:18 | 设备授权 | `R5CX12GQBZR device` |
| 20:18 | 拉取手机上的官方包 | `official_S9280.apk`，SHA-256 = `2433588b…d609195` → **与我们的 `target.apk` 字节完全一致** |
| 20:18 | 备份外部存储 | `scan/runtime/ext_files/`（6.5 MB：login_status、doraemon_records、mozirtc 日志、amap 数据） |
| 20:19 | `adb uninstall` | Success（登录态/数据一并清除） |
| 20:20 | 安装 `imclient_unlocked_signed.apk` | Success；签名方案 v3、证书为本地 debug key |
| 20:20 | 冷启动 | 正常；弹一次「constant 开关」提示（`mode=1` 触发 Doraemon 自检） |
| 20:21–20:22 | **用户手动登录**（账号 <ACCOUNT>） | **成功**：OAuth2 授权 → 回跳 → 进入 `LaunchHomeActivity`，消息列表加载真实数据 |
| 20:23 | `am start …DevSettingActivity` | **直接打开**（未登录时也已验证；登录态下同样可用） |

---

## 1. 登录链路（logcat 实证）

```text
https://login.<host>/oauth2/challenge.htm
    ?redirect_uri=https%3A%2F%2Flogin.<host>%2Flogin%2Fcall_back.htm
    &response_type=code&client_id=<REDACTED_OAUTH_CLIENT_ID>
→ https://login.<host>/***/oidcCallBack.htm
→ 首页工作台 H5：https://n.<host>/dingding/h5-worktab/index.html
    ?appUuid=SWAPP-…&corpId=<REDACTED_CORP_ID>
```

- 登录形态：**OAuth2 授权码**（`client_id=<REDACTED_OAUTH_CLIENT_ID>`），不是早期扫码直连。
- 组织标识：`corpId=<REDACTED_CORP_ID>`（工作台 URL 直接带出）。
- 登录过程中没有任何 `wua` / `securitybody` 失败日志；`SecurityGuard` 仅出现 5 次普通日志。
- 关键 DNS：`login.<host>`、`n.<host>`、`static.<host>`（1,792 次）、`down-cdn.<host>`（1,393）、`package.<host>`、`minipkg.<host>`、`file.<host>`、`qr.<host>`、`gw.alicdn.com`。

---

## 2. 结论（对之前假设的修正）

| 之前的推断 | 实测结果 |
|---|---|
| 重签会破坏 SecurityGuard（wua/securitybody）→ 登录/支付大概率失败 | **登录不受影响**。至少「OAuth 登录 + 会话建立 + 消息列表 + 工作台 H5」这条主链路对签名变化不敏感 |
| 需要账号才能验证改包可行性 | 已验证：**改包可用**，且这是同一份字节一致的官方包改的 |
| 开发者面板只能靠 hook | 不需要：`exported=true` + `am start` 直启，**登录前后都能进** |

> 仍然未知：支付、人脸、扫码、推送等 **signature 级 / 服务端风控**能力在重签包上是否降级（需要具体业务触发才能验证）。

---

## 3. DevSetting 面板（真实登录态）

截图 `scan/runtime/devsetting_loggedin.png`，可见控件（与 `analysis/01` §11.2 的 93 个 id 对应）：

- **LWS 环境**：日常 / 预发 / **线上（当前高亮）** / 新加坡预发 / 新加坡线上 / 主干 / 项目
- 主连接、文件连接输入框；`https://login.<host>`、`https://resolver.<host>`；quic
- 操作：切换 / 断开 lwp / 恢复 lwp
- **RPC 请求历史**、**下行消息历史** ← 这两块直接暴露 MTOP 请求与 IM 下行包，**不需要抓包**
- IM工具箱、刷新 VIP、VIP 信息（主连接/文件连接 IP）、功耗测试、mock 扫描、UT key 生成

> 风险：点「预发/日常/主干」会切环境 → 当前会话失效、需要重新登录；「断开 lwp」会断长连接（可恢复）。这些**未执行**，等你确认。

---

## 4. 副作用与风险

| 项 | 说明 | 处理 |
|---|---|---|
| 每次冷启动弹「constant 开关」 | `Doraemon.sMode=1` 触发 debug 自检 | 可出「无弹窗版」：`mode` 回 4，只把 `DevSettingActivity.onCreate` 的门控改成 `goto` 全量分支 |
| 登录态在非官方签名包上 | 企业侧若有终端合规/设备管理策略，可能被标记 | 测完建议换回官方包（`scan/runtime/official_S9280.apk`） |
| 支付/人脸/扫码 | 未验证 | 需要时再单项测试 |
| 数据 | 卸载已清空本地数据，重新登录后从服务端同步 | 已知 |

---

## 5. 恢复官方包

```bash
adb uninstall <PKG>
adb install scan/runtime/official_S9280.apk
```

---

## 6. 下一步（按价值/风险排序）

| # | 动作 | 价值 | 风险 |
|---|---|---|---|
| 1 | 打开「RPC 请求历史」「下行消息历史」，导出真实 MTOP api 与 IM 包结构 | **高**（协议层实证，替代抓包） | 低（只读面板） |
| 2 | DevSetting 里把「登录域名」临时指向本地 mitmproxy，观察未加密字段 | 中 | 中（会断线，可改回） |
| 3 | 触发 `TracingBroadcastReceiver`，验证登录态下的方法级 trace | 中 | 低（写 8 MB 文件） |
| 4 | `chrome://inspect` 连工作台 H5，看 cookie/token 注入 | 中 | 中（涉及账号凭据，需你同意） |
| 5 | 出「无弹窗版」补丁包 | 体验 | 低 |

---

## 7. 补记：RPC / 下行消息历史页为空的原因（已定位）

- 入口：DevSetting →「RPC请求历史」→ `imclient://qr.<host>/dev/rpc_dev` → `RpcDevHistoryActivity`；「下行消息历史」→ `PushDevHistoryActivity`。
- 数据源：`defpackage.zz6`（`implements NetInterceptor`）的**内存单例**，`zz6.b().g()` / `.f()`。
- 结论：**只有在该页面被打开（单例首次创建）之后发生的 LWP RPC / 下行消息才会入列**；登录流量发生在此之前，所以打开时是空列表。页面本身没有持久化，也没有"开始录制"开关。
- 因此要在真机拿到 RPC 历史，需要在**登录后先打开该页一次**（创建单例），再产生流量（切工作台/收发消息），最后回到页面查看。
- 更彻底的做法：改包在 `LauncherApplication.onCreate` 里提前调用 `zz6.b()` 完成注册，之后全量记录。
