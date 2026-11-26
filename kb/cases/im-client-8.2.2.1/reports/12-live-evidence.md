# 12 · 真机实测证据（Samsung SM-G9730 / Android 12 / 未 root）

> 测试对象：`tools/patch/out/imclient_unlocked_signed.apk`（补丁版，debug 证书重签，v1+v2+v3）
> 设备：`R28M30LTRKT` / SM-G9730 / Android 12 / 未 root
> 原始包 `target.apk` 未改动；以下均为本机 adb 实际操作记录。

---

## 1. 安装与启动

| 步骤 | 命令 | 结果 |
|---|---|---|
| 安装 | `adb install -r -d imclient_unlocked_signed.apk` | **Success**（285 MB 流式安装） |
| 启动 | `adb shell monkey -p <PKG> -c android.intent.category.LAUNCHER 1` | 进程起来，`LaunchHomeActivity` onResume |
| 首次引导 | 日志 `checkExportedActivityStartup and exit in LaunchHomeActivity` → `System.exit(0)` | 这是**首次启动的正常分支**：转 `PrivacyPolicyActivity`（见 `ExportedActivityUtils.a()`，非反调试） |
| 隐私协议 | 点「同意」（`input tap 540 1660`） | 进入 `NoLoginCommonWebViewActivity`（登录 H5） |
| 异常 | `logcat \| grep -E "VerifyError\|FATAL"` | **0 命中** —— 字节补丁没有破坏 dex 校验 |

截图：`tools/patch/shots/s2.png`（隐私协议）、`s5.png`（登录 WebView）。

---

## 2. 补丁生效证据：WebView 远程调试套接字

登录页是 WebView。原版（`Doraemon.sMode=4`）下，`setWebContentsDebuggingEnabled` 受门控不会打开；补丁版（`sMode=1`）后：

```text
$ adb shell cat /proc/net/unix | grep devtools
@webview_devtools_remote_26230      # 第一版（仅 ywm + <clinit> 两个补丁）
@webview_devtools_remote_31945      # 第二版（+ setRunningMode no-op，三补丁终版）
```

- 套接字名带的是主进程 pid（26230）→ WebView 调试已在主进程启用。
- 对应代码：`Available<pkg>WebView.H3()/K3()`、`RuntimeWebViewLayout.D0()`（见 `analysis/03-security.md` §6.4）。
- 结论：`Doraemon.sMode=1` 补丁**在真机运行期生效**，不是静态错觉。

---

## 3. 攻击面实测：`TracingBroadcastReceiver`

```text
$ adb shell am broadcast -a imclient.mcs.start_tracing \
    -n <PKG>/owt.conference.debugger.TracingBroadcastReceiver
Broadcasting: Intent { act=imclient.mcs.start_tracing ... }
Broadcast completed: result=0

$ adb shell ls -la /sdcard/Android/data/<PKG>/files/mcs/
-rw-rw---- 1 u0_a328 sdcard_rw 8977716 2026-10-27 19:59 mcs_trace.trace    ← 8.9 MB
```

拉取头部确认是 ART 方法级 trace（`*version\n3\ndata-file-overflow=true`，`tools/patch/shots/mcs_trace_head.bin`）。

- **无需任何权限、无需登录**，一条广播即触发全进程方法级采样，产物落在**外部存储可读路径**（`/sdcard/Android/data/<pkg>/files/mcs/`）。
- 危害：任意第三方 App 可让IM持续写盘（Doze/IO 压力）+ 事后可读的 `.trace` 暴露类名/方法名/调用时序（对逆向与指纹识别是现成情报）。
- 停止：同 action 的 `imclient.mcs.stop_tracing`。

---

## 4. `mock_nologin_switch` 联动（未完成验证）

补丁版 `sMode=1` 后，`ContactInterfaceImpl.X4` 的 `if (getRunningMode()==4) return;` 不再命中，路由变为可达：

```text
$ adb shell am start -a android.intent.action.VIEW \
    -d "imclient://imclientclient/action/mock_nologin_switch?key=mock_demo&value=1" \
    -n <PKG>/<PKG>
```

日志出现 `consant_key_error at UrlUtils.Q`（参数名要求特定 key，且未登录上下文不完整），**未完成落库验证**——需要登录态和正确 key 名（`mock_no_login_key_prefix_*`）。

---

## 5. 局限

1. 未登录 → 设置页/DevSettingActivity 无法从 UI 触达；`ywm.a()` 补丁的**运行期**效果只能静态证明（`a(){return true;}`）。
2. `DevSettingActivity` 里还有服务端 `dev_setting` 灰度（`ContactInterface.v1().y0("dev_setting")`）—— 若服务端关闭，mode=1 仍能进页面（`getRunningMode()==1` 在 or 的最左边，短路成立），此项无影响。
3. 改包签名变化 → SecurityGuard 的 wua 会带"非官方签名"，**服务端是否拒绝**未验证（需账号）。
