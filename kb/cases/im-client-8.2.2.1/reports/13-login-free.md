# 13 · 没有账号权限怎么进：绕开登录的三条路（含真机实测）

> 背景：目标为「专属IM」OEM 包，登录 = 账号 + **组织（realm/corpId）** + 服务端下发的会话。
> 没有组织权限时，服务端直接拒 —— 这是服务端策略，客户端造不出来（见 `analysis/05-network-api.md` §8.3）。
> 但**验证逆向结论、使用调试面板、改环境抓包，都不需要真的登录**。下面是三条可执行路径。

---

## 1. 结论

| 需求 | 是否需要账号 | 做法 | 状态 |
|---|---|---|---|
| 打开「开发设置」全量面板（改环境 / 覆盖 6 组 endpoint / 注入 uid / mock 扫描 / UT key） | **不需要** | 改包把 `DevSettingActivity` 的 `android:exported` 翻成 true，`adb am start` 直启 | **✅ 真机实测通过**（截图 `tools/patch/shots/ds1-3.png`） |
| 任意方法级改行为（不重签、官方包可用） | 不需要 | Frida 注入 `ISurgeon` 代理（`tools/patches/frida_isurgeon.js`） | ✅ 脚本就绪（需 root/gadget） |
| 让客户端"以为已登录"（假登录态） | 不需要 | `q01` monkey 账号 + `NoLoginSwitchService` 的 `mock_no_login_key_prefix_*` + `ContactInterfaceImpl.X4` | ◐ 机制已还原，未实测 |
| 真正收发消息 / 走业务 | **需要** | 服务端按组织校验，客户端无法伪造 | ❌ 不可绕过 |

---

## 2. 路线 A：把调试面板"挪到登录前"（已实测）

### 2.1 原理

`DevSettingActivity` 在清单里是 `android:exported="false"`（`apktool/AndroidManifest.xml:3667`），
且 `onCreate` 第一道门是 `Doraemon.getRunningMode()==1`（已被 `analysis/11` 的补丁打开）。
把 `exported` 改成 true 后，`adb shell am start` 就能从应用外部拉起它 —— **完全不需要登录**。

### 2.2 实现（字节级改 AXML，不重建）

`tools/patch/patch_manifest.py`：解析二进制 `AndroidManifest.xml`，定位 `<activity>` 的 `android:exported`
属性，把 typedValue 的 data 从 `0x00000000` 改成 `0xFFFFFFFF`（文件长度不变，其它资源引用不受影响）。

```bash
python tools/patch/patch_manifest.py unpacked/root/AndroidManifest.xml tools/patch/out/AndroidManifest.xml \
    com.alibaba.android.user.devset.DevSettingActivity \
    com.alibaba.android.user.settings.activity.DeveloperOptionsActivity
# OK   com.alibaba.android.user.devset.DevSettingActivity
# OK   com.alibaba.android.user.settings.activity.DeveloperOptionsActivity

# rebuild_apk.py 已把 AndroidManifest.xml 加入替换列表
python tools/patch/rebuild_apk.py target.apk tools/patch/out tools/patch/out/imclient_unlocked.apk
apksigner sign ... --out imclient_unlocked_signed.apk imclient_unlocked.apk
```

校验（aapt 读回）：

```text
A: android:name="com.alibaba.android.user.devset.DevSettingActivity"
A: android:exported=(type 0x12)0xffffffff      ← false 已改成 true
```

### 2.3 真机结果

```text
$ adb shell am start -n <PKG>/com.alibaba.android.user.devset.DevSettingActivity
Starting: Intent { cmp=.../DevSettingActivity }
$ adb shell dumpsys window | grep mCurrentFocus
  mCurrentFocus=Window{... <PKG>/com.alibaba.android.user.devset.DevSettingActivity}
```

**未登录状态下直接进入「开发设置」**。界面可见（`tools/patch/shots/ds1.png` / `ds2.png` / `ds3.png`）：

- 左列：`LWS`、`主连接`、`文件通道`、`https`×2、`quic`、`切换`、`IM工`、`刷新`、`VIP` —— 即 **endpoint 覆盖表**（LWS / QUIC / SHORT / OAUTH / ALADDIN / MEDIA_ID / 邮箱 6 组 / ENV）
- 启动时会弹「constant 开关」校验提示（列出 `contact_login_new_flow_user_gray_android`、`general_auth_dynamic_encrypt_enable_v5_android` 等 Gaea 键），说明面板读的是**真实配置中心数据**
- 面板里还有 `et_uid`（注入 uid）、`bt_mock_scan`、`btn_ut_debug_key_gen`、`btn_gaea_config`、`btn_exclusive_debug_license` 等控件（见 `analysis/01` §11.2 的 93 个 id）

> 注：`DeveloperOptionsActivity` 虽然也能被 adb 拉起（`START` 日志有），但它内部还有登录守卫，会跳登录页 —— 它的价值主要在"第三方应用 Debug 开关"，主线用 DevSetting 就够。

### 2.4 这一步能干什么

1. **改环境**：线上/预发/日常切换（`DevSettingActivity_ENV` 0/1/2）。
2. **覆盖域名**：把 LWS/QUIC/OAUTH/ALADDIN/邮件域名指到自己的服务端 —— 配合 `tools/capture.md` 做协议复现，**不需要账号**（能看到的只是 TLS 握手与未登录接口）。
3. **注入 uid**：`et_uid` 可以写一个任意 uid，用于观察客户端哪些逻辑依赖"当前用户"（本地 UI 层面）。
4. **开 mock 扫描 / UT key**：`bt_mock_scan`、`btn_ut_debug_key_gen`。

---

## 3. 路线 B：Frida 注入 ISurgeon（官方包、零改包）

见 `analysis/07-unlock.md` §3 与 `tools/patches/frida_isurgeon.js`。
一次把 `$surgeonFlag` 写进任意插桩类，即可覆盖 **583,595 个 (方法,id)**；不重签 → 不会触发 SecurityGuard 的签名差异，也不需要账号。

适用条件：能 attach（root / gadget）。本机 S10 未 root，只能走路线 A（重签）或先注入 gadget。

---

## 4. 路线 C：假登录态（本地 UI 层）

### 4.1 机制（已还原）

| 组件 | 作用 | 关键点 |
|---|---|---|
| `defpackage.q01` | monkey 测试账号 | `c()` 在 `getRunningMode()==2` 且 `l1r.d(ctx)` 为 `autokey007/010/101` 时返回 assets 里的 `monkey_account_for_*.txt`；`g()` 从 **assets** 读账号列表；`b()` 随机取一个 `Account` |
| `q01.e()` | Bokui 凭据注入闸 | `"autokey008".equals(l1r.d(ctx)) && (mode==2 || mode==1)`；id `-1007060566` |
| `ContactInterfaceImpl.X4(k,v)` | mock 开关落库 | 写 SP `mock_no_login_key_prefix_<k>`；**首行 `if(getRunningMode()==4) return;`** → mode=1 后可达 |
| `NoLoginSwitchService` | 消费这些键 | `u8j.c/a/Q("mock_no_login_key_prefix_"+k)`，控制"免登录"相关分支 |

### 4.2 要真要假登录，需要三步

1. 往 `assets/` 放 `monkey_account_for_default.txt`（格式：每行一个账号，`g()` 按 utf-8 逐行解析）；
2. 让 `l1r.d(ctx)` 返回 `autokey008`（读的是某个文件/SP，需再确认；`l1r` 是混淆过的工具类）；
3. `mode` 设为 2（灰度）——但注意：**mode=2 会让 `DevSettingActivity` 退回精简分支**（`cond_3a`），所以要么用 Surgeon 单独覆盖 `getRunningMode` 的调用点，要么在需要时切回 1。

### 4.3 边界

即使造出 `Account`，**网络层仍然是未登录**：MTOP 需要 `sid/uid/x-sign`，服务端认组织。
所以假登录态只能让**本地 UI 前进**（首页骨架、设置、部分离线页面），不会真的收发消息。
用于"看界面/验证门控"足够，用于"当账号用"不行。

---

## 5. 如果只是想要一个能登录的环境

三条正路（都不用破解）：

1. **自建组织**：IM支持免费创建团队/企业（专属版需要企业认证，但普通团队可自建），用自己建的 org 登录同一客户端 —— 需要该客户端绑定的 realm 允许，OEM 包通常锁定了特定 corpId，未必能登别的组织。
2. **找管理员开权限**：让目标组织管理员给你的账号开成员资格（这是唯一合法的"有权限"路径）。
3. **让服务端配合**：如果是做安全评估，可由甲方提供测试账号 + 测试组织（标准红队做法）。

---

## 6. 复现清单

```bash
# 1) 打 dex 补丁（3 个）
python tools/patch/patch_dex.py tools/patch/out

# 2) 打 manifest（导出 DevSetting / DeveloperOptions）
python tools/patch/patch_manifest.py unpacked/root/AndroidManifest.xml tools/patch/out/AndroidManifest.xml \
    com.alibaba.android.user.devset.DevSettingActivity \
    com.alibaba.android.user.settings.activity.DeveloperOptionsActivity

# 3) 重打包 + 重签
python tools/patch/rebuild_apk.py target.apk tools/patch/out tools/patch/out/imclient_unlocked.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias androiddebugkey --v1-signing-enabled true --v2-signing-enabled true \
  --min-sdk-version 21 --out tools/patch/out/imclient_unlocked_signed.apk tools/patch/out/imclient_unlocked.apk

# 4) 装 + 免登录直启
adb install -r -d tools/patch/out/imclient_unlocked_signed.apk
adb shell am start -n <PKG>/com.alibaba.android.user.devset.DevSettingActivity
```
