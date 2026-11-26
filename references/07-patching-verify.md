# 07 · 补丁与验证（三条路线，按侵入性排序）

## 路线 A：运行时 hook（零改包，首选验证手段）

适用：能拿到 root / 能注入 gadget。
优点：不改签名、随时回退；缺点：需要设备权限，不能交付“一个改好的包”。

模板见 `assets/frida_field_hook_template.js`（改字段/返回值）与
`assets/frida_isurgeon.js`（接管整套插桩体系：把目标类的 `$surgeonFlag` 换成自己的实现，
按 id 覆盖任意方法）。机型/构建指纹伪装见 `assets/frida_build_spoof_template.js`。

## 路线 B：字节级补丁（只改常量或单条指令）

适合：改一个布尔初值、改一个 `const/4`、把方法体开头改成 `return`。

规则：
1. **不改变方法长度**（`insns_size` 不变），否则要重排 code_item 与所有偏移；
2. 被替换区域**不能有分支目标**（否则改动要连带跳转）；
3. 改完重算 dex 头：`checksum = adler32(bytes[12:])`、`signature = SHA1(bytes[32:])`；
4. 重新打包要**剔除旧签名**（`META-INF/*.SF/*.RSA/MANIFEST.MF`），再 `apksigner sign`。

`scripts/patch_dex.py` 提供两个现成例子：把静态方法改成 `return true`、把 `<clinit>` 的
`const/4` 立即数改小。`scripts/rebuild_apk.py` 负责替换指定条目并去签名。

替换整个方法体（保留长度）的写法：

```
const/4 v0, #1     ; 0x1012
return v0          ; 0x000f
nop ...            ; 剩余单元填 0x0000（避免校验器对不可达代码报错）
```

## 路线 C：重建（apktool / smali 组装）

改动超过“几个常量”时才用：
```bash
apktool d -f target.apk -o work/        # 含 smali
# 改 smali / manifest / res
apktool b work/ -o rebuilt.apk
apksigner sign ...
```
大包（>200 MB、30 dex）重建很慢，且容易在资源/签名上翻车；优先考虑 A/B。

## 二进制 AXML 补丁（改 manifest 属性）

只改“已有属性的值”时不需要重打包：

1. 解析 AXML：string pool → 遍历 `RES_XML_START_ELEMENT_TYPE(0x0102)`；
2. 找到 `<activity>` 的 `android:name` 匹配目标类；
3. 把 `android:exported` 的 typedValue（`type=0x12`）从 `0x00000000` 改成 `0xFFFFFFFF`；
4. 文件长度不变，其它资源引用不受影响。

`scripts/patch_manifest.py` 是完整实现（含 UTF-8/UTF-16 string pool 解析）。

## 重签与安装

```bash
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias androiddebugkey --v1-signing-enabled true --v2-signing-enabled true \
  --min-sdk-version 21 --out signed.apk rebuilt.apk
apksigner verify --print-certs --verbose signed.apk
adb install -r -d signed.apk        # 签名变了，必须先卸载官方包
```

⚠️ 签名变化 = 客户端指纹变化，见 `05-security.md`：能登录 ≠ 不被风控。

## 真机验证清单

| 检查 | 命令/观察 |
|---|---|
| 装得上 | `adb install` 返回 Success |
| 无校验崩溃 | `logcat \| grep -E "VerifyError\|FATAL EXCEPTION"` 为空 |
| 补丁真的生效 | 反编译回读（jadx `--single-class`）确认语义 |
| 行为生效 | 找“只有补丁后才会出现”的副作用做证：例如 WebView 调试会创建 `@webview_devtools_remote_<pid>` 套接字 |
| 可回滚 | 保留官方包副本，`adb uninstall` + 重装即可 |

## 反模式

- 只改 dex 不重签 → 安装失败；
- 改完不重算 checksum → 运行期 `INSTALL_FAILED_INVALID_APK` 或 dex 校验失败；
- 用 `pm clear` 当“重置”却忘了它同时清登录态；
- 在真实工作账号上验证改包（风控会记录）。
