# IM 8.2.2.1「专属IM / IM」全量逆向工作区

目标：`base.apk(3).1`（299,485,058 B，SHA-256 `2433588b…d609195`）
结论一句话：**阿里巴巴官方签名的「专属IM enterprise/exclusive」OEM 客户端**，品牌 IM，内核IM 8.2.2.1（689），release、arm64-only、v1+v2 签名完整。

---

## 1. 目录导航

| 路径 | 内容 | 怎么用 |
|---|---|---|
| [`REPORT.md`](REPORT.md) | **总报告**（先看这个） | 身份、结构、功能、安全、协议、可改造点、未解项 |
| [`analysis/00-identity-container.md`](analysis/00-identity-container.md) | 指纹 / 签名 / 清单 / NSC / 反编译覆盖统计 | 复核容器层事实 |
| [`analysis/01-resources-assets.md`](analysis/01-resources-assets.md) | 资源与 assets 全解 | 找界面、文案、品牌、隐藏入口 |
| [`analysis/02-code-architecture.md`](analysis/02-code-architecture.md) | 代码架构 / 启动链 / 核心框架 / 调用链 | 找实现位置 |
| [`analysis/03-security.md`](analysis/03-security.md) | 防护栈 / 反调试 / 抓包对抗 / 开发面板 | 决定 hook 与抓包方案 |
| [`analysis/04-native.md`](analysis/04-native.md) | 152 个 .so 的 ELF/JNI/协议分析 | native 层定位 |
| [`analysis/05-network-api.md`](analysis/05-network-api.md) | 端点清单 / MTOP 签名 / 长连接 / 登录会话 | 接口与协议复现 |
| `unpacked/dex/` | 30 个 `classes*.dex`（220.5 MB） | 需要 smali/字节码级时用 |
| `java/sources/` | **jadx 全量反编译**（84,971 文件 / 598 MB） | 直接读 Java |
| `apktool/` | 清单明文 + resources 解码（values/layout/xml） | 改包、查资源 ID |
| `unpacked/native/arm64-v8a/` | 152 个 .so / 容器 | IDA/Ghidra/readelf |
| `unpacked/assets/` `unpacked/res/` | 原始资源 | 二进制比对 |
| `scan/` | 全部证据（tsv/json/txt） | 追溯每条结论 |
| [`analysis/07-unlock.md`](analysis/07-unlock.md) | 门控开锁（smali 级补丁集） | 改包开面板 |
| [`analysis/08-native-deep.md`](analysis/08-native-deep.md) | zkfv RegisterNatives / SafeGuard CRC / Gaea TLS | native 续攻 |
| [`analysis/09-capture-lws.md`](analysis/09-capture-lws.md) | LWS 加密套件 / 抓包实操 | 抓包 |
| [`analysis/10-poc.md`](analysis/10-poc.md) | 攻击面 PoC（Provider/广播/Service） | 验证漏洞 |
| [`analysis/11-surgeon-unlock.md`](analysis/11-surgeon-unlock.md) | **Surgeon 热修契约 + 字节补丁 + 真机验证** | 解锁版 APK |
| [`analysis/12-live-evidence.md`](analysis/12-live-evidence.md) | 真机实测证据（安装/启动/套接字/trace） | 复现验证 |
| [`analysis/13-login-free.md`](analysis/13-login-free.md) | **没有账号怎么进**（导出补丁直启 DevSetting，已实测） | 免登录调试 |
| [`tools/patch/`](tools/patch) | `patch_dex.py` / `rebuild_apk.py` / 已签名 APK / 截图 | 一键出解锁包 |
| [`tools/frida/unlock.js`](tools/frida/unlock.js) | Frida 解锁脚本 | root/gadget |
| [`tools/poc/`](tools/poc) | ExternalProvider / RequestDispatch 的 Java PoC | 漏洞复现 |
| [`tools/capture.md`](tools/capture.md) | 抓包 playbook（6 步 + hook 清单） | 抓 MTOP/LWS |

`scan/` 子目录：`lead/`（身份与清单证据）、`res/`、`dex-index/`、`security/`、`native/`、`net/`。

---

## 2. 反编译覆盖（重要）

- jadx 1.5.6 全量反编译 30 个 dex → 84,971 个 `.java`。
- 顶层类 90,131：命中 81,891（**90.86%**）。
- 未命中 8,240 = **7,668 个 `ACC_SYNTHETIC`**（编译器产物，jadx 默认跳过）+ **572 个** 因 Windows 大小写不敏感同名覆盖/保存失败。
- 换言：**非 synthetic 顶层类覆盖 99.37%**。

要 100% 字节码覆盖 / 做 smali patch：

```bash
# 逐 dex 反汇编为 smali（需自备 baksmali.jar：org.smali:baksmali:2.5.2）
java -jar baksmali.jar d unpacked/dex/classes.dex -o smali/classes
# 或直接看字节码
D:/Android-SDK/build-tools/36.0.0/dexdump.exe -d unpacked/dex/classes.dex > classes.dex.txt
```

---

## 3. 关键工具链（本机）

| 工具 | 路径 |
|---|---|
| java / keytool | `D:\Android-studio\jbr\bin\` |
| jadx CLI | `D:\jadx-1.5.6\lib\jadx-gui-1.5.6-all.jar`（`jadx.cli.JadxCLI`） |
| aapt / aapt2 / apksigner / dexdump | `D:\Android-SDK\build-tools\36.0.0\` |
| python | PATH 中的 3.12 |

常用命令（路径含括号空格，**整体加引号**）：

```bash
APK='/d/Deepseek-Harness-workspace/re/base_apk3/target.apk'
/d/Android-SDK/build-tools/36.0.0/aapt2.exe dump badging "$APK"
/d/Android-SDK/build-tools/36.0.0/apksigner.bat verify --print-certs --verbose "$APK"
/d/Android-studio/jbr/bin/java.exe -Xmx8g -cp "D:/jadx-1.5.6/lib/jadx-gui-1.5.6-all.jar" \
    jadx.cli.JadxCLI --single-class '<PKG>' \
    -d /tmp/one unpacked/dex/classes3.dex
```

---

## 4. 结论摘要（详见 REPORT.md）

1. 官方构建、非二次打包（v2 整包签名 + 阿里证书 + 全包同一构建时间戳 + `.w2534344268` 贯穿命名空间）。
2. 性质：专属IM/OEM（`FLAVOR=enterprise`、`UA_2ND_TYPE=exclusive`），品牌替换只在名称/图标层。
3. 最大配置面风险：NSC 全局 `cleartextTrafficPermitted=true` + 信任用户 CA；1,252 组件 / 79 exported。
4. 防护栈：SecurityGuard + SafeGuard + ByteHook + Zoloz + 安恒 safechat + crashsdk；`libzkfv_tj.so` 未定性。
5. 内建开发者能力（两套调试面板、环境切换、WebView 远程调试）全部有门控，非 debug 包。
