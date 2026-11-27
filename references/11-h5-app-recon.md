# 11 · H5 / 微应用侦察（零信任网关后面也能看清）

企业 App 里越来越多功能是 H5 或小程序做的：考勤、审批、工会、商城、报销……
它们不在 APK 里，抓不到包就等于没看见。这篇讲怎么把这类目标从「点开看看」变成「接口地图」。

## 0. 先判断它是哪种形态

| 现象 | 形态 | 落盘位置 |
|---|---|---|
| 打开后是 `CommonWebViewActivity`、`WebViewActivity` 之类宿主 | **H5 微应用** | 不落盘，只有 URL |
| 打开后是 `Nebula`/`Ariver` 容器，`/data/data/<pkg>/files/*ariverPackages*` 出现新目录 | **小程序** | `<appId>/<hash>/<appId>.tar` |
| 打开后进入独立 Activity，有 `assets/` 资源、原生控件 | 原生模块 | APK 内 |

判定命令（Android）：

```bash
adb shell dumpsys window | grep mCurrentFocus           # 看宿主 Activity
adb shell "su -c 'ls /data/data/<pkg>/files/dingtalkTheOne/ariverPackages/installed'"  # 小程序
adb shell ls /sdcard/Android/data/<pkg>/files/nebulaDownload                            # 小程序下载区
```

小程序包解出来是标准结构（`appConfig.json` / `index.js` / `api_permission`），直接可读；
**H5 则要看网络**。

## 1. H5 的抓包前提：TLS 在哪一层

先读 APK 的网络安全配置：

```bash
aapt2 dump xmltree app.apk res/xml/network_security_config.xml
```

- `cleartextTrafficPermitted` + `trust-anchors user` → 用户 CA 可解（本文路线）；
- 只有 system anchors → 需要 root 把 CA 塞进系统库（下面第 2 步）；
- 自研 native TLS（BoringSSL 静态链入）→ 代理无效，只能 hook `SSL_read/SSL_write`。

## 2. 把 CA 装进系统信任区（root）

Android 用户 CA 存于 `/data/misc/user/0/cacerts-added/`，文件名是 **subject_hash_old**：

```python
# 计算文件名：MD5(der(subject)) 前 4 字节小端
from cryptography import x509
import hashlib
cert = x509.load_pem_x509_certificate(open("mitmproxy-ca-cert.pem","rb").read())
name = hashlib.md5(cert.subject.public_bytes()).digest()[:4][::-1].hex() + ".0"
```

```bash
adb push mitmproxy-ca-cert.pem /data/local/tmp/<hash>.0
adb shell su -c 'mkdir -p /data/misc/user/0/cacerts-added && \
  cp /data/local/tmp/<hash>.0 /data/misc/user/0/cacerts-added/<hash>.0 && \
  chmod 644 /data/misc/user/0/cacerts-added/<hash>.0 && \
  chown system:system /data/misc/user/0/cacerts-added/<hash>.0 && \
  chcon u:object_r:misc_user_data_file:s0 /data/misc/user/0/cacerts-added/<hash>.0'
```

系统级 CA 在 Android 10+ 位于 APEX（`/apex/com.android.conscrypt/cacerts/`），
直接写 `/system` 会失败；**用户 CA 目录仍然有效**，且对声明了 `trust user` 的 App 立即生效。

## 3. 代理：优先 `adb reverse`，别折腾局域网

```bash
adb reverse tcp:8080 tcp:8080          # 设备 8080 → 本机 8080，免防火墙、免同网段
adb shell settings put global http_proxy 127.0.0.1:8080
mitmdump -s mitm_addon.py --listen-host 127.0.0.1 --listen-port 8080 --set block_global=false
```

抓完必须还原（否则手机断网就是你自己的锅）：

```bash
adb shell settings put global http_proxy :0
adb reverse --remove-all
adb shell su -c 'rm -f /data/misc/user/0/cacerts-added/<hash>.0'
```

## 4. 识别零信任 / SDP 网关

如果业务域名 **CNAME 指向 `atrust*.xxx` / `sdp*.xxx`**，或响应里出现 `sf_request_type=ajax`，
说明前面挡着深信服 aTrust（或同类 SDP）：业务站点被网关代理，会话靠 `sdp_app_session` cookie。

特征 cookie：

```
atrust.<domain>   sid / sid-legacy / sdp_limit_auth_tag / straceid   （均带 .sig 签名）
<app>.<domain>    sdp_app_session-443 / sdp_app_session-legacy-443
```

含义：
- 业务接口**没有自己的 token 头**，鉴权在网关；
- cookie 拷到 PC **无效**（绑定设备指纹 + 隧道）；
- 新设备首次登录会走短信/扫码二次认证。

所以：**只能在设备上抓**，而且抓完拿到的是「业务接口形状」，不是「可复用的凭据」。

## 5. 接口归并

抓到的请求按路径归并，去掉静态资源（`/assets/`、`/uploads/`），保留 `/api/`、`/sf-webproxy/`。
关注三件事：

1. **信封格式**：`{code,message,data}` 还是裸 JSON？
2. **id 空间**：`modules/4,5,6,7,15,18,19,21` 这种稀疏 id = 后台 CMS 配置出来的；
3. **权限字段**：`isAdmin`、`debugEnabled`、`role` 出现在响应里，说明前端据此渲染（服务端是否复核另说）。

## 6. 报告结构（可直接套用）

```markdown
1. 链路图        谁在哪一层（App → 网关 → 业务站）
2. 认证流程      免登换码 / 二次验证 / cookie 名
3. 模块表        id → 名称 → 模板类型
4. 接口清单      方法 / 路径 / 参数 / 用途
5. 数据结构      关键响应的字段树（不要贴真实值）
6. 观察          只读结论，不做漏洞定性
7. 复现步骤      证书 / 代理 / 还原
8. 数据处置      含 PII 的抓包不要外传
```

## 7. 边界（写给动手的人）

- **只读**：浏览、详情、列表都可以；提交、报名、下单、删除不要碰——一碰就从观察者变成当事人；
- **只自己账号**：不做越权试探，除非这是你自己的系统或已获授权；
- **只低压**：界面点得出来就点，别去枚举 id 扫描——那是另一个性质的动作，会留 WAF 记录；
- **抓包即敏感**：`capture.jsonl` 里有姓名、工号、部门、内部邮箱，属于公司数据。

## 8. 工具

```bash
# 一键配置 / 还原（封装第 2、3 步）
python scripts/h5_capture.py setup --serial <serial>
python scripts/h5_capture.py restore --serial <serial>

# 抓包前脱敏（导出给别人前跑一遍）
python scripts/sanitize_capture.py capture.jsonl -o capture.public.jsonl
```
