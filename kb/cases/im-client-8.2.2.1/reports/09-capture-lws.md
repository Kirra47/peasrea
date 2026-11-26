# IM 8.2.2.1 专属版 — 协议续攻：LWS 加密 / Gaea TLS / appSecret（task-8）

- 目标：`<PKG>`，MTOP_APPKEY `21811227`
- 输入：`unpacked/native/lib/arm64-v8a`（152 个 .so，本轮实测符号用 pyelftools + capstone）+ `java/sources`（jadx 全量）+ 上一轮 `analysis/05-network-api.md`
- 产物：本文件 · [`scan/net/lws_crypto.md`](../scan/net/lws_crypto.md)（算法/伪代码/验证点）· [`tools/capture.md`](../tools/capture.md)（可执行 playbook）· `scan/net/_tools/{elftool,a64dis}.py`（只读解析脚本）
- 记号：**[观察]** 代码或 ELF 符号直证；**[推断]** 证据链推出；**[未知]** 静态不可判定

---

## 1. 三个问题的直接答案

| # | 问题 | 答案 | 置信度 |
|---|---|---|---|
| ① | `CIPHER_SUITE=0` 的真实算法与 KDF | **X25519 ECDH + ChaCha20-Poly1305（libsodium 非 IETF：8B nonce / 16B tag / 无 AAD），无 KDF**（原始共享密钥直接当 key）；`HelloResponse.SIGN` 用 **Ed25519** 验签 | **高** |
| ② | Gaea 出网 JNI 入口 + TLS 是否走 libssl-dd + SSL_read/write hook 能否看到明文 | 入口 = `Java_com_imclient_gaea_http_jni_GaeaHttpNative_00024CppProxy_executeNative`（HTTP）/ `Java_com_imclient_gaea_jni_GaeaLwpNative_00024CppProxy_sendNative`（LWP 长连接）；**TLS 不走 libssl-dd**，Gaea 静态内嵌 **OpenSSL 1.1.1h-dev**（`libgaea.so` 自带 `SSL_read/SSL_write` 导出）；**hook `libgaea.so!SSL_write/SSL_read` 能看到 TLS 明文，但看到的是 LWS 帧（body 仍是 ChaCha20 密文）** | **高**（符号直证） |
| ③ | `appSecret` 在 native 还是服务端 | **既不在 Java、也不在服务端下发**：全包（Java 字串 + 152 个 .so + assets）**无 appSecret 明文**，`appkey` 也只以常量出现在 Java；签名由 SecurityGuard 在 native 内部完成，secret 属 SG 的**加密静态数据存储**（随包、按索引取，设备侧不可读明文）。本地 HMAC 兜底类 `mtopsdk.security.b` 在本包**无构造点**（死代码） | **中高**（需 V6 动态确认） |

---

## 2. ① LWS 加密套件与 KDF（详解见 `scan/net/lws_crypto.md`）

### 2.1 关键代码（Java，classes21/24）**[观察]**

```java
// ClientCodec.<init>
e78 kp     = new e78();                       // priv=random(32); pub=X25519_base(priv)
d43 cipher = new d43(kp.b(serverPubKey));     // key = X25519(priv, serverPub) —— 32B，无 KDF
hello = packer.c((byte)0 /*CIPHER_SUITE*/, kp.a(), sni, null, ua,
                 cipher.a() /*APP_NONCE 8B*/, cipher.e() /*SERVER_NONCE 8B*/, via);

// d43（StreamCipher 实现）
d43(byte[] key){ if (key.length != 32) throw new RuntimeException("chacha20 key err"); }
encrypt -> SodiumJNI.crypto_aead_chacha20poly1305_encrypt(..., ad=null, adLen=0, nonce=b(), key)
decrypt -> SodiumJNI.crypto_aead_chacha20poly1305_decrypt(..., ad=null, adLen=0, nonce=c(), key)
encryptAdditional() = 16                       // tag 长度
b()/c() = 8 字节基值「先 +1 再使用」；a()/e() = 未递增基值（握手用）
```

### 2.2 Native 证据（地址级）**[观察]**

`libkaliumjni.so`（112 KB，NEEDED 仅 `libc/libm/libdl` ⇒ libsodium 静态链入）**只有 9 个导出**，全部与 LWS 相关：

```
0x325c sodium_init                     0x3324 crypto_scalarmult_base   (216B)
0x3260 sodium_version_string           0x33fc crypto_scalarmult        (304B)
0x32a0 randombytes_buf                 0x352c crypto_aead_chacha20poly1305_encrypt (1168B)
0x3320 randombytes_close               0x39bc crypto_aead_chacha20poly1305_decrypt (1176B)
                                       0x3e54 crypto_sign_ed25519_open (864B)
```

**没有 `*_ietf_*`、没有 sha256/hkdf/blake2/aes** ⇒ KDF 不存在、AEAD 是非 IETF 变体，二者皆由"导出符号即可枚举"直接钉死。
内部核心：`chacha_enc/dec` 末尾均 `bl #0x3200`（chacha20-poly1305 公共实现），其余 `bl` 目标是 JNI 辅助（`0x2fd0/0x3110/0x3190/0x31e0`，Get/ReleaseByteArrayElements、ThrowNew 等）；`scalarmult` 的 304 字节包装内**没有指向独立 crypto 函数的直接 `bl`**（X25519 被内联/间接调用），故 X25519 只能按"libsodium 语义"认定。

`libgaea.so` 内嵌同一套原语（native LWP 用）：`crypto_aead_chacha20poly1305_encrypt@0x602af4`、`_decrypt@0x602ea4`、`crypto_scalarmult_curve25519@0x6064fc`、`crypto_scalarmult_curve25519_base@0x60655c`，另有 OpenSSL `ChaCha20_ctr32@0x5033d0`、`EVP_chacha20_poly1305@0x4d5a04`。

### 2.3 结论与算法伪代码

见 `scan/net/lws_crypto.md` §2（含 `inc_be` 递增规则、首包计数偏移、离线解密最小信息集）。一句话：**`key = X25519(client_priv, server_pub)` 原始 32 字节；`nonce = 8B base + 包序号（大端）`；`ChaCha20-Poly1305` 密文后追加 16B tag；握手/心跳明文**。

### 2.4 但先要判别「哪条实现是活的」

本包存在**两套 LWP/LWS 实现**，密码学相同但位置不同：

| 实现 | 入口 | 判别方法 |
|---|---|---|
| Java LWS（`ClientCodec` + `LwsConnection`，classes21） | `com.laiwang.protocol.android.lws.*` | hook `d43.<init>` 是否命中 |
| Native LWP（`GaeaLwpNative`，libgaealwp_jni ↔ libgaea） | `Java_com_imclient_gaea_jni_GaeaLwpNative_00024CppProxy_startNative/sendNative` | hook 上述 JNI 是否命中；命中则 key 在 native，改用 `libgaea.so!crypto_scalarmult_curve25519` 取值 |

`defpackage/w2b`（Gaea 门面）持有一个 `GaeaLwpNative` 实例，`defpackage/x2b` 初始化 Gaea 时 `this.f67302a = w2b.f()` ⇒ **native 路径是默认，Java 路径是兼容/降级** **[推断，高置信]**。playbook 第 2 步就是先跑这个判别。

---

## 3. ② Gaea 出网入口与 TLS

### 3.1 JNI 入口（ELF 导出符号直证）**[观察]**

`libgaeahttp_jni.so`（HTTP/2 与一般请求）：

```
0xf250 Java_com_imclient_gaea_http_jni_GaeaHttpNative_00024CppProxy_executeNative      (700B) ← 主入口
0xeb54 ..._initNative            0xec44 ..._setConfigServiceNative
0xf048 ..._needSpeedNative       0xf50c ..._getGaeaHttpNative
0xeddc ..._setMaxRequestsNative  0xee3c/_ee9c/_eefc/_ef5c  ...Limit*
```

`libgaealwp_jni.so`（长连接 LWP）：

```
0x50550 ..._GaeaLwpNative_00024CppProxy_startNative        0x505ac ..._sendNative   (344B)
0x50704 ..._sendExtNative     0x508f8 ..._cancelNative     0x509d4 ..._sendResponseNative
0x4f640 ..._initNative        0x4f70c ..._setLwpCallbackNative
0x50184 ..._registerNative    0x50274 ..._unregisterNative 0x50364 ..._addNoAckPushTopicNative
0x50bcc ..._downloadFileNative  ..._authNative / _devAuthNative / _getSessionIdNative / _detectRttNative
```

`libgaea.so` 自身只导出 14 个 JNI（`NetworkInterfaceMonitorManager`、`SystemInfoManager`、`Java_com_imclient_mars_*`、`Bifrost_JNI_OnLoad`）+ **大量 OpenSSL/QUIC/C++ 符号**。

### 3.2 TLS 到底是谁在做 **[观察]**

| 事实 | 证据 |
|---|---|
| **不走 `libssl-dd.so`** | `DT_NEEDED` 扫描：只有 `libencrypt_algorithm.so` 依赖 `libssl-dd.so`+`libcrypto-dd.so`；`libbarcodessl.so`、`libsafeguard.so` 只依赖 `libcrypto-dd.so`；Gaea 三件套（gaea/gaeahttp_jni/gaealwp_jni）**只依赖 `liblsquic.so` + `libdmojo_support.so`** |
| Gaea 的 TLS 是静态内嵌 **OpenSSL 1.1.1h-dev** | `libgaea.so` 内含 `"OpenSSL 1.1.1h-dev  xx XXX xxxx"`，并**导出** `SSL_read@0x63b7c0`、`SSL_write@0x63be54`、`SSL_CTX_new@0x63d604`、`SSL_set_verify@0x63b27c`、`SSL_get_verify_result@0x63ee00`、`SSL_do_handshake@0x63dd4c`、`SSL_get_peer_certificate@0x63b30c`、`X509_verify_cert@0x565d9c` |
| QUIC 用 **BoringSSL**（静态，符号被裁） | `liblsquic.so` 内含 `"BoringSSL"`/`"BoringCrypto"`；`SSL*` 只导出 5 个（`lsquic_ssl_to_conn` 等），**没有 `SSL_read/SSL_write`** |
| 有「关校验」开关 | `libgaea.so` 导出 `_ZN4gaea3lwp7Setting23set_ssl_verify_disabledEb`@`0x3839e0`（12B）与 `_ZN4gaea3lwp7Setting19set_tls_verify_hostERKNSt6__ndk112…`@`0x3839d8`（8B） |
| `libssl-dd.so` 的真实用途 | 服务于 `com/alibaba/imclient/encryptlib/algorithm/EncryptAlgorithm`（本地文件/字符串加密），**与网络无关** |

### 3.3 「mitmproxy + frida hook SSL_read/SSL_write 能否看到明文」——明确结论

| 通道 | 能否 | 说明 |
|---|---|---|
| **Gaea 的 TCP+TLS（HTTP/2 业务请求）** | **能（hook 层面）** | `SSL_read`/`SSL_write` 在 `libgaea.so` 是**动态导出符号**，`Module.findExportByName("libgaea.so","SSL_write")` 直接可用；`SSL_write(ssl, buf, num)` 的 `buf/num` 就是明文 HTTP/2 字节流 |
| **LWS 长连接（走 Gaea TCP）** | **只能到"帧"，看不到业务明文** | hook 到的是 LWS 二进制帧；`DATA` body 仍是 ChaCha20-Poly1305 密文 → 还需 key（hook `d43` 或 native `crypto_scalarmult_curve25519`） |
| **QUIC（`quic.<host>`，UDP/443）** | **不能（按名字）** | TLS 在 `liblsquic.so` 内静态 BoringSSL 且 `SSL_read/SSL_write` 未导出 → 只能按模式扫描定位或走应用层 hook |
| **mitmproxy/Charles 主动代理** | **基本不能** | Gaea 走自有 DNS/连接与证书校验（`SSL_get_verify_result` + 可能的 `set_tls_verify_host`），且长连接/QUIC 不走系统代理；要 MITM 必须同时 (a) 关校验 (b) 装 CA (c) 让流量走代理 —— 长连接基本无解 |
| **XCDN / 多媒体** | 部分能 | `libXcdnEngine.so` 也导出 `SSL_read/SSL_write`（@0x162750/0x162c4c） |

**一句话**：`SSL_read/SSL_write` hook 对**普通业务请求（MTOP over Gaea HTTP）有效**，对**长连接只到帧层**，对 **QUIC 无效**。

### 3.4 推荐的 native hook 组合（3 个）

```js
// 1) TLS 明文（Gaea TCP 路径）—— 最稳
const w = Module.findExportByName('libgaea.so', 'SSL_write');   // 0x63be54
const r = Module.findExportByName('libgaea.so', 'SSL_read');    // 0x63b7c0
// int SSL_write(SSL*, const void* buf, int num) / int SSL_read(SSL*, void* buf, int num)

// 2) LWS 应用层 key / 明文（native LWP 路径）
Module.findExportByName('libgaea.so', 'crypto_scalarmult_curve25519');      // 0x6064fc
Module.findExportByName('libgaea.so', 'crypto_aead_chacha20poly1305_decrypt'); // 0x602ea4

// 3) 关掉 TLS 校验（谨慎；仅供自有测试机）
Module.findExportByName('libgaea.so', '_ZN4gaea3lwp7Setting23set_ssl_verify_disabledEb'); // 0x3839e0
```
Java 侧 12 个 hook 点与完整脚本见 `tools/capture.md`。

---

## 4. ③ appSecret 位置

### 4.1 证据 **[观察]**

1. **Java 侧无 secret 字段**：`MtopConfig` 只有 `sign`（`ISign` 实例）与 `appkey` 相关字段；`mtopsdk` 全目录 grep `appSecretKey|secretKey|getAppSecret` = 0 命中。
2. **兜底实现是死代码**：`mtopsdk.security.b`（`LocalInnerSignImpl`，用 `stb.b(base, secret)` 做 HMAC-SHA1）在本包**没有任何构造点**（`InnerProtocolParamBuilderImpl` 只 import 了类型），生产路径是 `MtopConfig.sign = mtopsdk.security.a`（`InnerSignImpl`）→ SecurityGuard `signRequest(requestType=7)`。
3. **native 里也没有明文**：`grep -a "21811227"` 对 152 个 .so = 0 命中；`libsgmainso-6.6.230702.so`（1.5 MB）中 `appkey/appKey/secret/static_data` 关键词 **全 0 命中**（该 so 还故意破坏 section header，pyelftools 无法解析段表，属已知反分析手段）。
4. **appkey 的来源**：Java 常量 `BuildConfig.MTOP_APPKEY` 与 `defpackage.l1r.f52735a="21811227"`；运行时也可 `SecurityGuardManager.getStaticDataStoreComp().getAppKeyByIndex(i)`。
5. **SG 接口只回 appkey**：`l1r.a(ctx,i)` 用 `getAppKeyByIndex`；**没有任何 API 把 secret 返回给 Java**；`SecurityGuardParamContext.paramMap` 只塞 `INPUT`（待签串）。

### 4.2 结论

- **secret 在 native 的 SecurityGuard 静态数据存储里**（随包、加密、按 appkey index 寻址，可能和设备/签名绑定），**不是服务端下发**，也**不在 Java 层**。
- 因此「算出 MTOP 签名」只有三条路：① 调 SG 的 `signRequest`（等于借壳）；② hook `mtopsdk.security.a` 拿 `INPUT` 但 sign 仍需 SG；③ 从 `libsgmainso` 逆向其静态数据解密（成本极高，且 03 任务的段表破坏会挡）。
- 服务端侧只做**校验**，不参与 secret 存储。

### 4.3 动态确认（V6）

hook `mtopsdk.security.b#getCommonHmacSha1Sign`：若运行期**永不命中** ⇒ 兜底路径确实死；再 hook `mtopsdk.security.a#getMtopApiSign` 看是否返回非空 ⇒ 确认全部走 SG。

---

## 5. 可见性矩阵（hook 位置 × 能看到什么）

| hook | 可见内容 | 局限 |
|---|---|---|
| `libgaea.so!SSL_write` / `SSL_read` | HTTP/2 帧（明文 HTTP 头/体）、LWS 帧（密文 body） | 二进制流，需自己解帧；QUIC 不走这里 |
| `d43.<init>` / `d43.a/e`（Java） | LWS key、双向 nonce 基值 | 仅 Java LWS 路径；native LWP 时不命中 |
| `libgaea.so!crypto_scalarmult_curve25519` | 共享密钥（= key）入参/出参 | 需自己判定哪次调用属于 LWS |
| `libgaea.so!crypto_aead_chacha20poly1305_decrypt` | 明文（直接给） | 高频调用，需过滤 |
| `ClientCodec.c(ByteBuffer, CodecListener)` | **解密后的 LWS 帧** | Java 路径专用，最省事 |
| `GaeaLwpNative_..._sendNative` | 上行消息（native 结构体/序列化后） | 需再解 wukong IDL |
| `mtopsdk.security.a#e/map` | sign 原文（22 字段） | 拿不到 secret 本身 |
| `GaeaHttpNative_..._executeNative` | URL、头、耗时、状态码 | C++ 对象，需 JNI 反射读字段 |
| `XcdnEngine!SSL_*` | CDN/媒体明文 | 只覆盖 XCDN 流量 |

---

## 6. 与上一轮的修正

| 05 报告说法 | 本轮修正 |
|---|---|
| "LWS AEAD 密钥来自握手，native 未知" | **已定位**：X25519 + ChaCha20-Poly1305(8B nonce) + 无 KDF；地址与伪代码见 `scan/net/lws_crypto.md` |
| "Java 层抓不到 Gaea 明文" | **修正为**：`SSL_read/SSL_write` 在 `libgaea.so` 是**导出符号**，可 hook 拿到 TLS 明文（业务请求可读，长连接只到帧） |
| "pinning 待动态验证" | 发现 `gaea::lwp::Setting::set_ssl_verify_disabled(bool)` 与 `set_tls_verify_host(std::string)` 两个**可关校验**的导出符号 —— pinning 是否生效取决于这两个开关的调用方（**[未知]**，playbook 用 hook 观测） |
| "libssl-dd 可能是 TLS 栈" | **否**：仅被 `libencrypt_algorithm.so`（本地加密库）依赖；Gaea 用内嵌 OpenSSL 1.1.1h |

---

## 7. 未解

1. `HelloResponse.SIGN` 的 Ed25519 公钥来源与签名载荷（`sid||nonce`？）——需 hook `crypto_sign_ed25519_open` 的 `pk`。
2. `set_ssl_verify_disabled` / `set_tls_verify_host` 的调用方与触发条件（DevSetting？Gaea 配置项？）——`libgaea.so` 内 xref 需完整反汇编（未做）。
3. native LWP 的 LWS 等价帧格式是否与 Java 版逐字节一致（若一致，`lws_crypto.md` 的帧解析可直接复用）。
4. `libsgmainso` 静态数据表的解密（segment 表被破坏，需自建 ELF 解析器）。
5. QUIC 的 TLS 密钥导出（BoringSSL 符号被裁，只能靠 pattern scan/版本比对）。
