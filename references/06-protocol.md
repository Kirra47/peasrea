# 06 · 协议层：签名、长连接与“能不能抓到”

## 先分层，再谈抓包

典型分层（以阿里系为例）：

```
业务 API（MTOP，HTTP 语义，sign 由安全 SDK 生成）
   └─ 长连接（自研二进制帧，LWP/LWS）
        └─ 传输层（Gaea：HTTP/2 + QUIC，native 出网）
             └─ 寻址/降级（Aladdin/AMDC、Bifrost/XCDN）
```

判断“抓不抓得到”的关键：**TLS 在哪一层**。
- TLS 在平台栈（OkHttp/HttpURLConnection/WebView）→ 用户 CA + 代理即可；
- TLS 静态内嵌在 native（`libgaea` 自带 OpenSSL、`liblsquic` 内嵌 BoringSSL）→
  `network_security_config` 完全无效，只能 native hook `SSL_read/SSL_write` 或透明代理。

检查方法：`llvm-readelf -d libgaea.so | grep NEEDED` —— 若没有 `libssl.so`，
说明 TLS 是静态链入的。

## MTOP 签名（可按此复算）

签名原文（base string）字段顺序：
`utdid&uid&reqbiz-ext&appKey&urlencode(data)&t&api&v&sid&ttid&deviceId&lat&lng&[extdata]&x-features&routerId&placeId&open-biz&mini-appkey&req-appkey&accessToken&open-biz-data`

- `appKey` 是常量（BuildConfig）；
- 生产签名走安全 SDK（`signRequest(requestType=7)` / AVMP `mwua`），Java 层通常只剩
  HMAC-SHA1 兜底（且 `appSecret` 往往不在 Java 层）；
- 设备身份四件套：`utdid`（UT SDK）、`umid`（安全 SDK native）、`deviceId`（首次申请后落 SP）、`appkey`。

## 自研长连接帧（示例结构）

4 字节头：`[(type<<12)|bodyLen][(version<<14)|(attrCount<<8)|(cipher<<7)]`
+ TLV（1B id + 2B len）+ AEAD body；分片 4040B；type：
`HELLO_REQ=1 / HELLO_RESP=0 / DATA=3 / PING=4 / PONG=5`。
握手属性：`REUSE_SID / CIPHER_SUITE / SNI / APP_PUB_KEY / APP_NONCE / SERVER_NONCE / VIA / VERSION / UA`。

加密：X25519 ECDH + ChaCha20-Poly1305（libsodium 非 IETF：8B nonce / 16B tag / 无 AAD），
**无 KDF**（`key = X25519(priv, serverPub)` 原始 32 字节）。判断依据：加密库导出符号里
只有 `scalarmult` / `chacha20poly1305_encrypt|decrypt` / `ed25519_open`，没有 `*_ietf_*`、`hkdf`、`sha256`。

## 抓包的可行性矩阵

| 通道 | 手段 | 可行性 |
|---|---|---|
| WebView / 第三方 SDK / OkHttp 默认 | 系统代理 + 用户 CA（NSC 放行时） | 高 |
| 平台栈但做了 pinning | hook `X509TrustManagerFactory` / 证书校验回调 | 中 |
| native TLS（自研栈） | hook `SSL_read/SSL_write`（需符号导出） | 中（需 root/gadget） |
| QUIC | 导出密钥或 hook BoringSSL（常未导出） | 低 |
| 长连接应用层 AEAD | hook 解密函数 + 取会话密钥 | 低（需定位 key 派生） |

## 复现建议顺序

1. 静态确认每层的 TLS 归属（读 `DT_NEEDED`、找 `SSL_*` 符号是否导出）；
2. 平台栈流量用代理先跑通，确认请求形状；
3. native 流量用 Frida hook `SSL_write/SSL_read` 打印明文（`scripts/` 里的模板改一下即可）；
4. 长连接要拿到 `HELLO` 后的会话密钥，再解 `DATA` 帧；
5. 全程记录“哪一层解不开”，这比“抓到了”更有价值。
