# 抓包 Playbook — IM 8.2.2.1 专属版（LWS / MTOP / Gaea）

> 目标进程：`<PKG>`（专属版 IM）
> 配套：`analysis/09-capture-lws.md`（结论）· `scan/net/lws_crypto.md`（算法/帧格式）· `scan/net/protocol-notes.md`（协议常量）
> 本 playbook 的所有符号名/地址都已在本包 ELF 中**实测存在**（见 09 报告 §2、§3）。

---

## 0. 环境与前提

| 项 | 要求 | 备注 |
|---|---|---|
| 主机 | Windows（本仓库已有 `frida 17.16.3`、python 3.12） | `frida --version` 自检 |
| 设备 | **建议 root 机**（`frida-server` 直接跑）；手头 Samsung S10 为 **非 root / user 版** | 非 root 只能走 **重打包注入 frida-gadget**（改签名，可能触发 SG 校验，风险见 §7） |
| frida-server | 与 host frida 主版本一致，`arm64` | `adb push frida-server /data/local/tmp/ && adb shell su -c '/data/local/tmp/frida-server &'` |
| 代理 | mitmproxy 10.x（仅覆盖非 Gaea 流量） | `mitmproxy --mode regular@8080` |
| 抓包 | PCAPdroid（UDP/443 看 QUIC 有没有） | 无解密能力，只做"有没有 QUIC"的判定 |
| 设备证书 | mitmproxy CA 装到 **系统** 证书区（`/system/etc/security/cacerts`）或 user 区 | 本包 NSC 无 `domain-config`（03 报告），user CA 也可被系统信任，但 Gaea 自校验不看它 |

**判定成功的最短路径**：`Step 2`（判别实现路径）→ `Step 4`（SSL_write hook）→ `Step 5`（LWS key hook）。三步中任一步拿到可读明文/密钥即算成功。

---

## 1. Step 0 — 静态准备（主机侧，1 分钟）

```bash
cd /d/Deepseek-Harness-workspace/re/base_apk3
python scan/net/_tools/elftool.py jni  unpacked/native/lib/arm64-v8a/libgaea.so            # 应见 Bifrost_JNI_OnLoad
python scan/net/_tools/elftool.py syms unpacked/native/lib/arm64-v8a/libgaea.so SSL_read    # 应见 000000000063b7c0
python scan/net/_tools/elftool.py syms unpacked/native/lib/arm64-v8a/libgaea.so chacha      # 应见 0x602af4 / 0x602ea4
```
**预期**：三条命令都能打出符号。打不出 ⇒ `unpacked/` 被换过，停止并复核目标包。

---

## 2. Step 1 — 连通性与反调试基线（5 分钟）

```bash
frida-ps -U | grep -i <pkg>          # 能看到进程/包名
frida -U -f <PKG> --pause -l probe.js
```

`probe.js`（最小探针，先确认能不能挂上）：

```js
setTimeout(() => {
  console.log('[probe] pid=' + Process.id + ' arch=' + Process.arch);
  ['libgaea.so','libkaliumjni.so','libgaealwp_jni.so','libgaeahttp_jni.so','libsgmainso-6.6.230702.so']
    .forEach(m => console.log('[probe] ' + m + ' base=' + Module.findBaseAddress(m)));
}, 3000);
```

| 结果 | 含义 | 下一步 |
|---|---|---|
| 打印出 base 地址 | 挂载成功 | Step 2 |
| 进程秒退 / 无输出 | 反调试或 frida 检测（toyger/SG） | 换 `--pause` + 延迟 resume；或 attach 而非 spawn；仍失败 → 见 §7 |
| `libgaea.so base=null` | 还没加载到该 so（懒加载） | 等首屏后再查，或 hook `android_dlopen_ext` 监听加载 |

---

## 3. Step 2 — 判别「Java LWS」还是「native LWP」（关键分叉）

```js
// path.js —— 两个探针同时装，看谁先响
Java.perform(() => {
  try {
    const d43 = Java.use('defpackage.d43');
    d43.$init.overload('[B').implementation = function (k) {
      console.log('[PATH] Java-LWS active (d43 ctor), keylen=' + k.length);
      return this.$init(k);
    };
  } catch (e) { console.log('[PATH] no d43: ' + e); }
});
['Java_com_imclient_gaea_jni_GaeaLwpNative_00024CppProxy_startNative',
 'Java_com_imclient_gaea_jni_GaeaLwpNative_00024CppProxy_sendNative'].forEach(sym => {
  const p = Module.findExportByName('libgaealwp_jni.so', sym);
  if (p) Interceptor.attach(p, { onEnter(a) { console.log('[PATH] native-LWP active: ' + sym); } });
});
```

| 观测 | 结论 | 后续走 |
|---|---|---|
| 只有 `d43 ctor` 打印 | Java LWS 路径 | Step 5A |
| 只有 `startNative/sendNative` | native LWP 路径（默认更可能） | Step 5B |
| 两者都有 | 混合（Java 短连接 + native 长连接） | 5A 与 5B 都装 |

**失败判据**：10 分钟内两者都不响 ⇒ 长连接还没建立（未登录/网络异常），先登录到首页再观察。

---

## 4. Step 3 — Java 层 12 个 hook（MTOP / 长连接 / 端点）

一次性脚本 `java12.js`：

```js
function hex(a){ return a ? Array.from(new Uint8Array(a)).map(b=>('0'+((b+256)%256).toString(16)).slice(-2)).join('') : 'null'; }
Java.perform(() => {
  const H = [
    ['com.laiwang.protocol.android.lws.ClientCodec', 'c'],                    // 1 解密后 LWS 帧
    ['com.laiwang.protocol.android.lws.LwsConnection', 'r'],                  // 2 握手（sni/pub-key/UA）
    ['com.laiwang.protocol.android.lws.ServerPubKeyManager', 'c'],            // 3 服务端公钥查询
    ['com.laiwang.protocol.gaea.GaeaAladdinManager$b', 'get'],                // 4 native 出网 URL
    ['mtopsdk.security.a', 'e'],                                             // 5 sign base string
    ['mtopsdk.security.a', 'getUnifiedSign'],                                 // 6 x-sign 结果
    ['mtopsdk.security.a', 'getMtopApiSign'],                                 // 7 x-sign 结果(备)
    ['anet.channel.SessionCenter', 'switchEnvironment'],                      // 8 环境切换
    ['com.alibaba.android.user.service.ExtensionImpl', 'defaultServerURI'],     // 9 长连接端点（可被 mLWPDebugConfig.e 覆盖）
  ];
  H.forEach(([cls, m]) => {
    try {
      const C = Java.use(cls);
      C[m].overloads.forEach(ov => {
        ov.implementation = function () {
          const r = ov.apply(this, arguments);
          let out = '';
          try { out = JSON.stringify(Array.from(arguments).map(a => (a && a.length !== undefined) ? ('bytes:' + hex(a)) : String(a))); } catch (e) {}
          console.log('[' + cls.split('.').pop() + '.' + m + '] ' + out.slice(0, 400) + ' => ' + String(r).slice(0, 200));
          return r;
        };
      });
    } catch (e) { console.log('[skip] ' + cls + '.' + m + ' ' + e); }
  });
  // 10/11 Gaea 长连接 native 桥（Java 侧真实可 hook 的方法）
  hookOne('com.imclient.gaea.jni.GaeaLwpNative$CppProxy', 'send');
  hookOne('com.imclient.gaea.jni.GaeaLwpNative$CppProxy', 'sendExt');
  hookOne('com.imclient.gaea.jni.GaeaLwpNative$CppProxy', 'sendResponse');
  hookOne('com.imclient.gaea.jni.GaeaLwpNative$CppProxy', 'getConnectionEndpoint');
  // 12 Gaea HTTP 出网入口（native 方法，但以 Java 方法形态可见）+ CookieAPI 存在性
  hookOne('com.imclient.gaea.jni.GaeaHttpNative$CppProxy', 'executeNative');
  try { Java.use('defpackage.vo5'); console.log('[ok] CookieAPI(vo5) present'); } catch (e) {}

  function hookOne(cls, m) {
    try {
      const C = Java.use(cls);
      C[m].overloads.forEach(ov => {
        ov.implementation = function () {
          const r = ov.apply(this, arguments);
          let out = '';
          try { out = JSON.stringify(Array.from(arguments).map(a => (a && a.length !== undefined) ? ('bytes:' + hex(a)) : String(a))); } catch (e) {}
          console.log('[' + cls.split('.').pop() + '.' + m + '] ' + out.slice(0, 400) + ' => ' + String(r).slice(0, 200));
          return r;
        };
      });
    } catch (e) { console.log('[skip] ' + cls + '.' + m + ' ' + e); }
  }
});
```

> **12 个 Java hook 的准确清单**：①`ClientCodec.c` ②`LwsConnection.r` ③`ServerPubKeyManager.c` ④`GaeaAladdinManager$b.get` ⑤`mtopsdk.security.a.e` ⑥`.getUnifiedSign` ⑦`.getMtopApiSign` ⑧`anet.channel.SessionCenter.switchEnvironment` ⑨`ExtensionImpl.defaultServerURI` ⑩`GaeaLwpNative$CppProxy.send` ⑪`…sendExt` ⑫`GaeaHttpNative$CppProxy.executeNative`（+ `sendResponse`/`getConnectionEndpoint`/`vo5` 为附加观测）。
> 若 overload 解析报错，脚本打印 `[skip]` 后继续 —— **不允许因单个类失败中断**。

**预期**：
- `LwsConnection.r` 打印 `lws://…?sni=…` 与 UA；
- `ServerPubKeyManager.c` 打印 `default`/`test`/`cdn1..5`；
- `security.a.e` 打印 22 字段的 base string（含 `utdid/uid/api/v/sid/ttid/deviceId`…）;
- `getUnifiedSign` 返回 `x-sign`（长度通常 32–64）与可能的 `x-mini-wua`。

**失败判据**：`security.a.e` 一直不响 ⇒ 该版本把签名搬到 `mtopsdk.security.a` 的子类/Surgeon 实现，改用 `Java.enumerateMethods('*security*!*Sign*')` 找实现。

---

## 5. Step 4 — native 3 个 hook（TLS 明文 / 密钥 / 关校验）

`native3.js`：

```js
function dump(tag, ptr, n) {
  try { console.log('[' + tag + '] ' + n + 'B ' + hexdump(ptr, { length: Math.min(n, 256), ansi: false })); } catch (e) {}
}
function hex(a){ return a ? Array.from(new Uint8Array(a)).map(b=>('0'+((b+256)%256).toString(16)).slice(-2)).join('') : 'null'; }

// ---- 1) TLS 明文：libgaea.so 的 OpenSSL 1.1.1h（导出符号）
const w = Module.findExportByName('libgaea.so', 'SSL_write');
if (w) Interceptor.attach(w, {
  onEnter(a) { const n = a[2].toInt32(); this.n = n; console.log('\n[SSL_write] len=' + n); dump('SSL_write', a[1], n); }
});
const r = Module.findExportByName('libgaea.so', 'SSL_read');
if (r) Interceptor.attach(r, {
  onLeave(ret) { const n = ret.toInt32(); if (n > 0) { console.log('\n[SSL_read] len=' + n); dump('SSL_read', this.buf, n); } },
  onEnter(a) { this.buf = a[1]; }
});

// ---- 2) LWS 应用层密钥（native 路径）
const sm = Module.findExportByName('libgaea.so', 'crypto_scalarmult_curve25519'); // 0x6064fc
if (sm) Interceptor.attach(sm, {
  onLeave(ret) {
    // int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n, const unsigned char *p)
    console.log('[scalarmult] ret=' + ret.toInt32());
  }
});
const dec = Module.findExportByName('libgaea.so', 'crypto_aead_chacha20poly1305_decrypt'); // 0x602ea4
if (dec) Interceptor.attach(dec, { onEnter(a) { console.log('[aead_dec] m=' + a[4].toInt32() + ' clen=' + a[5].toInt32()); } });

// ---- 3) 关校验（仅自有测试机；用于让 mitmproxy 的证书被接受）
const off = Module.findExportByName('libgaea.so', '_ZN4gaea3lwp7Setting23set_ssl_verify_disabledEb');
if (off) {
  const f = new NativeFunction(off, 'void', ['bool']);
  setTimeout(() => { try { f(true); console.log('[pin] ssl_verify_disabled(true) called'); } catch (e) {} }, 2000);
}
```

| hook | 预期输出 | 失败判据 |
|---|---|---|
| `SSL_write/SSL_read` | 每条记录一段 hexdump，`SSL_write` 里能看到 `PRI * HTTP/2.0` 的 h2 preface 或 `POST /gw/... HTTP/1.1`；长连接里能看到 `\x01\x00…`（LWS HELLO/ DATA 帧头） | 一直无输出 ⇒ 流量全走 QUIC（`quic.<host>`）或 native LWP 自建 socket（换 5B） |
| `crypto_scalarmult_curve25519` | 若干次调用（每次会话一次） | 不响 ⇒ 走的是 Java LWS（用 5A） |
| `crypto_aead_chacha20poly1305_decrypt` | 每帧一次，`clen` 稳定递增 | 不响 ⇒ 同上 |

> 拿到 `SSL_write` 的 hexdump 后，按 `scan/net/protocol-notes.md` §1.1 解 4 字节头：`type=(b0>>4)`、`bodyLen=((b0&0xF)<<8)|b1`，即可切帧。

---

## 6. Step 5A / 5B — 取 LWS 明文

### 5A（Java LWS 路径）
```js
Java.perform(() => {
  const d43 = Java.use('defpackage.d43');
  d43.$init.overload('[B').implementation = function (k) { console.log('[KEY] ' + bytesToHex(k)); return this.$init(k); };
  const cc = Java.use('com.laiwang.protocol.android.lws.ClientCodec');
  cc.c.overload('java.nio.ByteBuffer', 'com.laiwang.protocol.android.lws.ClientCodec$CodecListener').implementation = function (b, l) {
    const arr = Java.array('byte', []); // 读 b 剩余
    const n = b.remaining(); const out = []; for (let i = 0; i < n; i++) out.push(b.get(b.position() + i));
    console.log('[LWS-PT] ' + bytesToHex(out.slice(0, 200)));
    return this.c(b, l);
  };
  function bytesToHex(a){ return Array.from(a).map(x=>('0'+((x+256)%256).toString(16)).slice(-2)).join(''); }
});
```
**预期**：`[KEY]` 打印 32 字节；`[LWS-PT]` 打印业务明文（wukong IDL 帧）。

### 5B（native LWP 路径）
用 Step 4 的 `crypto_aead_chacha20poly1305_decrypt`：读第 2 个参数（key 指针）与第 5 个参数（密文）——`decrypt(dst, &dstlen, nsec, c, clen, ad, adlen, nonce, key)`（libsodium 顺序）。取 `key`（arg8）与 `nonce`（arg7）各 32/8 字节，即可离线解全部帧（规则见 `scan/net/lws_crypto.md` §2）。

**失败判据**：`key` 读出来是 0 或长度不符 ⇒ 参数序按 ABI 偏移错位，改用 `Memory.readByteArray(a[7], 8)` 起逐个偏移试（0..7）。

---

## 7. Step 6 — 代理 / QUIC / 备用手段

1. **mitmproxy（覆盖非 Gaea 流量）**
   ```bash
   mitmproxy --mode regular@8080 --set confdir=./mitm
   adb shell settings put global http_proxy 10.0.2.2:8080
   ```
   装 CA 后访问 WebView 内 H5、图片等应可见；**MTOP/IM 基本不出现**（Gaea + pinning），属预期。
2. **QUIC 判定**：PCAPdroid 抓 `udp/443`，看是否有到 `quic.<host>` 的包。有 ⇒ 说明部分流量绕过 TCP，`SSL_*` hook 覆盖不到。
3. **关校验 + 代理**：仅当 `set_ssl_verify_disabled(true)` 生效（Step 4 日志出现）后再试代理，否则 Gaea 会直接断连。
4. **frida 被检测时**：① attach 而非 spawn；② 先 `--pause`，在 `libsgmainso` JNI_OnLoad 之后再 resume；③ 重命名 frida-server 线程/端口（`-l 0.0.0.0:8899`）；④ 换非 root 重打包 + gadget 方案（会改签名 → SG 可能拒，需同时 patch 校验点，属 03 任务范围）。

---

## 8. 输出归档

| 产物 | 命令 |
|---|---|
| Java 日志 | `frida -U -f <pkg> -l java12.js -o logs/java12.log` |
| native 日志 | `frida -U -f <pkg> -l native3.js -o logs/native3.log` |
| 原始 LWS 帧 | `SSL_write` dump 重定向到 `logs/frames.hex`，用 `xxd -r -p` 还原后按 §1.1 切帧 |
| 代理流量 | mitmproxy `--save-stream-file logs/flows.mitm` |

---

## 9. 失败判据总表（什么时候该停）

| 现象 | 判据 | 处置 |
|---|---|---|
| 进程启动即退出（<3s） | 反调试/完整性校验 | 改 attach；或先 hook `libc!ptrace`、`Debug.isDebuggerConnected` |
| 所有 hook 安装成功但**零回调** | 走的是未覆盖的实现（native LWP over QUIC） | 换 5B；再不行看 `liblsquic.so`（需 pattern scan） |
| `SSL_write` 有数据但**看不到 h2 preface** | 该连接不是 Gaea 的（可能是别的 so 的 TLS） | 同时 hook `libXcdnEngine.so`/`libssl-dd.so` 的 `SSL_write` |
| `security.a.e` 打出 base string，但 sign 请求 4xx | 改包破坏了签名 | 只读不改；改包必须同时 hook sign |
| 长连接每 ~60s 断一次 | 心跳/NAT 超时（后台被杀） | 前台保持 + 关电池优化；观察 `HEART_BEAT` 告警 |

---

## 10. 合规边界

本 playbook 仅用于**自有测试机 + 自有租户**的协议分析与联调；`set_ssl_verify_disabled` 会关闭传输层校验，禁止在真实办公环境对他人流量使用。抓到的 `x-sid`/cookie/wukong 消息属个人数据，按最小留存处理。
