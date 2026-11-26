# 01 · 容器、签名与清单（先定位“这是什么”）

## 目标
在动任何反编译之前，用 10 分钟回答：包名/版本/SDK/ABI、签名方案与证书、dex 规模、
native 规模、zip 结构是否异常、清单关键属性。

## 命令

```bash
APK=target.apk
aapt2 dump badging   "$APK" | head -40
aapt2 dump permissions "$APK"
apksigner verify --print-certs --verbose "$APK"
aapt dump xmltree "$APK" AndroidManifest.xml > manifest_tree.txt
```

zip 结构异常扫描（比 unzip -l 更有用）：

```python
import zipfile, collections
z = zipfile.ZipFile('target.apk'); infos = z.infolist()
print('entries', len(infos),
      'compressed %.1f MB' % (sum(i.compress_size for i in infos)/1e6),
      'uncompressed %.1f MB' % (sum(i.file_size for i in infos)/1e6))
print('dates', collections.Counter(i.date_time[:3] for i in infos).most_common(3))
print('ext', collections.Counter(
    ('.'+i.filename.rsplit('.',1)[1].lower()) if '.' in i.filename.split('/')[-1] else '<none>'
    for i in infos).most_common(12))
low = collections.Counter(i.filename.lower() for i in infos)
print('case-collisions', [k for k,v in low.items() if v>1][:5])
print('suspicious', [i.filename for i in infos
      if '..' in i.filename or i.filename.startswith('/') or '__MACOSX' in i.filename][:10])
```

嵌套归档探测（找出 assets 里的 zip/dex/gzip/elf）：

```python
for i in infos:
    if 4 <= i.file_size <= 60*1024*1024:
        head = z.open(i).read(8)
        if head[:2]==b'PK' or head[:4]==b'dex\n' or head[:3]==b'\x1f\x8b\x08' or head[:4]==b'\x7fELF':
            print(i.filename, i.file_size, head[:4])
```

## 判读要点

| 观察 | 含义 |
|---|---|
| v2/v3 通过 + 证书主体是厂商 | 官方构建；**改包必须重签**，重签会改变客户端指纹 |
| 全部条目同一时间戳 | 单次构建会话；跨时间戳要怀疑二次打包 |
| 包名带后缀（`.w123456`）且 authority/自定义权限同名 | 构建期 applicationId 改名（企业定制/OEM 分渠道），不是改包 |
| `usesCleartextTraffic=true` + NSC `trust-anchors user` | 平台栈流量可被 MITM（不代表自研协议可解） |
| dex 数量 × 单个 > 8 MB | 需要 `-Xmx` 大堆 + 多线程 + 覆盖率核算 |
| `lib/` 只有 arm64 | 模拟器验证要用 arm 镜像或真机 |

## 清单解析（不依赖 apktool）

`aapt dump xmltree` 是纯文本，可直接解析出组件表、exported、权限、process：

```python
import re
node=re.compile(r'^(\s*)E: (\S+)'); attr=re.compile(r'^(\s*)A: (android:\S+?)\(0x[0-9a-f]+\)=(.*)$')
# 用缩进建树；布尔属性形如 (type 0x12)0xffffffff，资源引用形如 @0x7f150014
```

产出：`components.tsv`（type/name/exported/permission/intent_filters）、`exports.tsv`、
`processes.tsv`、`permissions.txt`。后续攻击面分析全部基于它。

## 易踩的坑

- `aapt2 dump badging` 的 `native-code` 只列出存在的 ABI，不代表支持所有设备；
- 权限数量看着吓人，先按「危险/特殊/厂商/签名级」分类再评估；
- `android:exported` 缺省在 targetSdk≥31 时对带 filter 的组件是**必须显式声明**的，
  但老包常见“没写却能被外部拉起”的历史行为，按实际 dump 为准。
