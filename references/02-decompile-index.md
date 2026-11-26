# 02 · 全量反编译、覆盖率核算与 dex 索引

## 全量反编译

```bash
java -Xmx20g -XX:+UseG1GC -cp jadx-all.jar jadx.cli.JadxCLI \
     -d java -j 24 --no-res unpacked/dex/classes*.dex
```

- 大包（>150 MB dex / >10 万类）必须给 16–24 GB 堆与 16–24 线程；
- `--no-res` 跳过资源（资源另用 apktool 解），减少内存与失败点；
- 结束码 3 = 完成但有失败方法（正常），失败数写进报告，不要忽略。

## 覆盖率核算（关键，别跳过）

jadx **默认跳过 `ACC_SYNTHETIC` 类**（编译器产物），Windows 上还会因大小写不敏感
覆盖同名文件（`Lf20;` 与 `LF20;` → 同一个 `f20.java`）。不核算就会高估覆盖率。

```bash
python scripts/coverage_check.py java/sources unpacked/dex
```

做法：自建 dex 解析器枚举全部 `class_def` 的描述符 → 按包路径映射到 `.java`
（默认包 → `defpackage/`；内部类并入外部类，不单独成文件）→ 统计命中率，
并把未命中的类按 access flags 分成 synthetic / 非 synthetic 两堆。

经验值：大型商用包「非 synthetic 顶层类覆盖率」通常 98–99.5%；
剩下缺口用 `dexdump -d` 或换大小写敏感文件系统重跑补足。

## dex 索引（不装 androguard）

只需解析 header 与 `class_def`，几百毫秒跑完 220 MB：

```python
import struct
def uleb(d,o):
    r=s=0
    while True:
        x=d[o]; o+=1; r|=(x&0x7f)<<s
        if not x&0x80: return r,o
        s+=7

d=open('classes.dex','rb').read()
ss,so=struct.unpack_from('<II',d,56)   # string_ids
ts,to=struct.unpack_from('<II',d,64)   # type_ids
cs,co=struct.unpack_from('<II',d,96)   # class_defs
offs=struct.unpack_from('<%dI'%ss,d,so)
def s(i):
    o=offs[i]; n,o=uleb(d,o); return d[o:o+n].decode('utf8','replace')
tidx=struct.unpack_from('<%dI'%ts,d,to)
for i in range(cs):
    ci,acc=struct.unpack_from('<II',d,co+i*32)
    print(s(tidx[ci]), hex(acc))
```

产出四张表（后续分析全靠它们）：

| 表 | 用途 |
|---|---|
| `classes.tsv` | 类 → dex / 包 / access flags；先看包分布再决定钻哪里 |
| `package-stats.tsv` | 包 → 类数/方法数；找出“业务主包”和“第三方 SDK” |
| `processes.tsv` | manifest 的 `android:process` 分组 → 多进程模型与动态分析挂载点 |
| `routes.tsv` | intent-filter 的 scheme/host/path → 深链与入口攻击面 |

## 混淆与插桩的识别

- **R8/ProGuard**：短名类（`a0`/`jln`）扎堆、单字母包；框架命名空间通常保留。
- **字节码插桩**（如阿里的 Surgeon）：每个方法头都有
  `sget-object $flag; invoke-static support(...)` 的三段式样板 —— 这类桩本身可作为
  “运行时替换方法”的入口（见 `references/07-patching-verify.md`）。
- **多 dex 重复类**：统计 `class_def` 去重后的差值，少量重复正常（构建产物）。

## 定位入口的实用顺序

1. manifest 的 `application` / launcher activity；
2. 启动框架（`*startup*`、`*launch*`、`InitTask`）；
3. 事件总线/RPC 的注册点（`subscribe("/push/...")` 这类字符串最好找）；
4. 网络层（MTOP/自研 SDK）→ 顺着 api 名反推业务模块；
5. 最后才按包名逐个啃。
