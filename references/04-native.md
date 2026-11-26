# 04 · Native 层：清点、加固识别、JNI 表与段表还原

## 清点

```bash
for f in unpacked/lib/arm64-v8a/*; do
  file "$f"
done
llvm-readelf -h -d -s --dyn-syms "$f" | head -60
```

产出 `elf_summary.tsv`：类型（DYN/EXEC）、架构、是否 stripped、节/段是否完整、
`DT_NEEDED`（含悬空依赖）、导出符号数、是否导出 `JNI_OnLoad`。

**非 ELF 文件不要跳过**：常见 6 类容器 —— 签名迷你 APK、7z/ZIP、加密配置体（`.ucb`）、
版本桩（`.version`）、纯数据、以及“同名不同物”的壳文件。

## 加固/保护识别

| 特征 | 判断 |
|---|---|
| 节头表被擦除：`sh_addr/sh_offset = 0xffffffffffffffff`、`sh_name = 0` | 静态工具全挂，但 `PT_LOAD`/`PT_DYNAMIC` 通常完好 → 可重建 |
| `JNI_OnLoad` 内控制流平坦化（`mov w8,#imm; b dispatcher`） | 有混淆器，按 vtable 调用点反查更可靠 |
| 字符串区高熵、`.bss` 运行时填充 | 字符串加密；用“长度一致性”反解方法名/签名 |
| 水印字符串（如 `java2jni-1.0.x`、`-Obfuscator-`） | 直接定性工具链 |

## JNI 表重建（当 `RegisterNatives` 表是明文时）

思路：`JNIEnv` 是函数表指针数组，`RegisterNatives` 索引 **215**（偏移 `0x6b8`）。
扫 `ldr Xa,[Xb]; ldr Xc,[Xa,#0x6b8]; blr Xc` 三连 → 唯一调用点 → 回溯
`{className*, JNINativeMethod*, nMethods}` 描述符数组 → 每个 methods 数组是
`{name*, sig*, fnPtr}` 的 24 字节结构（arm64）。

名字/签名若在 `.bss` 运行时解密：`.bss` 里字符串紧凑、NUL 分隔，**长度可静态精确求出**；
用 Java 侧声明的 JNI 签名算 `(name_len, sig_len)`，与 `.bss` 长度做唯一匹配，
通常能 100% 还原长签名（含 79/83/120 字符这种）。

## 段表破坏的还原

```python
# 伪代码：从 PT_LOAD + PT_DYNAMIC 反推 section header
# 1) 读 Elf64_Ehdr 的 e_phoff/e_phnum，定位所有 PT_LOAD（vaddr, offset, filesz, flags）
# 2) 读 PT_DYNAMIC：DT_SYMTAB/DT_STRTAB/DT_HASH/DT_GNU_HASH/DT_JMPREL/DT_RELA
# 3) 用 vaddr→offset 映射，重建 .dynsym/.dynstr/.rela.* 的 sh_addr/sh_offset/sh_size
# 4) 回填符号 st_shndx，写出修复副本（原件不动）
```

验证：`llvm-readelf -S` 零错误、`objdump -d` 正常反汇编、`llvm-nm -D` 能看到导出。
**修复副本只用于静态分析，不要拿去回编译**（会破坏 v2 签名）。

## 容器

- `.ucb.so`（几十~几百字节、长度 16 的整数倍、高熵）→ 加密配置体，外层迷你 APK 里常有同名条目；
- `*.7z` 改名的 `.so` → 标准 7z，首部 `37 7A BC AF 27 1C`，`kEncodedHeader` 说明还有一层编码；
- 签名迷你 APK（`PK\x03\x04` + `META-INF/*.SF`）→ 用 `unzip -l` 看内部结构。

## 坑

- 只按 `.eh_frame` FDE 找函数会漏（java2jni 生成的函数常不在 unwind 表里）；
- `DT_NEEDED` 里的悬空依赖（包内没有该 so）说明运行期由插件/容器注入，静态不可解；
- 同名文件可能一个是 ELF、一个是 ZIP（`libsgmain.so` 这类），按魔数判断而不是扩展名。
