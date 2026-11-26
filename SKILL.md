---
name: peasrea
description: PeasRea — reverse engineer large Android apps end-to-end (APK/AAB/APKS): container and signature verification, full jadx decompilation with coverage accounting, resource/ARSC decoding, dex-level indexing, native ELF analysis (packer/section-table damage/JNI tables), security-stack identification, protocol recovery, and byte-level patching with real-device verification. Use for "逆向一个 APK", "分析这个安卓包", "改包/去限制", "找出接口和签名算法", "native 层分析", "这个 App 怎么实现的". Ships a searchable knowledge base built from a completed 180k-class case (kb/).
metadata:
  version: "1"
  project: "PeasRea"
  case: "anonymous 180,864-class Android client (30 dex / 152 .so)"
---

# PeasRea

面向**大型** Android 客户端（万级类、多 dex、重加固、自研协议）的完整逆向流程。
每一步都产出可复现的中间件（索引、清单、补丁、证据），而不是只给结论。

## 何时用

- 拿到一个 APK/AAB/APKS，要搞清它是什么、能不能改、接口怎么走；
- 需要“全量反编译 + 覆盖率核算”，而不是随手反编译几个类；
- 遇到加固/段表破坏/字符串加密，需要判断是哪家、能不能静态还原；
- 需要落地补丁（改 manifest 属性、改 dex 常量、去门控），并验证真机行为；
- 需要把一次逆向沉淀成可检索的知识库。

不适用：纯源码仓库的架构分析（用普通代码工具即可）。

## 铁律（先读）

1. **原件只读**。所有分析在副本上做；产物目录与原件分离（`target.apk` 不动）。
2. **区分观察/推断/未知**。每条结论标注来源（文件:行号、dex 偏移、ELF 地址、命令输出）。
3. **改包 = 改签名**。v2/v3 覆盖整包，改动必须重签；重签会改变 `wua`/客户端指纹，
   可能触发服务端风控（真实案例里表现为长连接被拒 + 组织侧安全告警）。
4. **客户端能改的只有客户端**。账号、组织、会话、考勤、灰度策略都在服务端；
   先判断“这是不是服务端判定”，再决定要不要改包。
5. **不在生产账号上试**。验证用测试账号 / 备用机。

## 流程（七步）

### 0. 目标识别（10 分钟定生死）
```bash
aapt2 dump badging target.apk | head -40      # 包名/版本/SDK/ABI/权限
apksigner verify --print-certs --verbose target.apk   # 签名方案与证书
python - <<'PY'                               # zip 结构异常扫描
import zipfile,collections
z=zipfile.ZipFile('target.apk'); i=z.infolist()
print(len(i), sum(x.compress_size for x in i)/1e6)
print(collections.Counter(x.filename.rsplit('.',1)[-1] for x in i if '.' in x.filename).most_common(10))
PY
```
关注：签名方案（v1/v2/v3）、证书主体、dex 数量与体积、`lib/<abi>` 数量、
条目时间戳是否同一构建会话、是否有重名/大小写冲突/路径穿越。

### 1. 解包与反编译
```bash
# 原始解包（保留字节，供后续精确比对）
python - <<'PY'
import zipfile,os
z=zipfile.ZipFile('target.apk')
for i in z.infolist():
    if i.is_dir(): continue
    p=os.path.join('unpacked',i.filename); os.makedirs(os.path.dirname(p),exist_ok=True)
    open(p,'wb').write(z.read(i))
PY

# 全量反编译（大包要给足堆与线程）
java -Xmx20g -cp jadx-all.jar jadx.cli.JadxCLI -d java -j 24 --no-res unpacked/dex/classes*.dex
```
详细参数、失败处理、覆盖率核算见 `references/02-decompile-index.md`。

### 2. 覆盖率核算（必做）
jadx 会**跳过 ACC_SYNTHETIC 类**，Windows 上还会因大小写不敏感覆盖同名文件。
用 `scripts/coverage_check.py` 算真实覆盖率，并把缺口写进报告，否则会被“看起来全反编译了”骗到。

### 3. 资源与清单
`apktool d -s`（只解资源）+ `aapt2 dump xmltree/resources`。
注意 apktool 会**重命名资源目录**（`drawable-xhdpi-v4` → `drawable-xhdpi`），做覆盖率统计时要归一化。
见 `references/03-resources.md`。

### 4. dex 层索引（功能地图）
自建轻量 dex 解析器（无需 androguard）遍历 `class_def`，产出：
类-包统计、进程表、路由表（intent-filter 的 scheme/host/path）、SP/DB/常量清单。
见 `references/02-decompile-index.md` 与 `scripts/dex_index.py`。

### 5. native 层
ELF 清点（类型/架构/strip/DT_NEEDED/JNI_OnLoad/RegisterNatives 表）；
识别加固特征（节头表擦除、UPX、字符串加密、java2jni 水印）；
段表被破坏时用 `PT_LOAD + PT_DYNAMIC` 重建。
见 `references/04-native.md`。

### 6. 安全栈与协议
- 安全：SecurityGuard / SafeGuard / ByteHook / Zoloz / 自研加密库 / 崩溃 SDK 的识别与验证矩阵；
- 协议：MTOP 签名原文、长连接帧格式、TLS 是否在平台栈。
见 `references/05-security.md`、`references/06-protocol.md`。

### 7. 补丁与验证
三条路线（按侵入性排序）：
1. **运行时 hook**（Frida）：零改包，需 root/gadget；
2. **字节级补丁**：只改常量/单条指令，重算 dex checksum+signature，重签；
3. **重建**（apktool/smali）：改动大时才用。
见 `references/07-patching-verify.md`；脚本 `scripts/patch_dex.py`、`patch_manifest.py`、`rebuild_apk.py`。

## 与 REA 协作

本环境带 REA 逆向工具链（打开 ELF/PE/APK/ASAR、反编译、反汇编、xref、调用图、证据）。
分工：**jadx 负责“面”，REA 负责“点”与证据**。

- native 精确定位：`open_binary` → `binary_overview` → `search_procedures`/`search_strings`
  → `xrefs` → `analyze_function` → `inspect_native_instruction`；
- Android 不开 App 看实现：`inspect_android_package` → `search_android_classes`
  → `inspect_android_method` → `trace_android_references`；
- 流量：`inspect_pcap_capture` / `inspect_web_network_capture`；
- 证据：`export_evidence_bundle`、`record_unknown`、`verify_reconstruction`。

完整映射（含每条链的命令与注意事项）见 `references/10-rea-integration.md`。

## 本案例知识库

`kb/` 是IM/IM 8.2.2.1（180,864 类、152 .so）完整逆向的检索库：
15 份分报告 + 方法论文档切块入库，支持中文子串检索。

```bash
python scripts/kb_query.py "长连接"                      # 全库
python scripts/kb_query.py "ISurgeon" --case imclient-8.2.2.1
python scripts/kb_query.py --stats                       # 规模 + 案例/来源清单
python scripts/kb_query.py --cases                       # 只列案例
```

## 累积新案例（每做完一个包就跑一次）

```bash
python scripts/kb_add_case.py --kb kb --case <case-id> \
    --from analysis/ REPORT.md \
    --title "…" --version "1.2.3" --package com.example.app \
    --sha256 <apk sha256> --classes <类数> --date 2026-11-26
```

它会：复制报告到 `kb/cases/<case-id>/reports/`、合并 `case.json`、重建索引。
约定：报告文件名带序号前缀（`00-`、`01-`…），重建后自动按文件名排序。
多个案例共享同一个 `kb.sqlite`，用 `--case` 限定检索范围。

## 目录

```
references/01-recon-container.md   容器/签名/清单/异常扫描
references/02-decompile-index.md   全量反编译、覆盖率、dex 索引
references/03-resources.md         资源解码、locale、品牌、raw/assets
references/04-native.md            ELF、加固、JNI 表、段表还原
references/05-security.md          安全栈、风控、检测清单
references/06-protocol.md          MTOP 签名、LWS 帧、抓包现实
references/07-patching-verify.md   三条补丁路线 + 真机验证 + 回滚
references/08-case-im-client.md     案例复盘：可行性边界与教训
references/09-ideas-log.md         想法台账：每条试过的路 + ✅/⚠️/❌ 依据
references/10-rea-integration.md   与 REA 工具链的协同（native/Android/流量/证据）
scripts/                           可直接复用的工具
assets/                            Frida 模板（字段 hook / ISurgeon / 机型伪装）
kb/cases/<case-id>/                各案例的报告与元数据
kb/kb.sqlite                       FTS5 检索库（trigram，中文子串可查）
```
