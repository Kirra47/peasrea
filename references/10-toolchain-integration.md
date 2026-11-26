# 10 · 与 REA 协同（本环境自带的逆向工具链）

REA（Reverse Engineering Agent）是一组 MCP 工具：能直接打开 ELF/PE/Mach-O/APK/ASAR/plist，
给出反编译、反汇编、交叉引用、字符串、段表、调用图，并把每条结果记成**带来源的证据**。
它与 jadx/grep 的分工如下。

## 什么时候用 REA，什么时候用普通工具

| 场景 | 选择 |
|---|---|
| 读 Java 源码、按包名翻类 | jadx + grep/read（快、便宜） |
| 精确定位某条 native 指令、某个函数调用者 | **REA**（`analyze_function` / `xrefs` / `inspect_native_instruction`） |
| 判断一个 `.so` 用了什么库、有没有被加固 | **REA**（`binary_overview` / `inspect_binary_layout`） |
| 需要“可复核的证据链”（谁调用谁、字符串被谁引用） | **REA**（自动产出 evidence id、覆盖率和限制说明） |
| APK 里某个类/方法的行为（不启动 App） | **REA**（`search_android_classes` / `inspect_android_method`） |
| 抓包/运行时行为 | 本项目脚本 + Frida，REA 负责解析产物（pcap/har） |

REA 的结论带 `confidence: observed / derived / inferred` 与 `limitations`，
写报告时**照抄这三项**，比自己在文档里写“推测”更可靠。

## 阶段映射

### 0–1 容器与规模
| 目的 | 工具 |
|---|---|
| 打开并清点 APK/ASAR/PLIST 内容 | `inspect_artifact`（+ `detail: summary` 再分页读） |
| 抽出全部文件 | `extract_artifact` |
| 两个版本比差异 | `compare_artifacts` |

### 5 native 层（REA 最强的一块）
| 目的 | 工具 |
|---|---|
| 打开 `.so` 并看规模/段/符号数 | `open_binary` → `binary_overview` |
| ELF 布局、重定位、缓解措施（PIE/NX/RELRO） | `inspect_binary_layout` |
| 字符串检索与引用定位 | `search_strings` → `xrefs` |
| 函数清单/按名搜索 | `list_procedures` / `search_procedures` |
| 反编译 + 反汇编 + 调用者/被调用者 | `analyze_function`（一次拿到 dossier） |
| 单条指令 + 入边（谁跳到这里） | `inspect_native_instruction` |
| 间接调用解析（vtable/函数指针） | `resolve_native_call_targets` |
| 字节特征扫描（找魔数/常量表） | `search_bytes` |
| 调用图（前向/后向、最短路径） | `get_call_graph` / `trace_call_path` / `build_call_path` |
| 数据流（参数→汇点） | `trace_native_values` |
| Go / Rust 二进制元信息 | `inspect_go_binary` / `inspect_rust_binary` |
| PE 资源（图标/清单/版本） | `inspect_pe_resources` |
| 崩溃转储 | `inspect_recorded_crash` |

**典型一条链**（找 “谁调用了 SSL_write”）：
```
open_binary(libgaea.so)
→ binary_overview                       # 确认导出符号存在
→ search_procedures("SSL_write")        # 或 list_names
→ xrefs(<addr>)                         # 入边
→ analyze_function(<caller>)            # 反编译 + 调用点
→ inspect_native_instruction(<call site>)  # 精确参数
```

### 4/6 Android 包与类（不开 App）
| 目的 | 工具 |
|---|---|
| manifest 权限/组件/SDK/类数 | `inspect_android_package` |
| 资源解码（strings/manifest 明文） | `decode_android_resources` |
| 类名搜索 | `search_android_classes` |
| 类成员（方法/字段/内部类） | `inspect_android_class` |
| 方法反编译（含 smali 回退） | `inspect_android_method` |
| 谁在调用这个类/方法 | `trace_android_references` |
| Flutter 构建识别 / Dart AOT 字符串 | `identify_flutter_build` / `inspect_dart_aot` |
| 从真机拉包 | `pull_adb_package` → 再 `inspect_android_package` |

### 7 运行时与流量
| 目的 | 工具 |
|---|---|
| 设备/进程/日志/截图 | `list_adb_devices` / `list_adb_processes` / `read_adb_logcat` / `capture_adb_screen` |
| 拉起 App 做动态分析 | `start_adb_app`（配对 `stop_adb_app`） |
| pcap / har / qlog 解析 | `inspect_pcap_capture` / `inspect_web_network_capture` |
| 单包字段过滤 | `inspect_packet_capture`（配合 `inspect_packet_fields` 查字段名） |
| Frida 注入 | `list_frida_devices` → `start_frida_session` → `load_frida_script` → （`instrument_with_frida` 一次性也行） |
| 原生调试 | `start_gdb_session` / `gdb_console`；`start_rizin_debug_session` / `rizin_debug_command` |

### WebView / H5（本项目 H5 部分）
| 目的 | 工具 |
|---|---|
| 列页面 target | `list_browser_targets`（需 CDP endpoint） |
| 静态看页面结构/脚本/网络 | `inspect_web_page` |
| 抓 JS 包并找接口 | `analyze_web_bundle` / `export_web_scripts` |
| 复现交互场景 | `capture_browser_scenario` |
| 看覆盖率/执行 | `observe_web_execution` |

### 证据沉淀
| 目的 | 工具 |
|---|---|
| 导出本次全部证据 | `export_evidence_bundle` |
| 回放/合并 | `import_evidence_bundle`；比对 `compare_bundles` |
| 记录未解问题 | `record_unknown` / `update_unknown` / `list_unknowns` |
| 验证“重建是否覆盖需求” | `verify_reconstruction` / `evaluate_reconstruction_coverage` |

## 与 jadx 的配合

1. jadx 负责“面”（全量、可搜、可读）；
2. REA 负责“点”（精确地址/指令/证据）；
3. 报告里两者都标来源：`analysis/xx.md:NN` 与 `ev_xxxxxxxx`（REA evidence id）。

## 注意

- REA 打开大文件（>200 MB）会慢，先 `inspect_artifact` 看清单，再 `open_binary` 单个 `.so`；
- `analyze_function` 的输出很长，优先用 `detail: summary` 或 `inspect_analysis_view` 分页；
- REA 的“覆盖率/限制”是判断可信度的关键字段，**不要删**，它决定了结论能不能写进报告；
- 同一份证据二次利用时用 `get_evidence_bundle` + retained `evidence_id`，避免重复分析。
