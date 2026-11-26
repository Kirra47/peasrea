# PeasRea

> 大型 Android 客户端的**可复核逆向工作流**：技能包 + 可复用工具 + 可检索知识库。
>
> 不是「教你破解某个 App」，而是把「怎么把一个 18 万类的包拆明白、并且每一步都能被验证」写成流程。

```
 30 dex / 180,864 classes / 152 .so / 244 MB native
        │
        ├── 01 容器与签名      → 你在跟什么打交道
        ├── 02 反编译与索引    → 覆盖率可核算，不靠感觉
        ├── 03 资源与配置      → 运行时行为的默认值在哪
        ├── 04 native 层       → 加固识别 / 段表还原 / JNI 表重建
        ├── 05 安全栈          → 改包前先算清代价
        ├── 06 协议            → 抓不抓得到，先看 TLS 在哪一层
        ├── 07 补丁与验证      → 三条路线 + 真机验证 + 回滚
        └── 08–10 复盘 / 台账 / 工具链协同
```

## 它是什么

| 组成 | 说明 |
|---|---|
| **SKILL.md** | 七步流程 + 五条铁律 + 何时用/何时不用。可被支持 skill 的 agent 直接加载 |
| **references/** | 10 篇方法论，每篇都是「命令 + 判读 + 坑」 |
| **scripts/** | 可直接跑的工具：dex 索引、覆盖率核算、dex/AXML 字节补丁、重建、知识库构建与检索 |
| **assets/** | Frida 模板：字段 hook、插桩体系接管、机型伪装 |
| **kb/** | 从一次完整案例切块建成的检索库（SQLite FTS5 + trigram，中文子串可查） |

## 快速开始

```bash
git clone <this-repo> peasrea
cd peasrea

# 1) 安装成技能（可选，供支持 skill 的 agent 使用）
bash install.sh                 # macOS / Linux
pwsh -File install.ps1          # Windows
#   → 复制到 ~/.agents/skills/peasrea

# 2) 直接查知识库
python scripts/kb_query.py "长连接"
python scripts/kb_query.py "ISurgeon" --case im-client-8.2.2.1
python scripts/kb_query.py --stats

# 3) 对自己的包跑一遍
python scripts/dex_index.py <unpacked>/dex --out dex-index
python scripts/coverage_check.py java/sources <unpacked>/dex --json cov.json
```

只依赖 Python 3.9+ 标准库（SQLite 需带 FTS5，官方发行版默认带）。

## 脚本

| 脚本 | 用途 |
|---|---|
| `coverage_check.py` | 真实口径的反编译覆盖率（区分 synthetic / 内部类 / 默认包） |
| `dex_index.py` | 轻量 dex 索引：类表、包统计、重复类（18 万类 < 1 秒） |
| `patch_manifest.py` | 二进制 AXML 直接改 `android:exported`（不重打包） |
| `patch_dex.py` | 常量级字节补丁，自动重算 checksum + SHA-1 |
| `rebuild_apk.py` | 替换条目 + 剔除旧签名 |
| `extract_surgeon_ids.py` | 从插桩样板里抽取 (方法, id) 映射表 |
| `kb_build.py` / `kb_add_case.py` / `kb_query.py` | 知识库构建 / 追加案例 / 检索 |
| `observe_readonly.sh` | 只读真机观测（不安装、不清数据、不点屏） |

## 知识库

```bash
python scripts/kb_query.py --stats         # 规模、按案例/来源统计
python scripts/kb_query.py --cases         # 案例列表
python scripts/kb_query.py "导出组件" --top 5
```

当前收录 **390 块 / 35 万字**：
- `im-client-8.2.2.1` —— 一次完整案例的 17 份报告（品牌与账号信息已脱敏）
- `skill` —— 本仓库的方法论文档

追加自己的案例（报告放进 `analysis/` 后）：

```bash
python scripts/kb_add_case.py --kb kb --case my-app-1.0 --from analysis/ REPORT.md \
  --title "…" --version "1.0" --package com.example.app --sha256 <hash> --classes <n>
```

## 方法论要点（摘自 references）

- **先分层，再动手**：业务 API / 自研长连接 / 传输层（HTTP2+QUIC）/ 寻址降级，四层各自独立；
- **抓包先判断 TLS 归属**：TLS 在平台栈可代理，静态链入 native 就只能 hook；
- **改包 = 改签名 = 改客户端指纹**：能登录 ≠ 没被发现；
- **服务端策略不可客户端绕过**：会话、考勤、灰度、权限都在服务端；
- **证据三态**：观察 / 推导 / 未知，报告里必须分开写。

## 免责声明

本项目用于**自有应用或已获授权目标**的安全研究、兼容性分析与教学。
仓库内案例报告已做脱敏（包名、账号、组织、域名、密钥均替换为占位符）。
使用者应自行确保其行为符合当地法律与目标服务条款；作者不对误用承担责任。

## License

MIT
