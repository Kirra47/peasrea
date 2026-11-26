#!/usr/bin/env python3
"""kb_add_case.py — 把一个新案例的报告并入知识库（可重复、可累积）

用法:
    python kb_add_case.py --kb <kb_dir> --case <case-id> --from <dir_or_md...> \
        [--title T] [--version V] [--package P] [--sha256 H] [--classes N] \
        [--date YYYY-MM-DD] [--notes "..."] [--no-rebuild]

行为:
  1. 建 <kb>/cases/<case-id>/reports/，把 --from 里的 .md 复制进去（同名覆盖）
  2. 合并写入 <kb>/cases/<case-id>/case.json（已有元数据不丢）
  3. 默认重建索引（等价于跑一次 kb_build.py）

约定: 报告文件名建议带序号前缀（00-、01-…），kb_build 会按文件名排序入库。
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_build  # noqa: E402


def main(argv):
    def opt(name, default=None):
        return argv[argv.index(name) + 1] if name in argv else default

    kb_dir = os.path.abspath(opt("--kb") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "kb"))
    case_id = opt("--case")
    if not case_id:
        print(__doc__)
        return 1
    i = argv.index("--from")
    srcs = [a for a in argv[i + 1:] if not a.startswith("--")]

    case_dir = os.path.join(kb_dir, "cases", case_id)
    reports = os.path.join(case_dir, "reports")
    os.makedirs(reports, exist_ok=True)

    copied = 0
    for s in srcs:
        if os.path.isdir(s):
            for f in sorted(os.listdir(s)):
                if f.endswith(".md"):
                    shutil.copy2(os.path.join(s, f), os.path.join(reports, f))
                    copied += 1
        elif s.endswith(".md"):
            shutil.copy2(s, os.path.join(reports, os.path.basename(s)))
            copied += 1

    meta_path = os.path.join(case_dir, "case.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    meta.update({"id": case_id})
    for k, flag in (("title", "--title"), ("version", "--version"),
                    ("package", "--package"), ("sha256", "--sha256"),
                    ("classes", "--classes"), ("date", "--date"),
                    ("notes", "--notes")):
        v = opt(flag)
        if v is not None:
            meta[k] = v
    meta.setdefault("date", "")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)

    print(json.dumps({"case": case_id, "reports_copied": copied,
                      "reports_total": len([f for f in os.listdir(reports) if f.endswith('.md')])},
                     ensure_ascii=False))
    if "--no-rebuild" not in argv:
        kb_build.main(["kb_build.py", "--kb", kb_dir])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
