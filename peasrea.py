#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PeasRea CLI —— 一个入口调用仓库里全部工具。

    peasrea info                            # 版本 + 知识库规模
    peasrea query 长连接 [--case ID] [--top N]
    peasrea kb-build
    peasrea kb-add-case --case ID --from DIR [--title ...] [--version ...]
    peasrea index <dex_dir> [--out DIR]
    peasrea coverage <java_dir> <dex_dir> [--json FILE]
    peasrea manifest <src.xml> <dst.xml> <class...>

也可以不安装直接用：`python peasrea.py <子命令> ...`
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
__version__ = "0.1.0"


def _load(name):
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    return __import__(name)


def _usage():
    print(__doc__.strip())


def cmd_info(argv):
    print(f"PeasRea {__version__}")
    print(f"repo    {ROOT}")
    try:
        kb = _load("kb_query")
        import sqlite3
        con = sqlite3.connect(ROOT / "kb" / "kb.sqlite")
        blocks = con.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        cases = con.execute("SELECT COUNT(DISTINCT case_id) FROM chunks").fetchone()[0]
        con.close()
        print(f"kb      {blocks} blocks / {cases} cases")
    except Exception as exc:  # 知识库缺失不应让 info 失败
        print(f"kb      (unavailable: {exc})")
    return 0


def cmd_query(argv):
    return _load("kb_query").main(["kb_query.py", *argv])


def cmd_kb_build(argv):
    return _load("kb_build").main(["kb_build.py", "--kb", str(ROOT / "kb"), *argv])


def cmd_kb_add_case(argv):
    return _load("kb_add_case").main(
        ["kb_add_case.py", "--kb", str(ROOT / "kb"), *argv])


def cmd_index(argv):
    return _load("dex_index").main(["dex_index.py", *argv])


def cmd_coverage(argv):
    return _load("coverage_check").main(["coverage_check.py", *argv])


def cmd_manifest(argv):
    if len(argv) < 3:
        print("usage: peasrea manifest <src.xml> <dst.xml> <class...>")
        return 1
    mod = _load("patch_manifest")
    src, dst, targets = argv[0], argv[1], argv[2:]
    ax = mod.Axml(open(src, "rb").read())
    rc = 0
    for t in targets:
        ok = ax.set_exported(t)
        print(("OK   " if ok else "MISS ") + t)
        rc |= 0 if ok else 2
    ax.save(dst)
    return rc


COMMANDS = {
    "info": cmd_info,
    "query": cmd_query,
    "kb-build": cmd_kb_build,
    "kb-add-case": cmd_kb_add_case,
    "index": cmd_index,
    "coverage": cmd_coverage,
    "manifest": cmd_manifest,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0 if argv else 1
    if argv[0] in ("-V", "--version"):
        print(__version__)
        return 0
    cmd, rest = argv[0], argv[1:]
    fn = COMMANDS.get(cmd)
    if not fn:
        print(f"unknown command: {cmd}\n")
        _usage()
        return 1
    return fn(rest) or 0


if __name__ == "__main__":
    sys.exit(main())
