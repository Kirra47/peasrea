#!/usr/bin/env python3
"""kb_query.py — 查询本地逆向知识库（SQLite FTS5, trigram；支持中文子串）

用法:
    python kb_query.py "长连接"                      # 全库检索
    python kb_query.py "导出组件" --top 5
    python kb_query.py "ISurgeon" --case dingtalk-8.2.2.1
    python kb_query.py --stats                       # 规模 + 案例/来源清单
    python kb_query.py --cases                       # 只列案例

说明: trigram 分词，中文可用任意 ≥3 字片段检索；查不到会自动退回 LIKE 子串。
"""
import json
import os
import sqlite3
import sys

KB_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "kb", "kb.sqlite")


def out(s=""):
    try:
        sys.stdout.write(s + "\n")
    except UnicodeEncodeError:
        sys.stdout.buffer.write((s + "\n").encode("utf-8", "replace"))


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if len(argv) < 2:
        out(__doc__)
        return 1
    db = os.environ.get("KB_DB", KB_DEFAULT)
    if not os.path.exists(db):
        out("kb not found: " + db)
        return 1
    con = sqlite3.connect(db)

    if "--cases" in argv:
        for cid, cnt in con.execute(
                "SELECT case_id, COUNT(*) FROM chunks GROUP BY case_id ORDER BY 2 DESC"):
            out(f"  {cnt:5d}  {cid}")
        return 0

    if "--stats" in argv:
        out(json.dumps(dict(con.execute("SELECT k, v FROM meta").fetchall()),
                       ensure_ascii=False, indent=2))
        out("\n按案例:")
        for cid, cnt in con.execute(
                "SELECT case_id, COUNT(*) FROM chunks GROUP BY case_id ORDER BY 2 DESC"):
            out(f"  {cnt:5d}  {cid}")
        out("\n按来源 (top 20):")
        for src, cnt in con.execute(
                "SELECT source, COUNT(*) FROM chunks GROUP BY source ORDER BY 2 DESC LIMIT 20"):
            out(f"  {cnt:5d}  {src}")
        return 0

    case = None
    if "--case" in argv:
        j = argv.index("--case")
        case = argv[j + 1]
    skip = {"--top", "--case"}
    query = next((a for a in argv[1:]
                  if not a.startswith("--") and a not in skip
                  and (case is None or a != case)), None)
    if not query:
        out(__doc__)
        return 1
    top = int(argv[argv.index("--top") + 1]) if "--top" in argv else 8

    where = "chunks_fts MATCH ?" + (" AND c.case_id = ?" if case else "")
    params = ['"%s"' % query.replace('"', '""')] + ([case] if case else []) + [top]
    try:
        rows = con.execute(
            f"""SELECT c.case_id, c.source, c.heading,
                       snippet(chunks_fts, 0, '[', ']', ' … ', 30)
                FROM chunks_fts f JOIN chunks c ON c.id = f.rowid
                WHERE {where} ORDER BY rank LIMIT ?""", params).fetchall()
    except sqlite3.OperationalError as e:
        out("query error: %s" % e)
        rows = []
    if not rows:
        sql = "SELECT case_id, source, heading, substr(text,1,400) FROM chunks WHERE text LIKE ?"
        p = [f"%{query}%"]
        if case:
            sql += " AND case_id = ?"
            p.append(case)
        rows = con.execute(sql + " LIMIT ?", p + [top]).fetchall()
    if not rows:
        out("no match. try a shorter substring.")
        return 0
    for cid, src, heading, snip in rows:
        out(f"\n=== {heading}  [{cid}] {src}")
        out("    " + snip.replace("\n", " ")[:600])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
