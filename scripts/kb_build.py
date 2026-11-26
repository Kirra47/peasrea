#!/usr/bin/env python3
"""kb_build.py — 构建多案例知识库（SQLite FTS5, trigram 分词）

用法:
    python kb_build.py --kb <kb_dir> [--no-refs] [--extra <dir_or_md> ...]

目录约定:
    <kb_dir>/cases/<case-id>/case.json      案例元数据（可选）
    <kb_dir>/cases/<case-id>/reports/*.md   该案例的报告
    <kb_dir>/../references/*.md             方法论文档（默认一起入库，来源标记 skill）

产出:
    <kb_dir>/findings.jsonl   每块一行（id/case/source/heading/text/chars）
    <kb_dir>/kb.sqlite        FTS5 表 chunks_fts(text, heading, source, case)
    <kb_dir>/index.md         规模统计 + 案例清单
"""
import json
import os
import re
import sqlite3
import sys

HEAD = re.compile(r"^(#{1,6})\s+(.*)$")


def chunk_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    chunks, cur_head, cur = [], os.path.basename(path), []
    for line in lines:
        m = HEAD.match(line)
        if m:
            if cur and sum(len(x) for x in cur) >= 200:
                chunks.append((cur_head, "\n".join(cur).strip()))
                cur = []
            cur_head = m.group(2).strip() or cur_head
            cur.append(line)
        else:
            cur.append(line)
    if cur:
        chunks.append((cur_head, "\n".join(cur).strip()))
    return [(h, t) for h, t in chunks if t.strip()]


def case_meta(case_dir):
    p = os.path.join(case_dir, "case.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {"id": os.path.basename(case_dir)}


def main(argv):
    kb_dir = None
    if "--kb" in argv:
        kb_dir = argv[argv.index("--kb") + 1]
    if not kb_dir:
        kb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "kb")
    kb_dir = os.path.abspath(kb_dir)
    extras = []
    if "--extra" in argv:
        i = argv.index("--extra")
        for a in argv[i + 1:]:
            if a.startswith("--"):
                break
            extras.append(a)
    include_refs = "--no-refs" not in argv

    sources = []  # (case, path)
    cases_root = os.path.join(kb_dir, "cases")
    case_list = []
    if os.path.isdir(cases_root):
        for cid in sorted(os.listdir(cases_root)):
            cdir = os.path.join(cases_root, cid)
            rdir = os.path.join(cdir, "reports")
            if not os.path.isdir(rdir):
                continue
            meta = case_meta(cdir)
            case_list.append(meta)
            for f in sorted(os.listdir(rdir)):
                if f.endswith(".md"):
                    sources.append((cid, os.path.join(rdir, f)))
    if include_refs:
        refs = os.path.abspath(os.path.join(kb_dir, "..", "references"))
        if os.path.isdir(refs):
            for f in sorted(os.listdir(refs)):
                if f.endswith(".md"):
                    sources.append(("skill", os.path.join(refs, f)))
    for e in extras:
        if os.path.isdir(e):
            for root, _, files in os.walk(e):
                for f in sorted(files):
                    if f.endswith(".md"):
                        sources.append(("extra", os.path.join(root, f)))
        elif e.endswith(".md"):
            sources.append(("extra", e))

    if not sources:
        print("no markdown found. expected <kb>/cases/<id>/reports/*.md or ../references/*.md")
        return 1

    # 表头若被当成独立块会出现大量“空章节”，统一丢弃纯标题块
    rows, n, per_case = [], 0, {}
    for case_id, path in sources:
        label = case_id + "/" + os.path.basename(path)
        for heading, text in chunk_file(path):
            body = "\n".join(l for l in text.splitlines() if not HEAD.match(l)).strip()
            if len(body) < 40:
                continue
            n += 1
            rows.append({"id": n, "case": case_id, "source": label,
                         "heading": heading, "text": text, "chars": len(text)})
            per_case[case_id] = per_case.get(case_id, 0) + 1

    os.makedirs(kb_dir, exist_ok=True)
    with open(os.path.join(kb_dir, "findings.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    db_path = os.path.join(kb_dir, "kb.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)
    con = sqlite3.connect(db_path)
    tokenizer = "trigram"
    try:
        con.execute("CREATE VIRTUAL TABLE __probe USING fts5(x, tokenize='trigram')")
        con.execute("DROP TABLE __probe")
    except sqlite3.OperationalError:
        tokenizer = "unicode61"
    con.executescript(
        f"""
        CREATE TABLE chunks(id INTEGER PRIMARY KEY, case_id TEXT, source TEXT,
                            heading TEXT, text TEXT);
        CREATE VIRTUAL TABLE chunks_fts USING fts5(text, heading, source, case_id,
            content='chunks', content_rowid='id', tokenize='{tokenizer}');
        CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
        """
    )
    con.executemany(
        "INSERT INTO chunks(id, case_id, source, heading, text) VALUES (?,?,?,?,?)",
        [(r["id"], r["case"], r["source"], r["heading"], r["text"]) for r in rows],
    )
    con.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
    con.executemany("INSERT INTO meta(k, v) VALUES (?,?)", [
        ("blocks", str(len(rows))),
        ("chars", str(sum(r["chars"] for r in rows))),
        ("sources", str(len({r["source"] for r in rows}))),
        ("cases", str(len(per_case))),
        ("tokenizer", tokenizer),
    ])
    con.commit()
    con.close()

    with open(os.path.join(kb_dir, "index.md"), "w", encoding="utf-8") as fh:
        fh.write("# 知识库索引\n\n")
        fh.write(f"- 块数 **{len(rows)}** ｜ 字符 **{sum(r['chars'] for r in rows):,}** "
                 f"｜ 分词 `{tokenizer}`\n\n## 案例\n\n")
        meta_by_id = {m.get("id"): m for m in case_list}
        for cid, cnt in sorted(per_case.items()):
            m = meta_by_id.get(cid, {})
            title = m.get("title") or cid
            ver = m.get("version", "")
            fh.write(f"- **{cid}** — {title} {ver}（{cnt} 块）\n")
            for k in ("package", "sha256", "date", "classes"):
                if m.get(k):
                    fh.write(f"  - {k}: `{m[k]}`\n")
        fh.write("\n## 来源\n\n")
        src_counts = {}
        for r in rows:
            src_counts[r["source"]] = src_counts.get(r["source"], 0) + 1
        for src in sorted(src_counts):
            fh.write(f"- `{src}` — {src_counts[src]} 块\n")

    print(json.dumps({"blocks": len(rows), "cases": len(per_case),
                      "sources": len({r['source'] for r in rows}),
                      "chars": sum(r["chars"] for r in rows),
                      "tokenizer": tokenizer}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
