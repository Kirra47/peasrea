"""kb_build / kb_add_case / kb_query：知识库构建与检索（含中文子串）。"""
import json
import sqlite3

import kb_add_case
import kb_build

DOC = (
    "# 标题\n\n"
    "这里是一段正文，包含关键词：补丁、逆向、长连接、导出组件，"
    "长度足够触发切块阈值（>=200 字符的段落才会单独成块）。\n\n"
    "## 小节\n\n"
    "第二段继续补充内容，确保这一段也足够长，用于验证按标题切块的行为是否正确，"
    "以及 FTS5 的中文子串检索是否可用。\n"
)


def _mk(tmp_path):
    kb = tmp_path / "kb"
    refs = tmp_path / "references"
    (kb / "cases" / "c1" / "reports").mkdir(parents=True)
    refs.mkdir()
    (refs / "01-method.md").write_text(DOC, encoding="utf-8")
    (kb / "cases" / "c1" / "reports" / "01-report.md").write_text(DOC, encoding="utf-8")
    (kb / "cases" / "c1" / "case.json").write_text(
        json.dumps({"id": "c1", "title": "demo"}), encoding="utf-8")
    return kb


def _count(kb, where="1=1"):
    con = sqlite3.connect(kb / "kb.sqlite")
    try:
        return con.execute(f"SELECT COUNT(*) FROM chunks WHERE {where}").fetchone()[0]
    finally:
        con.close()


def test_build_creates_fts(tmp_path):
    kb = _mk(tmp_path)
    assert kb_build.main(["kb_build.py", "--kb", str(kb)]) == 0
    assert _count(kb) >= 2

    con = sqlite3.connect(kb / "kb.sqlite")
    try:
        cases = {r[0] for r in con.execute("SELECT DISTINCT case_id FROM chunks")}
        assert {"c1", "skill"} <= cases
        hit = con.execute(
            "SELECT heading FROM chunks_fts WHERE chunks_fts MATCH ? LIMIT 1",
            ('"长连接"',)).fetchone()
        assert hit is not None, "trigram 分词应支持中文子串（>=3 字）"
        # 不足 3 字时 trigram 无法命中，kb_query 会退回 LIKE —— 这里验证退路的数据面
        short = con.execute(
            "SELECT heading FROM chunks WHERE text LIKE ? LIMIT 1", ("%补丁%",)).fetchone()
        assert short is not None
    finally:
        con.close()


def test_add_case_grows_kb(tmp_path):
    kb = _mk(tmp_path)
    kb_build.main(["kb_build.py", "--kb", str(kb)])
    before = _count(kb)

    src = tmp_path / "new"
    src.mkdir()
    (src / "01-extra.md").write_text(DOC, encoding="utf-8")
    assert kb_add_case.main(
        ["kb_add_case.py", "--kb", str(kb), "--case", "c2", "--from", str(src)]) == 0

    assert _count(kb) > before
    assert _count(kb, "case_id='c2'") >= 1
    meta = json.loads((kb / "cases" / "c2" / "case.json").read_text(encoding="utf-8"))
    assert meta["id"] == "c2"


def test_index_md_written(tmp_path):
    kb = _mk(tmp_path)
    kb_build.main(["kb_build.py", "--kb", str(kb)])
    text = (kb / "index.md").read_text(encoding="utf-8")
    assert "知识库索引" in text
    assert "c1" in text
    assert "tokenizer" in text or "trigram" in text
