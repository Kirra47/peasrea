"""sanitize_capture.py：抓包脱敏（PII / token / 电话 / 邮箱 / 嵌套 JSON）。"""
import json

import sanitize_capture as sc


def _run(tmp_path, records, names=""):
    src = tmp_path / "in.jsonl"
    out = tmp_path / "out.jsonl"
    src.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records), encoding="utf-8")
    argv = ["sanitize_capture.py", str(src), "-o", str(out)]
    if names:
        argv += ["--names", names]
    assert sc.main(argv) == 0
    return [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]


def test_masks_identity_fields(tmp_path):
    rec = {
        "path": "/api/portal/auth/me",
        "resp_body": json.dumps({
            "code": 200,
            "data": {"empNo": "12345", "displayName": "张三", "unitName": "某单位",
                     "points": 10, "isAdmin": False},
        }, ensure_ascii=False),
    }
    out = _run(tmp_path, [rec])[0]
    body = json.loads(out["resp_body"])
    assert body["data"]["empNo"] == "<redacted>"
    assert body["data"]["displayName"] == "<redacted>"
    assert body["data"]["points"] == 10, "非敏感字段必须保留"
    assert body["data"]["isAdmin"] is False


def test_masks_nested_json_string(tmp_path):
    inner = json.dumps({"recipients": [{"name": "工会", "email": "a@b.com"}]}, ensure_ascii=False)
    rec = {"path": "/api/portal/custom-pages/x",
           "resp_body": json.dumps({"data": {"config": inner}}, ensure_ascii=False)}
    out = _run(tmp_path, [rec])[0]
    body = json.loads(out["resp_body"])
    cfg = json.loads(body["data"]["config"])
    assert cfg["recipients"][0]["email"] == "<redacted>"
    assert cfg["recipients"][0]["name"] == "<redacted>"


def test_masks_query_and_tokens(tmp_path):
    rec = {"path": "/passport/v1/auth/dingtalk?code=abc&platform=Android",
           "resp_body": json.dumps({"data": {"csrfToken": "x" * 32, "ticket": "t"}}, ensure_ascii=False)}
    out = _run(tmp_path, [rec])[0]
    assert "code=<redacted>" in out["path"]
    assert "platform=Android" in out["path"], "非敏感参数保留"
    body = json.loads(out["resp_body"])
    assert body["data"]["csrfToken"] == "<redacted>"
    assert body["data"]["ticket"] == "<redacted>"


def test_regex_scrubs_free_text(tmp_path):
    rec = {"path": "/x", "resp_body": "联系 13800001111 或 a.b@c.com"}
    out = _run(tmp_path, [rec])[0]
    assert "13800001111" not in out["resp_body"]
    assert "a.b@c.com" not in out["resp_body"]
    assert "<phone>" in out["resp_body"] and "<email>" in out["resp_body"]


def test_names_option(tmp_path):
    rec = {"path": "/x", "resp_body": '{"title":"致 李四 的公告","id":1}'}
    out = _run(tmp_path, [rec], names="李四")[0]
    assert "李四" not in out["resp_body"]
    assert "<redacted>" in out["resp_body"]
