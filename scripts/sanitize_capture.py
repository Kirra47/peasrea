#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sanitize_capture.py — 抓包结果脱敏（分享/归档前跑一遍）

    python sanitize_capture.py capture.jsonl -o capture.public.jsonl [--names 张三,李四]

处理：
  1) JSON 响应/请求体里按字段名打码（name / displayName / empNo / email / ticket / sid …）
  2) 字符串里嵌套的 JSON（如 `config`）递归解析后再打码
  3) 全局正则兜底：邮箱、手机号、18 位身份证、32/36 位 token
  4) query 里疑似身份参数（user/uid/name/emp/token/sid/code/t）整体替换
  5) --names 指定的人名做字面替换

只改值不改结构，便于贴进报告/issue。
"""
import argparse
import json
import re
import sys

MASK = "<redacted>"

PII_KEYS = {
    "name", "username", "displayname", "nickname", "realname", "otherusername",
    "empno", "userid", "otheruserid", "uid", "account", "openid",
    "email", "mail", "phone", "mobile", "tel", "idcard", "idnumber",
    "avatar", "avatarurl", "otheravatar",
    "unitname", "dptcode", "dptname", "sectioncode", "sectionname", "groupname",
    "token", "accesstoken", "csrftoken", "ticket", "sidticket", "sid", "session",
    "cookie", "authorization", "clientip", "ip", "ukey", "authinfoukey", "lastmessage",
}

SECRET_QUERY = {"token", "sid", "t", "code", "cookie", "session", "signature", "sig",
                "user", "uid", "name", "emp", "empno", "mobile", "phone"}

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
IDCARD = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
LONGTOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def _maybe_json(text):
    t = text.strip()
    if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
        try:
            return json.loads(t)
        except Exception:
            return None
    return None


def mask_value(v):
    if isinstance(v, dict):
        return {k: (MASK if k.lower() in PII_KEYS else mask_value(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_value(x) for x in v]
    if isinstance(v, str):
        nested = _maybe_json(v)
        if nested is not None:
            return json.dumps(mask_value(nested), ensure_ascii=False)
        return scrub_text(v)
    return v


def scrub_text(s):
    s = EMAIL.sub("<email>", s)
    s = PHONE.sub("<phone>", s)
    s = IDCARD.sub("<idcard>", s)
    s = LONGTOKEN.sub("<hex>", s)
    return s


def mask_body(text):
    if not text:
        return text
    nested = _maybe_json(text)
    if nested is not None:
        return json.dumps(mask_value(nested), ensure_ascii=False)
    # 表单体 a=1&b=2
    if "=" in text and "&" in text or re.match(r"^[\w.\-]+=", text or ""):
        parts = []
        for kv in text.split("&"):
            k, _, v = kv.partition("=")
            parts.append(f"{k}={MASK}" if k.lower() in PII_KEYS else f"{k}={scrub_text(v)}")
        return "&".join(parts)
    return scrub_text(text)


def mask_query(q):
    parts = []
    for kv in q.split("&"):
        k, _, v = kv.partition("=")
        parts.append(f"{k}={MASK}" if k.lower() in SECRET_QUERY else f"{k}={scrub_text(v)}")
    return "&".join(parts)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0].endswith(".py"):   # 允许传 ["sanitize_capture.py", ...]
        argv = argv[1:]
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--names", default="", help="额外要打码的人名，逗号分隔")
    args = ap.parse_args(argv)

    names = [n.strip() for n in args.names.split(",") if n.strip()]
    n = 0
    with open(args.src, encoding="utf-8") as fin, open(args.out, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rec["resp_body"] = mask_body(rec.get("resp_body"))
            rec["req_body"] = mask_body(rec.get("req_body"))
            p = rec.get("path") or ""
            if "?" in p:
                head, _, q = p.partition("?")
                rec["path"] = head + "?" + mask_query(q)
            blob = json.dumps(rec, ensure_ascii=False)
            for nm in names:
                blob = blob.replace(nm, MASK)
            fout.write(blob + "\n")
            n += 1
    print(f"sanitized {n} records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
