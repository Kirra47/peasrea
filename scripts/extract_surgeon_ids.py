#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 jadx 反编译源码抽取 Surgeon 插桩契约：类 -> 方法签名 -> surgeon id。

输入：一个文件列表（每行一个 java 路径，相对 java/ 目录），由 `grep -rl 'surgeon$dispatch'` 生成。
输出 TSV：class \t method \t id \t kind \t line \t source
"""
import io, os, re, sys

LIST = sys.argv[1]
BASE = sys.argv[2] if len(sys.argv) > 2 else "java"
OUT = sys.argv[3] if len(sys.argv) > 3 else "scan/security/surgeon_ids.tsv"

ID_RE = re.compile(r'InstrumentAPI\.support\(\s*\w+\s*,\s*"(-?\d+)"\s*\)')
DISPATCH_RE = re.compile(r'surgeon\$dispatch\(\s*"(-?\d+)"')
METHOD_RE = re.compile(
    r'^    (?:(?:public|protected|private)\s+)?(?:(?:static|final|synchronized|abstract|native)\s+)*'
    r'([\w\.\[\]<>\?,\s\$]+?)\s+([\w\$<>]+)\s*\(([^)]*)\)'
    r'(?:\s*throws\s+[\w\.,\s]+)?\s*\{\s*$'
)
CTOR_RE = re.compile(r'^    (?:(?:public|protected|private)\s+)?([\w\$]+)\s*\(([^)]*)\)\s*\{\s*$')


def parse(path, cls):
    out = []
    cur = None
    try:
        fh = io.open(path, encoding='utf-8', errors='replace')
    except Exception:
        return out
    with fh:
        for i, ln in enumerate(fh, 1):
            s = ln.rstrip('\n')
            if s.endswith('{') and s.startswith('    ') and '(' in s:
                m = METHOD_RE.match(s)
                if m and m.group(1).strip() not in ('if', 'for', 'while', 'switch', 'catch', 'else'):
                    cur = f"{m.group(1).strip()} {m.group(2)}({m.group(3).strip()})"
                else:
                    mc = CTOR_RE.match(s)
                    if mc and mc.group(1) not in ('if', 'for', 'while', 'switch', 'catch', 'else', 'try', 'synchronized'):
                        cur = f"<init>({mc.group(2).strip()})"
            for mid in ID_RE.findall(s):
                kind = 'ternary' if '?' in s and ':' in s else 'if'
                out.append((cls, cur or '<field/static-init>', mid, kind, i))
            if DISPATCH_RE.search(s) and not ID_RE.search(s):
                for mid in DISPATCH_RE.findall(s):
                    out.append((cls, cur or '<field/static-init>', mid, 'dispatch-reuse', i))
    return out


def main():
    rows = []
    n = 0
    with io.open(LIST, encoding='utf-8', errors='replace') as f:
        for line in f:
            p = line.strip()
            if not p:
                continue
            n += 1
            full = os.path.join(BASE, p) if not os.path.isabs(p) else p
            cls = os.path.relpath(full, BASE).replace('\\', '/')[:-5].replace('/', '.')
            rows.extend(parse(full, cls))
    rows.sort()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write("class\tmethod\tid\tkind\tline\tsource\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    print(f"parsed files={n} rows={len(rows)} distinct_ids={len({r[2] for r in rows})}")


main()
