#!/usr/bin/env python3
"""dex_index.py — 轻量 dex 索引（无需 androguard）

用法:
    python dex_index.py <dex_dir> [--out outdir]

产出（outdir 默认 ./dex-index）:
    classes.tsv         descriptor  access(hex)  dex 包
    package-stats.tsv   包  类数
    summary.json        规模/去重/重复类统计
"""
import collections
import json
import os
import struct
import sys


def uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def read_dex(path):
    data = open(path, "rb").read()
    if data[:4] != b"dex\n":
        return []
    str_n, str_off = struct.unpack_from("<II", data, 56)
    type_n, type_off = struct.unpack_from("<II", data, 64)
    cls_n, cls_off = struct.unpack_from("<II", data, 96)
    str_offs = struct.unpack_from("<%dI" % str_n, data, str_off)
    type_ids = struct.unpack_from("<%dI" % type_n, data, type_off)

    def string(idx):
        off = str_offs[idx]
        _, off = uleb128(data, off)
        end = data.index(b"\x00", off)
        return data[off:end].decode("utf-8", "replace")

    out = []
    for i in range(cls_n):
        class_idx, access = struct.unpack_from("<II", data, cls_off + i * 32)
        out.append((string(type_ids[class_idx]), access))
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    dex_dir = argv[1]
    out_dir = argv[argv.index("--out") + 1] if "--out" in argv else "dex-index"
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    dup = collections.Counter()
    for name in sorted(os.listdir(dex_dir)):
        if not name.endswith(".dex"):
            continue
        for desc, acc in read_dex(os.path.join(dex_dir, name)):
            rows.append((desc, acc, name))
            dup[desc] += 1

    rows.sort()
    with open(os.path.join(out_dir, "classes.tsv"), "w", encoding="utf-8", newline="") as fh:
        fh.write("descriptor\taccess\tdex\tpackage\n")
        for desc, acc, dex in rows:
            body = desc[1:-1] if desc.startswith("L") else desc
            pkg = body.rsplit("/", 1)[0].replace("/", ".") if "/" in body else "<default>"
            fh.write(f"{desc}\t0x{acc:08x}\t{dex}\t{pkg}\n")

    pkgs = collections.Counter()
    for desc, acc, dex in rows:
        body = desc[1:-1] if desc.startswith("L") else desc
        pkg = body.rsplit("/", 1)[0].replace("/", ".") if "/" in body else "<default>"
        pkgs[pkg] += 1
    with open(os.path.join(out_dir, "package-stats.tsv"), "w", encoding="utf-8", newline="") as fh:
        fh.write("package\tclasses\n")
        for pkg, n in pkgs.most_common():
            fh.write(f"{pkg}\t{n}\n")

    summary = {
        "classes": len(rows),
        "unique_classes": len(dup),
        "duplicated_classes": sum(1 for v in dup.values() if v > 1),
        "packages": len(pkgs),
        "top_packages": pkgs.most_common(20),
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in summary.items() if k != "top_packages"},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
