#!/usr/bin/env python3
"""coverage_check.py — 计算 jadx 反编译覆盖率（真实口径）

用法:
    python coverage_check.py <java_sources_dir> <dex_dir_or_files...> [--json out.json]

口径说明:
  * 只统计 dex 里真实存在的 class_def（多 dex 去重）；
  * 内部类（`A$B`）并入外部类的 .java 文件，不单独计；
  * 默认包（无 `/` 的描述符）映射到 jadx 的 `defpackage/`；
  * 同时给出 synthetic / 非 synthetic 两组，报告里应引用「非 synthetic 顶层类覆盖率」。

退出码: 0 正常；1 参数错误。
"""
import json
import os
import struct
import sys

SYNTHETIC = 0x1000  # ACC_SYNTHETIC


def uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def dex_classes(path):
    """yield (descriptor, access_flags)"""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"dex\n":
        return
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

    for i in range(cls_n):
        class_idx, access = struct.unpack_from("<II", data, cls_off + i * 32)
        yield string(type_ids[class_idx]), access


def java_path_for(descriptor):
    """Lcom/foo/A$B; -> pkg/com/foo/A (without .java)"""
    desc = descriptor
    if desc.startswith("L") and desc.endswith(";"):
        desc = desc[1:-1]
    desc = desc.split("$", 1)[0]
    if "/" in desc:
        return desc
    return "defpackage/" + desc  # jadx 把默认包放到 defpackage/


def main(argv):
    args = [a for a in argv[1:]]
    json_out = None
    if "--json" in args:
        i = args.index("--json")
        json_out = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    if len(args) < 2:
        print(__doc__)
        return 1
    src, targets = args[0], args[1:]
    dex_files = []
    for t in targets:
        if os.path.isdir(t):
            dex_files += [os.path.join(t, f) for f in sorted(os.listdir(t)) if f.endswith(".dex")]
        else:
            dex_files.append(t)
    if not dex_files:
        print("no dex found")
        return 1

    seen = {}
    for p in dex_files:
        for desc, acc in dex_classes(p):
            seen.setdefault(desc, acc)

    total = len(seen)
    hit = synth_hit = 0
    miss_synth = []
    miss_plain = []
    for desc, acc in seen.items():
        rel = java_path_for(desc)
        exists = os.path.exists(os.path.join(src, rel + ".java"))
        synthetic = bool(acc & SYNTHETIC)
        if exists:
            hit += 1
            synth_hit += 1 if synthetic else 0
        else:
            (miss_synth if synthetic else miss_plain).append(desc)

    plain_total = total - sum(1 for a in seen.values() if a & SYNTHETIC)
    report = {
        "dex_files": [os.path.basename(p) for p in dex_files],
        "classes_total": total,
        "classes_synthetic": total - plain_total,
        "classes_plain": plain_total,
        "java_files_hit": hit,
        "coverage_all_pct": round(100.0 * hit / total, 2) if total else 0.0,
        "coverage_plain_pct": round(100.0 * (hit - synth_hit) / plain_total, 2) if plain_total else 0.0,
        "missing_plain_sample": sorted(miss_plain)[:40],
        "missing_synthetic_sample": sorted(miss_synth)[:20],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print("written:", json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
