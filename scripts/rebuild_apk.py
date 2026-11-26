#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用补丁后的 dex 重建IM APK，并去掉旧签名（随后用 apksigner 重签）。

用法:
    python tools/patch/rebuild_apk.py target.apk tools/patch/out tools/patch/out/imclient_unlocked.apk
"""
import os
import sys
import zipfile

REPLACE = {
    "classes8.dex": "classes8.dex",
    "classes14.dex": "classes14.dex",
    "AndroidManifest.xml": "AndroidManifest.xml",
}


def main(src_apk, patch_dir, out_apk):
    zin = zipfile.ZipFile(src_apk)
    names = [i.filename for i in zin.infolist()]
    dropped = [n for n in names if n.startswith("META-INF/") and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF"))]
    with zipfile.ZipFile(out_apk, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zout:
        for info in zin.infolist():
            if info.is_dir():
                continue
            if info.filename in dropped:
                continue
            if info.filename in REPLACE:
                data = open(os.path.join(patch_dir, REPLACE[info.filename]), "rb").read()
            else:
                data = zin.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = info.compress_type if info.compress_type != zipfile.ZIP_STORED else zipfile.ZIP_STORED
            zi.external_attr = info.external_attr
            zout.writestr(zi, data)
    print("written", out_apk, os.path.getsize(out_apk), "bytes; dropped old signature entries:", len(dropped))


if __name__ == "__main__":
    main(*sys.argv[1:4])
