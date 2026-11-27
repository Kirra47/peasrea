#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""h5_capture.py — 一条命令搭好/拆掉 H5 抓包环境（Android，需 root 装系统 CA）

    python h5_capture.py setup    --serial R28M30LTRKT
    python h5_capture.py status   --serial R28M30LTRKT
    python h5_capture.py restore  --serial R28M30LTRKT

setup 做四件事：
  1) 计算 mitmproxy CA 的 Android 文件名（subject_hash_old）
  2) push 到 /data/misc/user/0/cacerts-added/（644 system:system + SELinux 标签）
  3) adb reverse tcp:8080 tcp:8080（免局域网/免防火墙）
  4) settings put global http_proxy 127.0.0.1:8080

restore 反向操作，务必执行——否则手机断网。
"""
import argparse
import hashlib
import os
import subprocess
import sys

CA_DEFAULT = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
CACERT_DIR = "/data/misc/user/0/cacerts-added"


def adb(args, serial, capture=True):
    cmd = [os.environ.get("ADB", "adb"), "-s", serial] + args
    p = subprocess.run(cmd, capture_output=capture, text=True)
    return (p.stdout or "") + (p.stderr or "")


def sh(cmd, serial):
    return adb(["shell", cmd], serial)


def android_ca_name(pem_path):
    """subject_hash_old：MD5(DER(subject)) 前 4 字节小端 + '.0'"""
    try:
        from cryptography import x509
    except ImportError:
        sys.exit("需要 cryptography：pip install cryptography（或手动用 openssl x509 -subject_hash_old）")
    cert = x509.load_pem_x509_certificate(open(pem_path, "rb").read())
    return hashlib.md5(cert.subject.public_bytes()).digest()[:4][::-1].hex() + ".0"


def cmd_setup(args):
    if not os.path.exists(args.ca):
        sys.exit("CA not found: " + args.ca)
    name = android_ca_name(args.ca)
    print(f"[1/4] CA name = {name}")

    out = adb(["push", args.ca, f"/data/local/tmp/{name}"], args.serial)
    print("      push:", "ok" if "1 file pushed" in out or not out.strip() else out.strip()[:120])

    su = (
        f"mkdir -p {CACERT_DIR} && cp /data/local/tmp/{name} {CACERT_DIR}/{name} && "
        f"chmod 644 {CACERT_DIR}/{name} && chown system:system {CACERT_DIR}/{name} && "
        f"chcon u:object_r:misc_user_data_file:s0 {CACERT_DIR}/{name}"
    )
    out = sh(f"su -c '{su}'", args.serial)
    print("[2/4] install CA:", out.strip() or "ok")

    adb(["reverse", f"tcp:{args.port}", f"tcp:{args.port}"], args.serial)
    print(f"[3/4] reverse tcp:{args.port} ok")

    sh(f"settings put global http_proxy 127.0.0.1:{args.port}", args.serial)
    print(f"[4/4] proxy -> 127.0.0.1:{args.port}")
    print("\n下一步：mitmdump -s mitm_addon.py --listen-port "
          f"{args.port} --set block_global=false")
    print("抓完记得：python h5_capture.py restore --serial " + args.serial)
    return 0


def cmd_restore(args):
    sh("settings put global http_proxy :0", args.serial)
    adb(["reverse", "--remove-all"], args.serial)
    name = ""
    try:
        name = android_ca_name(args.ca)
    except SystemExit:
        pass
    if name:
        sh(f"su -c 'rm -f {CACERT_DIR}/{name}'", args.serial)
    print("restored: proxy=:0, reverse removed, CA removed" + (f" ({name})" if name else ""))
    return 0


def cmd_status(args):
    print("proxy   :", sh("settings get global http_proxy", args.serial).strip())
    print("reverse :", adb(["reverse", "--list"], args.serial).strip().replace("\n", " | "))
    print("cacerts :", sh(f"su -c 'ls {CACERT_DIR} 2>/dev/null'", args.serial).strip() or "(empty)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="H5 抓包环境一键配置（Android + root）")
    ap.add_argument("action", choices=["setup", "restore", "status"])
    ap.add_argument("--serial", required=True)
    ap.add_argument("--ca", default=CA_DEFAULT)
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)
    return {"setup": cmd_setup, "restore": cmd_restore, "status": cmd_status}[args.action](args)


if __name__ == "__main__":
    sys.exit(main())
