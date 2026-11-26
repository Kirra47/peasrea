#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IM 8.2.2.1（<PKG>）解锁补丁：dex 级字节补丁

补丁 1 — defpackage/ywm.a()Z （classes8.dex）
    原逻辑：return InstrumentAPI.support($surgeonFlag, "1669440712") ? ... : f69400a;
    补丁后：const/4 v0, #1 ; return v0   （其余指令填 nop；方法内无分支目标指向被替换区）
    效果：设置页「开发者选项」入口可见、DeveloperOptionsActivity 门控放开。

补丁 2 — com.alibaba.doraemon.Doraemon.<clinit> （classes14.dex）
    原逻辑：private static int sMode = 4;
    补丁后：sMode = 1
    效果：Doraemon.getRunningMode()==1 → DevSettingActivity.onCreate 门控通过，
          进而解锁环境切换(线上/预发/日常)、endpoint 覆盖、WebView 调试开关等全部 DevSetting 能力。

两个补丁都只改立即数/指令，不改变方法长度、不改变寄存器数，故不需要重排 dex。
补丁后重算 dex checksum(adler32) 与 signature(SHA-1)。
"""
import hashlib
import struct
import sys
import zlib


def uleb(d, o):
    r = 0
    s = 0
    while True:
        x = d[o]
        o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


class Dex:
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path, "rb").read())
        d = self.d
        self.string_ids_size, self.string_ids_off = struct.unpack_from("<II", d, 56)
        self.type_ids_size, self.type_ids_off = struct.unpack_from("<II", d, 64)
        self.method_ids_size, self.method_ids_off = struct.unpack_from("<II", d, 88)
        self.class_defs_size, self.class_defs_off = struct.unpack_from("<II", d, 96)
        self.str_offs = struct.unpack_from("<%dI" % self.string_ids_size, d, self.string_ids_off)
        self.type_ids = struct.unpack_from("<%dI" % self.type_ids_size, d, self.type_ids_off)

    def s(self, i):
        o = self.str_offs[i]
        n, o = uleb(self.d, o)
        return self.d[o:o + n].decode("utf8", "replace")

    def type_str(self, i):
        return self.s(self.type_ids[i])

    def methods_of(self, class_desc):
        """返回 (direct[(name, code_off)], virtual[...])"""
        d = self.d
        for i in range(self.class_defs_size):
            e = struct.unpack_from("<8I", d, self.class_defs_off + i * 32)
            if self.type_str(e[0]) != class_desc:
                continue
            o = e[6]
            if o == 0:
                return [], []
            sf, o = uleb(d, o)
            inf, o = uleb(d, o)
            dm, o = uleb(d, o)
            vm, o = uleb(d, o)
            for _ in range(sf + inf):
                _, o = uleb(d, o)
                _, o = uleb(d, o)
            out = [[], []]
            midx = 0
            for idx in range(dm + vm):
                diff, o = uleb(d, o)
                _acc, o = uleb(d, o)
                midx += diff
                _cls, _proto, nm = struct.unpack_from("<HHI", d, self.method_ids_off + midx * 8)
                coff, o = uleb(d, o)
                out[0 if idx < dm else 1].append((self.s(nm), coff))
            return out[0], out[1]
        raise KeyError(class_desc)

    def insns(self, code_off):
        regs, ins, outs, tries, dbg, size = struct.unpack_from("<HHHHII", self.d, code_off)
        return code_off + 16, size, regs

    def put_unit(self, base, u, value):
        struct.pack_into("<H", self.d, base + u * 2, value)

    def fix(self):
        d = self.d
        d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
        struct.pack_into("<I", d, 8, zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)

    def save(self, path):
        self.fix()
        open(path, "wb").write(bytes(self.d))


def patch_ywm_a(src, dst):
    dex = Dex(src)
    direct, _ = dex.methods_of("Lywm;")
    code = dict(direct)["a"]
    base, size, regs = dex.insns(code)
    if size < 2:
        raise SystemExit("unexpected ywm.a() size")
    dex.put_unit(base, 0, 0x1012)   # const/4 v0, #1
    dex.put_unit(base, 1, 0x000F)   # return v0
    for u in range(2, size):
        dex.put_unit(base, u, 0x0000)  # nop
    dex.save(dst)
    return size, regs


def patch_doraemon_mode(src, dst, mode=1):
    dex = Dex(src)
    direct, _ = dex.methods_of("Lcom/alibaba/doraemon/Doraemon;")
    code = dict(direct)["<clinit>"]
    base, size, regs = dex.insns(code)
    hits = []
    for u in range(size):
        w = struct.unpack_from("<H", dex.d, base + u * 2)[0]
        if (w & 0xFF) == 0x12 and ((w >> 12) & 0xF) == 4:  # const/4 vX, #4
            hits.append(u)
    if len(hits) != 1:
        raise SystemExit("expected exactly one const/4 #4 in <clinit>, got %r" % hits)
    u = hits[0]
    w = struct.unpack_from("<H", dex.d, base + u * 2)[0]
    dex.put_unit(base, u, (w & 0x0FFF) | (mode << 12))
    dex.save(dst)
    return u


def patch_set_runmode_noop(src, dst):
    """setRunningMode(I)V -> return-void; 防止包内 `if(mode==1) setRunningMode(2)` 把 1 降级成 2"""
    dex = Dex(src)
    direct, _ = dex.methods_of("Lcom/alibaba/doraemon/Doraemon;")
    code = dict(direct)["setRunningMode"]
    base, size, regs = dex.insns(code)
    dex.put_unit(base, 0, 0x000E)          # return-void
    for u in range(1, size):
        dex.put_unit(base, u, 0x0000)      # nop
    dex.save(dst)
    return size


if __name__ == "__main__":
    import os
    out = sys.argv[1] if len(sys.argv) > 1 else "out"
    os.makedirs(out, exist_ok=True)
    print("patch ywm.a()      ->", out + "/classes8.dex", patch_ywm_a("unpacked/dex/classes8.dex", out + "/classes8.dex"))
    print("patch Doraemon mode->", out + "/classes14.dex", patch_doraemon_mode("unpacked/dex/classes14.dex", out + "/classes14.dex", 1))
    print("patch setRunningMode no-op ->", out + "/classes14.dex", patch_set_runmode_noop(out + "/classes14.dex", out + "/classes14.dex"))
