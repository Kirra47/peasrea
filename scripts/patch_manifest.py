#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""二进制 AndroidManifest.xml (AXML) 定点补丁：把指定 <activity> 的 android:exported 改成 true。

不重排、不重建，只改 attributes 里的 typedValue.data（0 -> 0xFFFFFFFF），
所以文件长度不变、其余资源引用全部保持原样。

用法:
    python tools/patch/patch_manifest.py unpacked/root/AndroidManifest.xml out/AndroidManifest.xml \
        com.alibaba.android.user.devset.DevSettingActivity \
        com.alibaba.android.user.settings.activity.DeveloperOptionsActivity
"""
import struct
import sys

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
TYPE_INT_BOOLEAN = 0x12
ATTR_EXPORTED = "exported"
ATTR_NAME = "name"
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class Axml:
    def __init__(self, data):
        self.d = bytearray(data)
        self.strings = []
        self._parse_strings()
        self.string_offsets = []   # (chunk_off, count, offsets_off)

    def _parse_strings(self):
        d = self.d
        off = 8  # skip file header (type,headerSize,size)
        while off < len(d):
            ctype, hsize, size = struct.unpack_from("<HHI", d, off)
            if size == 0:
                break
            if ctype == RES_STRING_POOL_TYPE:
                count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", d, off + 8)
                offsets = struct.unpack_from("<%dI" % count, d, off + hsize)
                base = off + strings_start
                self.string_offsets = (off, hsize, count, offsets, base, flags)
                for o in offsets:
                    p = base + o
                    if flags & 0x100:  # UTF-8
                        # u8 length (1 or 2 bytes), then u8 byte-length
                        n = d[p]
                        p2 = p + 1
                        if n & 0x80:
                            n = ((n & 0x7F) << 8) | d[p + 1]
                            p2 = p + 2
                        bn = d[p2]
                        p3 = p2 + 1
                        if bn & 0x80:
                            bn = ((bn & 0x7F) << 8) | d[p2 + 1]
                            p3 = p2 + 2
                        self.strings.append(d[p3:p3 + bn].decode("utf-8", "replace"))
                    else:              # UTF-16
                        n = struct.unpack_from("<H", d, p)[0]
                        p2 = p + 2
                        if n & 0x8000:
                            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p + 2)[0]
                            p2 = p + 4
                        self.strings.append(d[p2:p2 + n * 2].decode("utf-16-le", "replace"))
                return
            off += size

    def walk_elements(self):
        """yield (chunk_offset, element_name, [(attr_name, type, data, data_offset)])"""
        d = self.d
        off = 8
        while off < len(d):
            ctype, hsize, size = struct.unpack_from("<HHI", d, off)
            if size <= 0:
                break
            if ctype == RES_XML_START_ELEMENT_TYPE:
                name_idx = struct.unpack_from("<I", d, off + 20)[0]
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", d, off + 24)
                attrs = []
                aoff = off + hsize + (attr_start - 20 if attr_start >= 20 else 0)
                for i in range(attr_count):
                    p = aoff + i * attr_size
                    ns_idx, aname_idx, raw_idx = struct.unpack_from("<III", d, p)
                    vsize, res0, dtype, data = struct.unpack_from("<HBBI", d, p + 12)
                    aname = self.strings[aname_idx] if aname_idx < len(self.strings) else ""
                    raw = self.strings[raw_idx] if raw_idx != 0xFFFFFFFF and raw_idx < len(self.strings) else None
                    attrs.append((aname, dtype, data, p + 16, raw))
                yield off, self.strings[name_idx], attrs
            off += size

    def set_exported(self, activity_class):
        hit = False
        for off, name, attrs in self.walk_elements():
            if name != "activity":
                continue
            cls = None
            for a in attrs:
                if a[0] == ATTR_NAME and a[4]:
                    cls = a[4]
            if cls != activity_class:
                continue
            for a in attrs:
                if a[0] == ATTR_EXPORTED:
                    aname, dtype, data, data_off, raw = a
                    struct.pack_into("<I", self.d, data_off, 0xFFFFFFFF if data == 0 else 0)
                    hit = True
        return hit

    def save(self, path):
        open(path, "wb").write(bytes(self.d))


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    targets = sys.argv[3:]
    ax = Axml(open(src, "rb").read())
    for t in targets:
        ok = ax.set_exported(t)
        print(("OK   " if ok else "MISS ") + t)
    ax.save(dst)
