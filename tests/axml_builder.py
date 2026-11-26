"""生成一个最小的二进制 AXML（AndroidManifest.xml）用于测试 patch_manifest.py。

结构：文件头 + 字符串池(UTF-8) + 一个 <activity> 开始元素。
解析器只看：字符串池、START_ELEMENT 的 name/attributes。
"""
import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102


def _utf8_pool(strings):
    """返回 string pool chunk 字节。"""
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        raw = s.encode("utf-8")
        data += bytes([len(s), len(raw)]) + raw + b"\x00"  # utf16len, bytelen, bytes, NUL
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(data)
    out = struct.pack("<HHI", RES_STRING_POOL_TYPE, header_size, size)
    out += struct.pack("<IIIII", len(strings), 0, 0x100, strings_start, 0)  # flags=UTF8
    out += b"".join(struct.pack("<I", o) for o in offsets)
    out += data
    return out


def _start_element(name_idx, attrs):
    """attrs: [(ns_idx, name_idx, raw_idx, data_type, data)]"""
    header_size = 36
    body = struct.pack("<II", 0xFFFFFFFF, name_idx)                # ns, name
    body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)    # attrStart/Size/Count/id/class/style
    for ns, an, raw, dtype, data in attrs:
        body += struct.pack("<III", ns, an, raw)
        body += struct.pack("<HBBI", 8, 0, dtype, data)
    size = 16 + len(body)                                          # 16 = type/hsize/size/line/comment
    # XML 节点通用头是 16 字节：type(2) headerSize(2) size(4) lineNumber(4) comment(4)
    out = struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, header_size, size,
                      0xFFFFFFFF, 0xFFFFFFFF)
    return out + body


def build(activity_class, exported=False, extra_strings=()):
    """生成含一个 <activity android:name android:exported> 的 AXML。"""
    strings = ["activity", "name", "exported", activity_class, "android", *extra_strings]
    idx = {s: i for i, s in enumerate(strings)}
    pool = _utf8_pool(strings)
    elem = _start_element(
        idx["activity"],
        [
            (idx["android"], idx["name"], idx[activity_class], 0x03, idx[activity_class]),
            (idx["android"], idx["exported"], 0xFFFFFFFF, 0x12, 0xFFFFFFFF if exported else 0),
        ],
    )
    total = 8 + len(pool) + len(elem)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, total)
    return header + pool + elem
