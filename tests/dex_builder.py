"""生成一个只含 class_def 的最小 dex，用于测试 dex_index.py / coverage_check.py。

只填解析器会读的段：string_ids / type_ids / class_defs / 字符串数据。
checksum 与 signature 留空（这两个工具的用途不依赖它们）。
"""
import struct

HEADER_SIZE = 0x70


def _uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build(descriptors):
    """descriptors: ['Ltest/Sample;', 'Ltest/Sample$Inner;'] → dex bytes"""
    strings = list(dict.fromkeys(list(descriptors) + ["Ljava/lang/Object;"]))
    str_index = {s: i for i, s in enumerate(strings)}

    # type_ids 指向 string，此处 type i == string i 的前 len(strings) 个不成立，
    # 所以单独维护 type 列表（每个 type 一个描述符）
    types = list(strings)
    type_index = {s: i for i, s in enumerate(types)}

    n = len(strings)
    n_types = len(types)
    n_cls = len(descriptors)

    str_ids_off = HEADER_SIZE
    type_ids_off = str_ids_off + 4 * n
    cls_defs_off = type_ids_off + 4 * n_types
    data_off = cls_defs_off + 32 * n_cls

    # 字符串数据
    data = bytearray()
    str_data_off = []
    for s in strings:
        str_data_off.append(data_off + len(data))
        raw = s.encode("utf-8")
        data += _uleb(len(s)) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"

    file_size = data_off + len(data)

    out = bytearray(HEADER_SIZE)
    out[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, HEADER_SIZE)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<II", out, 56, n, str_ids_off)
    struct.pack_into("<II", out, 64, n_types, type_ids_off)
    struct.pack_into("<II", out, 96, n_cls, cls_defs_off)
    struct.pack_into("<II", out, 104, len(data), data_off)

    for i in range(n):
        out += struct.pack("<I", str_data_off[i])
    for s in types:
        out += struct.pack("<I", str_index[s])
    for desc in descriptors:
        out += struct.pack("<IIIIIIII",
                           type_index[desc],          # class_idx
                           0x0001,                    # access_flags (PUBLIC)
                           type_index["Ljava/lang/Object;"],  # superclass
                           0, 0, 0, 0, 0)             # interfaces..static_values
    out += data
    return bytes(out)
