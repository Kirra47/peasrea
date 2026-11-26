"""生成带「类方法 + 指令」的最小 dex，用于测试 patch_dex.py 的三条补丁。

只构造解析器会用到的段：
  string_ids / type_ids / proto_ids / method_ids / class_defs / code_item / class_data
checksum 与 signature 由被测代码自己重算（正好一起验证）。

指令编码速查（小端 16 位单元）：
  const/4 vA, #lit4 = 0x12 | (A<<8) | (lit4<<12)     → v0,#4 = 0x4012 ; v0,#1 = 0x1012
  return-void       = 0x000e
  return vA         = 0x000f | (A<<8)                → return v0 = 0x000f
"""
import struct

HEADER_SIZE = 0x70
CONST4 = lambda reg, lit: 0x12 | (reg << 8) | (lit << 12)  # noqa: E731
RETURN_VOID = 0x000E


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


def _align4(n):
    return (n + 3) & ~3


def build_with_methods(classes):
    """classes: [{"desc": "Lywm;", "methods": [{"name": "a", "insns": [...], "regs": 1}]}]

    每个方法都会生成：method_ids 条目 + code_item + class_data 里的 direct_method 记录。
    """
    # ---- 收集字符串 / 类型 ----
    strings = []
    def sid(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    obj_desc = "Ljava/lang/Object;"
    sid(obj_desc)
    for c in classes:
        sid(c["desc"])
        for m in c["methods"]:
            sid(m["name"])
    sid("V")  # proto 返回类型（void），本工具不解析 proto，占位即可

    types = [obj_desc] + [c["desc"] for c in classes] + ["V"]
    def tid(desc):
        return types.index(desc)

    # ---- 段布局 ----
    n_str = len(strings)
    n_type = len(types)
    n_proto = 1
    methods = [(c, m) for c in classes for m in c["methods"]]
    method_index = {}
    gi = 0
    for ci, c in enumerate(classes):
        for mi in range(len(c["methods"])):
            method_index[(ci, mi)] = gi
            gi += 1
    n_method = len(methods)
    n_cls = len(classes)

    str_ids_off = HEADER_SIZE
    type_ids_off = str_ids_off + 4 * n_str
    proto_ids_off = type_ids_off + 4 * n_type
    method_ids_off = proto_ids_off + 12 * n_proto
    cls_defs_off = method_ids_off + 8 * n_method
    data_off = cls_defs_off + 32 * n_cls

    # ---- data 段：先 code_item，再 class_data，最后字符串 ----
    data = bytearray()
    code_offs = []
    for _c, m in methods:
        code_offs.append(data_off + len(data))
        data += struct.pack("<HHHHII", m.get("regs", 1), 0, 0, 0, 0, len(m["insns"]))
        for u in m["insns"]:
            data += struct.pack("<H", u)
    pad = _align4(data_off + len(data)) - (data_off + len(data))
    data += b"\x00" * pad

    cls_data_offs = []
    for ci, c in enumerate(classes):
        cls_data_offs.append(data_off + len(data))
        data += _uleb(0) + _uleb(0) + _uleb(len(c["methods"])) + _uleb(0)
        prev = 0
        for mi, m in enumerate(c["methods"]):
            idx = method_index[(ci, mi)]
            data += _uleb(idx - prev)
            data += _uleb(m.get("access", 0x0009))
            data += _uleb(code_offs[idx])
            prev = idx

    str_data_offs = []
    for s in strings:
        str_data_offs.append(data_off + len(data))
        raw = s.encode("utf-8")
        data += _uleb(len(s)) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"

    file_size = data_off + len(data)

    # ---- 头 ----
    out = bytearray(HEADER_SIZE)
    out[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, HEADER_SIZE)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<II", out, 56, n_str, str_ids_off)
    struct.pack_into("<II", out, 64, n_type, type_ids_off)
    struct.pack_into("<II", out, 72, n_proto, proto_ids_off)
    struct.pack_into("<II", out, 88, n_method, method_ids_off)
    struct.pack_into("<II", out, 96, n_cls, cls_defs_off)
    struct.pack_into("<II", out, 104, len(data), data_off)

    for o in str_data_offs:
        out += struct.pack("<I", o)
    for d in types:
        out += struct.pack("<I", sid(d))
    out += struct.pack("<III", sid("V"), tid("V"), 0)                 # proto: shorty, return, params
    for c, m in methods:
        out += struct.pack("<HHI", tid(c["desc"]), 0, sid(m["name"]))
    for i, c in enumerate(classes):
        out += struct.pack("<8I", tid(c["desc"]), 0x0001, tid(obj_desc),
                           0, 0, 0, cls_data_offs[i], 0)
    out += data
    return bytes(out)


def wrap_doraemon(mode=4):
    """生成含 Doraemon.<clinit> 与 setRunningMode 的 dex。"""
    return build_with_methods([{
        "desc": "Lcom/alibaba/doraemon/Doraemon;",
        "methods": [
            {"name": "<clinit>", "insns": [CONST4(0, mode), RETURN_VOID], "regs": 1, "access": 0x0009},
            {"name": "setRunningMode", "insns": [CONST4(0, mode), RETURN_VOID], "regs": 1, "access": 0x0009},
        ],
    }])


def wrap_ywm():
    """生成含 ywm.a() 的 dex。"""
    return build_with_methods([{
        "desc": "Lywm;",
        "methods": [{"name": "a", "insns": [CONST4(0, 0), RETURN_VOID], "regs": 1, "access": 0x0009}],
    }])
