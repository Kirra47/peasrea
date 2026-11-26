"""patch_dex.py：三条字节补丁在合成 dex 上的行为（含 checksum/signature 重算）。"""
import hashlib
import struct
import zlib

import dex_builder_methods as dbm
import patch_dex
import pytest


def _dump(tmp_path, name, blob):
    p = tmp_path / name
    p.write_bytes(blob)
    return p


def _units(dex, code_off):
    base, size, _regs = dex.insns(code_off)
    return [struct.unpack_from("<H", dex.d, base + i * 2)[0] for i in range(size)]


def test_patch_ywm_a_returns_true(tmp_path):
    src = _dump(tmp_path, "classes8.dex", dbm.wrap_ywm())
    dst = tmp_path / "out8.dex"

    size, _regs = patch_dex.patch_ywm_a(str(src), str(dst))
    dex = patch_dex.Dex(str(dst))
    direct, _ = dex.methods_of("Lywm;")
    units = _units(dex, dict(direct)["a"])

    assert units[0] == 0x1012, "const/4 v0, #1"
    assert units[1] == 0x000F, "return v0"
    assert all(u == 0 for u in units[2:]), "剩余单元必须是 nop"
    assert len(units) == size


def test_checksum_and_signature_recomputed(tmp_path):
    src = _dump(tmp_path, "classes8.dex", dbm.wrap_ywm())
    dst = tmp_path / "out8.dex"
    patch_dex.patch_ywm_a(str(src), str(dst))

    raw = dst.read_bytes()
    assert struct.unpack_from("<I", raw, 8)[0] == zlib.adler32(raw[12:]) & 0xFFFFFFFF
    assert raw[12:32] == hashlib.sha1(raw[32:]).digest()


def test_patch_doraemon_mode_one(tmp_path):
    src = _dump(tmp_path, "classes14.dex", dbm.wrap_doraemon(4))
    dst = tmp_path / "out14.dex"

    offset = patch_dex.patch_doraemon_mode(str(src), str(dst), 1)
    dex = patch_dex.Dex(str(dst))
    direct, _ = dex.methods_of("Lcom/alibaba/doraemon/Doraemon;")
    units = _units(dex, dict(direct)["<clinit>"])

    assert units[offset] == 0x1012, "const/4 v0, #1（原为 #4）"
    assert units[offset + 1] == dbm.RETURN_VOID


def test_patch_set_runmode_noop(tmp_path):
    src = _dump(tmp_path, "classes14.dex", dbm.wrap_doraemon(1))
    dst = tmp_path / "out14.dex"

    patch_dex.patch_set_runmode_noop(str(src), str(dst))
    dex = patch_dex.Dex(str(dst))
    direct, _ = dex.methods_of("Lcom/alibaba/doraemon/Doraemon;")
    units = _units(dex, dict(direct)["setRunningMode"])

    assert units[0] == dbm.RETURN_VOID
    assert all(u == 0 for u in units[1:])


def test_doraemon_requires_exactly_one_const4(tmp_path):
    """<clinit> 里有两个 const/4 #4 时必须拒绝（避免改错位置）。"""
    blob = dbm.build_with_methods([{
        "desc": "Lcom/alibaba/doraemon/Doraemon;",
        "methods": [{
            "name": "<clinit>",
            "insns": [dbm.CONST4(0, 4), dbm.CONST4(1, 4), dbm.RETURN_VOID],
            "regs": 2,
        }],
    }])
    src = _dump(tmp_path, "dup.dex", blob)
    with pytest.raises(SystemExit):
        patch_dex.patch_doraemon_mode(str(src), str(tmp_path / "o.dex"), 1)
