"""patch_manifest.py：二进制 AXML 里 android:exported 的定点翻转。"""
import axml_builder
import pytest
from patch_manifest import Axml

TARGET = "com.example.Target"


def _exported_value(ax):
    for _off, name, attrs in ax.walk_elements():
        if name != "activity":
            continue
        values = {a[0]: a[2] for a in attrs}
        if "exported" in values:
            return values["exported"]
    return None


def test_parse_strings_utf8():
    ax = Axml(axml_builder.build(TARGET))
    assert "activity" in ax.strings
    assert TARGET in ax.strings


def test_flip_false_to_true():
    raw = axml_builder.build(TARGET, exported=False)
    ax = Axml(raw)
    assert _exported_value(ax) == 0
    assert ax.set_exported(TARGET) is True
    assert _exported_value(ax) == 0xFFFFFFFF
    assert len(ax.d) == len(raw), "补丁必须是等长改写"


def test_missing_class_returns_false():
    ax = Axml(axml_builder.build(TARGET))
    assert ax.set_exported("com.example.Other") is False


def test_second_apply_toggles_back():
    """当前实现是 toggle：已在 true 的组件再次 patch 会变回 false（记录该语义）。"""
    ax = Axml(axml_builder.build(TARGET, exported=False))
    ax.set_exported(TARGET)
    ax.set_exported(TARGET)
    assert _exported_value(ax) == 0


@pytest.mark.parametrize("exported", [False, True])
def test_roundtrip_is_stable(exported, tmp_path):
    src = tmp_path / "AndroidManifest.xml"
    src.write_bytes(axml_builder.build(TARGET, exported=exported))
    ax = Axml(src.read_bytes())
    ax.set_exported(TARGET)
    out = tmp_path / "out.xml"
    ax.save(out)
    assert out.stat().st_size == src.stat().st_size
