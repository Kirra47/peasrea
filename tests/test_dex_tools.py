"""dex_index.py / coverage_check.py：用合成 dex 做端到端校验。"""
import json

import coverage_check
import dex_builder
import dex_index

DESCRIPTORS = ["Ltest/Sample;", "Ltest/Sample$Inner;"]


def _make_dex_dir(tmp_path):
    d = tmp_path / "dex"
    d.mkdir()
    (d / "classes.dex").write_bytes(dex_builder.build(DESCRIPTORS))
    return d


def test_dex_index_counts(tmp_path):
    dexdir = _make_dex_dir(tmp_path)
    out = tmp_path / "index"
    assert dex_index.main(["dex_index.py", str(dexdir), "--out", str(out)]) == 0

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["classes"] == 2
    # 内部类与外部类同包
    assert summary["packages"] == 1

    rows = (out / "classes.tsv").read_text(encoding="utf-8").splitlines()
    assert rows[0].startswith("descriptor")
    assert any("Ltest/Sample$Inner;" in r for r in rows)


def test_java_path_mapping():
    assert coverage_check.java_path_for("Ltest/A;") == "test/A"
    assert coverage_check.java_path_for("Ltest/A$B;") == "test/A"
    assert coverage_check.java_path_for("LOnly;") == "defpackage/Only"


def test_coverage_full_and_empty(tmp_path):
    dexdir = _make_dex_dir(tmp_path)
    java = tmp_path / "java"
    (java / "test").mkdir(parents=True)
    (java / "test" / "Sample.java").write_text("class Sample {}", encoding="utf-8")

    cov_json = tmp_path / "cov.json"
    assert coverage_check.main(
        ["coverage_check.py", str(java), str(dexdir), "--json", str(cov_json)]) == 0
    cov = json.loads(cov_json.read_text(encoding="utf-8"))
    assert cov["classes_total"] == 2
    # 内部类并入外部类，所以两个 class_def 都命中同一个 Sample.java
    assert cov["coverage_all_pct"] == 100.0

    empty = tmp_path / "emptyjava"
    empty.mkdir()
    cov2 = tmp_path / "cov2.json"
    coverage_check.main(["coverage_check.py", str(empty), str(dexdir), "--json", str(cov2)])
    assert json.loads(cov2.read_text(encoding="utf-8"))["coverage_all_pct"] == 0.0


def test_coverage_rejects_no_dex(tmp_path):
    empty = tmp_path / "emptydex"
    empty.mkdir()
    assert coverage_check.main(["coverage_check.py", str(tmp_path), str(empty)]) == 1
