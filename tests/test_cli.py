"""peasrea.py CLI：子命令分发与退出码。"""
import json

import axml_builder
import dex_builder
import peasrea


def test_info_and_version(capsys):
    assert peasrea.main(["info"]) == 0
    out = capsys.readouterr().out
    assert "PeasRea" in out and "blocks" in out

    assert peasrea.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == peasrea.__version__


def test_no_args_prints_usage(capsys):
    assert peasrea.main([]) == 1
    assert "peasrea info" in capsys.readouterr().out


def test_unknown_command(capsys):
    assert peasrea.main(["nope"]) == 1
    assert "unknown command" in capsys.readouterr().out


def test_query_hits_kb(capsys):
    assert peasrea.main(["query", "长连接", "--top", "1"]) == 0
    assert "长连接" in capsys.readouterr().out


def test_index_subcommand(tmp_path, capsys):
    dexdir = tmp_path / "dex"
    dexdir.mkdir()
    (dexdir / "classes.dex").write_bytes(dex_builder.build(["Ltest/A;"]))
    out = tmp_path / "idx"
    assert peasrea.main(["index", str(dexdir), "--out", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["classes"] == 1


def test_manifest_subcommand(tmp_path, capsys):
    src = tmp_path / "in.xml"
    src.write_bytes(axml_builder.build("com.example.Target"))
    dst = tmp_path / "out.xml"

    assert peasrea.main(["manifest", str(src), str(dst), "com.example.Target"]) == 0
    assert "OK   com.example.Target" in capsys.readouterr().out
    assert dst.stat().st_size == src.stat().st_size

    # 目标不存在时返回非 0（便于脚本判错）
    assert peasrea.main(["manifest", str(src), str(dst), "com.example.Missing"]) != 0
