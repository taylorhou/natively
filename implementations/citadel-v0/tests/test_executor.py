import pytest

from natively.errors import RefusedError
from natively.executor import Executor

KEY = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_info_and_fs_write(tmp_path):
    ex = Executor(KEY, tmp_path / "scratch")
    assert ex.apply("info", "host:x:y", {})["outcome"] == "applied"
    r = ex.apply("fs.write", ex.resource_for("hello.txt"), {"content": "hi\n"})
    assert r["outcome"] == "applied" and r["bytes"] == 3
    assert (tmp_path / "scratch" / "hello.txt").read_text() == "hi\n"
    assert sorted(p.name for p in (tmp_path / "scratch").iterdir()) == ["hello.txt"]  # no temp left


@pytest.mark.parametrize(
    "action,resource,params,reason",
    [
        ("fs.delete", "host:x:y", {}, "executor.unsupported"),
        ("fs.write", "host:other:scratch/a", {"content": "x"}, "executor.resource"),
        ("fs.write", f"host:{KEY}:etc/passwd", {"content": "x"}, "executor.resource"),
        ("fs.write", f"host:{KEY}:scratch/../a", {"content": "x"}, "executor.resource.name"),
        ("fs.write", f"host:{KEY}:scratch/sub/a", {"content": "x"}, "executor.resource.name"),
        ("fs.write", f"host:{KEY}:scratch/.hidden", {"content": "x"}, "executor.resource.name"),
        ("fs.write", f"host:{KEY}:scratch/a", {}, "executor.params"),
        ("fs.write", f"host:{KEY}:scratch/a", {"content": 1}, "executor.params"),
        ("fs.write", f"host:{KEY}:scratch/a", {"content": "x", "mode": "777"}, "executor.params"),
        ("fs.write", f"host:{KEY}:scratch/a", {"content": "x" * 70000}, "executor.params"),
    ],
)
def test_refusals(tmp_path, action, resource, params, reason):
    ex = Executor(KEY, tmp_path / "scratch")
    with pytest.raises(RefusedError) as e:
        ex.apply(action, resource, params)
    assert e.value.reason == reason
    assert not (tmp_path / "scratch").exists() or not list((tmp_path / "scratch").iterdir())


def test_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    import os

    def boom(src, dst, **kw):
        raise OSError("disk went away")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert list((tmp_path / "scratch").iterdir()) == []


# ---- symlink confinement (gate finding 4) ----------------------------------------------


def test_symlink_inside_scratch_is_refused_and_target_untouched(tmp_path):
    ex = Executor(KEY, tmp_path / "scratch")
    (tmp_path / "scratch").mkdir(exist_ok=True)  # the executor created it
    (tmp_path / "scratch" / "b.txt").write_text("keep")
    (tmp_path / "scratch" / "a.txt").symlink_to(tmp_path / "scratch" / "b.txt")
    with pytest.raises(RefusedError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert e.value.reason == "executor.resource.symlink"
    assert (tmp_path / "scratch" / "b.txt").read_text() == "keep"
    assert (tmp_path / "scratch" / "a.txt").is_symlink()
    assert sorted(p.name for p in (tmp_path / "scratch").iterdir()) == ["a.txt", "b.txt"]


def test_symlink_out_of_scratch_is_refused_and_target_untouched(tmp_path):
    ex = Executor(KEY, tmp_path / "scratch")
    (tmp_path / "scratch").mkdir(exist_ok=True)  # the executor created it
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (tmp_path / "scratch" / "a.txt").symlink_to(outside)
    with pytest.raises(RefusedError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert e.value.reason == "executor.resource.symlink"
    assert outside.read_text() == "secret"


def test_preplaced_temp_symlink_is_not_followed(tmp_path, monkeypatch):
    import secrets

    ex = Executor(KEY, tmp_path / "scratch")
    (tmp_path / "scratch").mkdir(exist_ok=True)  # the executor created it
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    monkeypatch.setattr(secrets, "token_hex", lambda n=8: "deadbeef")
    (tmp_path / "scratch" / ".a.txt.tmp-deadbeef").symlink_to(outside)
    with pytest.raises(RefusedError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert e.value.reason == "executor.tmp_exists"
    assert outside.read_text() == "secret"
    assert not (tmp_path / "scratch" / "a.txt").exists()
    assert (tmp_path / "scratch" / ".a.txt.tmp-deadbeef").is_symlink()  # left as found


def test_scratch_root_swapped_for_a_symlink_is_refused(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    ex = Executor(KEY, scratch)
    ex.apply("fs.write", ex.resource_for("ok.txt"), {"content": "fine"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    scratch.rename(tmp_path / "moved")
    scratch.symlink_to(elsewhere)
    with pytest.raises(RefusedError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert e.value.reason == "executor.scratch"
    assert list(elsewhere.iterdir()) == []


def test_destination_that_is_a_directory_is_refused(tmp_path):
    ex = Executor(KEY, tmp_path / "scratch")
    (tmp_path / "scratch" / "a.txt").mkdir(parents=True)
    with pytest.raises(RefusedError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert e.value.reason == "executor.resource.type"
    assert (tmp_path / "scratch" / "a.txt").is_dir()
