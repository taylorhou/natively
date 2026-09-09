"""The CLI end to end with file-based wire bodies (no mail): two state dirs, two key
dirs, the verbs the README lists, in the order the first live exchange runs them."""

from __future__ import annotations

import json
import os
from pathlib import Path

from natively.cli import main


def run(env, *argv, capsys=None):
    for k, v in env.items():
        os.environ[k] = str(v)
    try:
        rc = main(list(argv))
    finally:
        for k in env:
            os.environ.pop(k, None)
    out = capsys.readouterr() if capsys else None
    return rc, out


def envs(tmp_path: Path, name: str) -> dict[str, str]:
    return {
        "NATIVELY_STATE": str(tmp_path / f"{name}-state"),
        "NATIVELY_KEYS": str(tmp_path / f"{name}-keys"),
        "NATIVELY_SCRATCH": str(tmp_path / f"{name}-scratch"),
    }


def test_cli_first_exchange_via_files(tmp_path, capsys):
    A, B = envs(tmp_path, "a"), envs(tmp_path, "b")
    for env, name in ((A, "citadel-mayor"), (B, "instinct")):
        assert run(env, "keygen", capsys=capsys)[0] == 0
        assert run(env, "keygen", capsys=capsys)[0] == 1  # refuses to overwrite
        rc, out = run(env, "card", "--agent-name", name, "--node-name", name, capsys=capsys)
        assert rc == 0 and "card sha256:" in out.out
    # each side pins the other's principal (out of band)
    a_pub = (tmp_path / "a-keys" / "principal-standin.pub").read_text().strip()
    b_pub = (tmp_path / "b-keys" / "principal-standin.pub").read_text().strip()
    assert run(A, "pin", b_pub, "--name", "instinct-principal", capsys=capsys)[0] == 0
    assert run(B, "pin", a_pub, "--name", "citadel-principal", capsys=capsys)[0] == 0
    # cards over the file wire
    fa, fb = tmp_path / "a-card.txt", tmp_path / "b-card.txt"
    assert run(A, "send", "--card", "--out", str(fa), capsys=capsys)[0] == 0
    assert run(B, "send", "--card", "--out", str(fb), capsys=capsys)[0] == 0
    assert run(B, "poll", "--file", str(fa), capsys=capsys)[0] == 0
    assert run(A, "poll", "--file", str(fb), capsys=capsys)[0] == 0
    # a file is not a revocation lookup: the freshness clock is untouched
    assert not (tmp_path / "a-state" / "revocations.check.json").exists()
    rc, out = run(A, "cards", capsys=capsys)
    assert rc == 0 and "trusted" in out.out and "instinct" in out.out
    # information A -> B, ack B -> A
    fm, fack = tmp_path / "m.txt", tmp_path / "ack.txt"
    assert (
        run(A, "send", "--to", "instinct", "--info", "hello", "--out", str(fm), capsys=capsys)[0]
        == 0
    )
    rc, out = run(A, "outbox", capsys=capsys)
    assert "exported" in out.out  # delivered by hand: never re-sent by a poll
    assert run(B, "poll", "--file", str(fm), "--out", str(fack), capsys=capsys)[0] == 0
    assert run(A, "poll", "--file", str(fack), capsys=capsys)[0] == 0
    rc, out = run(A, "outbox", capsys=capsys)
    assert "acked" in out.out
    # a grant-scoped write A -> B. `poll --file` never refreshes the revocation-lookup
    # clock (only a complete mail poll does), so B's clock is set here as a completed
    # poll would, or the write fails closed with revocation.never_checked.
    from natively.revocation import RevocationFeed
    from natively.timeutil import now_utc

    RevocationFeed(tmp_path / "b-state" / "revocations.jsonl").mark_checked(now_utc())
    rc, out = run(
        A,
        "grant",
        "--to",
        "instinct",
        "--action",
        "fs.write",
        "--file",
        "hello.txt",
        "--statement",
        "Write hello.txt once.",
        "--param",
        "content=regex:^[a-z, !\n]+$",  # a literal newline: the language has no \n escape
        capsys=capsys,
    )
    assert rc == 0, out.err
    gid = out.out.split()[1]
    assert gid.startswith("grt_")
    # fs.write grants always carry "content" in keys (an empty key list permits no params)
    rc, out = run(
        A,
        "grant",
        "--to",
        "instinct",
        "--action",
        "fs.write",
        "--file",
        "bare.txt",
        "--statement",
        "s",
        capsys=capsys,
    )
    bare = json.loads((tmp_path / "a-state" / "grants" / f"{out.out.split()[1]}.json").read_text())
    assert bare["scope"][0]["params"]["keys"] == ["content"]
    assert (
        run(
            A,
            "send",
            "--to",
            "instinct",
            "--action",
            "fs.write",
            "--file",
            "hello.txt",
            "--param",
            "content=hello, instinct\n",
            "--grant",
            gid,
            "--out",
            str(fm),
            capsys=capsys,
        )[0]
        == 0
    )
    assert run(B, "poll", "--file", str(fm), "--out", str(fack), capsys=capsys)[0] == 0
    assert (tmp_path / "b-scratch" / "hello.txt").read_text() == "hello, instinct\n"
    assert run(A, "poll", "--file", str(fack), capsys=capsys)[0] == 0
    # ledgers verify; show prints prose; the ack's outcome is applied
    for env in (A, B):
        rc, out = run(env, "ledger", "verify", capsys=capsys)
        assert rc == 0 and "ledger ok" in out.out
    # ledger repair: drop the last prose line, verify fails, repair restores it
    prose = tmp_path / "b-state" / "ledger.prose.txt"
    good = prose.read_text()
    prose.write_text("".join(good.splitlines(keepends=True)[:-1]))
    assert run(B, "ledger", "verify", capsys=capsys)[0] == 2
    rc, out = run(B, "ledger", "repair", capsys=capsys)
    assert rc == 0 and "1 trailing prose line" in out.out and prose.read_text() == good
    assert run(B, "ledger", "verify", capsys=capsys)[0] == 0
    rc, out = run(B, "ledger", "show", "--tail", "3", capsys=capsys)
    assert "fs.write under " + gid in out.out
    rc, out = run(A, "ledger", "show", "--json", "--tail", "1", capsys=capsys)
    assert json.loads(out.out.strip().splitlines()[-1])["outcome"] == "applied"
    # revoke (no send) + deny behind its flag + wire-decode + config
    assert (
        run(A, "revoke", "--grant", gid, "--statement", "done", "--no-send", capsys=capsys)[0] == 0
    )
    assert (
        run(
            B,
            "deny",
            "--action",
            "fs.write",
            "--resource",
            "host:*:scratch/secret-*",
            "--statement",
            "never",
            capsys=capsys,
        )[0]
        == 1
    )  # extension off
    assert run(B, "config", "--set", "extensions.standing_denial=true", capsys=capsys)[0] == 0
    assert (
        run(
            B,
            "deny",
            "--action",
            "fs.write",
            "--resource",
            "host:*:scratch/secret-*",
            "--statement",
            "never",
            capsys=capsys,
        )[0]
        == 0
    )
    rc, out = run(A, "wire-decode", str(fm), capsys=capsys)
    assert rc == 0 and json.loads(out.out)["kind"] == "message"
    # a manual re-ack for a message B has seen
    msg_id = json.loads(bundle_json(fm))["object"]["msg_id"]
    assert run(B, "ack", msg_id, "--out", str(fack), capsys=capsys)[0] == 0
    assert (
        run(B, "ack", "msg_00000000000000000000000000", "--out", str(fack), capsys=capsys)[0] != 0
    )
    # nothing under the scratch roots but the granted file; no key material in state
    assert sorted(p.name for p in (tmp_path / "b-scratch").iterdir()) == ["hello.txt"]
    seeds = {
        (tmp_path / f"{n}-keys" / f"{r}.key").read_text().strip()
        for n in ("a", "b")
        for r in ("host", "agent", "principal-standin")
    }
    for f in (tmp_path / "a-state").rglob("*"):
        if f.is_file():
            text = f.read_text(errors="replace")
            assert not any(s in text for s in seeds), f


def bundle_json(path: Path) -> str:
    import base64

    lines = path.read_text().splitlines()[1:]
    return base64.b64decode("".join(lines)).decode()


def test_keygen_refuses_keys_inside_state(tmp_path, capsys):
    env = envs(tmp_path, "k")
    env["NATIVELY_KEYS"] = str(tmp_path / "k-state" / "keys")
    rc, out = run(env, "keygen", capsys=capsys)
    assert rc == 1 and "inside the state directory" in out.err
    assert not (tmp_path / "k-state" / "keys").exists()


def test_wrapper_runs_from_any_directory(tmp_path):
    """bin/natively from /tmp: the package is found through PYTHONPATH, not the cwd."""
    import subprocess

    from natively.cli import TOOL_DIR

    if not (TOOL_DIR / ".venv" / "bin" / "python").exists():
        import pytest

        pytest.skip("no .venv beside the package")
    r = subprocess.run(
        [str(TOOL_DIR / "bin" / "natively"), "--help"],
        cwd="/tmp",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0 and "natively keygen" in r.stdout
