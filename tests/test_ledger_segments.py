"""Ledger segments (spec 5.1): a seal renames the live file to a 0400
segment beside a manifest and starts a fresh live file whose first row is a
ledger.checkpoint chaining onto the sealed head. No row is removed; start
verifies a sealed segment by one sha256, `verify --full` row by row."""
import fcntl
import hashlib
import json
import os
import tracemalloc

import pytest

from natively import cli, jcs, ledger as ledgermod, node as nodemod
from natively.ledger import CHECKPOINT, Ledger, LedgerCorrupt
from conftest import make_node

GID = "grt_" + "0" * 26


def _fill(led, n, grant_every=0):
    for i in range(n):
        if grant_every and i % grant_every == 0:
            led.append("agent:a", GID, "test.ping", {"i": i}, "ok", "ping %d" % i, scope=0)
        else:
            led.append("node:t", None, "msg.recv", {"i": i}, "rejected-bad-card", "row %d" % i)


def _sealed(tmp_path, n=30, grant_every=5):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    _fill(led, n, grant_every)
    return path, led


def _rows(path):
    return [json.loads(ln) for ln in open(path) if ln.strip()]


def _flip(path, at):
    """Change one hex digit inside a sealed file, keeping its size."""
    os.chmod(path, 0o600)
    with open(path, "r+b") as f:
        f.seek(at)
        c = f.read(1)
        f.seek(at)
        f.write(b"0" if c != b"0" else b"1")


def test_seal_dry_run_changes_nothing_then_apply_seals(tmp_path):
    path, led = _sealed(tmp_path)
    before, head = _rows(path), led.head()
    listing = sorted(os.listdir(tmp_path))
    dry = led.seal(actor="node:t")
    assert dry["applied"] is False and sorted(os.listdir(tmp_path)) == listing and _rows(path) == before
    res = led.seal(apply=True, actor="node:t")
    assert res["applied"] and res["verify"]["ok"]
    seg = str(tmp_path / "ledger.000001.jsonl")
    assert _rows(seg) == before  # the sealed file is the live file, renamed: every row, byte for byte
    for f in ("ledger.000001.jsonl", "ledger.000001.jsonl.prose", "ledger.000001.manifest.json", "ledger.000001.grants.jsonl"):
        assert os.stat(tmp_path / f).st_mode & 0o777 == 0o400
    assert os.stat(path).st_mode & 0o777 == 0o600
    man = json.load(open(tmp_path / "ledger.000001.manifest.json"))
    assert man["rows"] == 30 and man["head"] == head and man["first_prev_hash"] == "GENESIS"
    assert man["sha256"] == hashlib.sha256(open(seg, "rb").read()).hexdigest()
    assert man["first_ts"] == before[0]["ts"] and man["last_ts"] == before[-1]["ts"]
    prose = open(str(tmp_path / "ledger.000001.jsonl.prose"), "rb").read()
    assert man["prose"]["sha256"] == hashlib.sha256(prose).hexdigest()
    assert man["grants"]["rows"] == 6
    # the live file holds exactly the checkpoint row, chained onto the sealed head
    live = _rows(path)
    assert len(live) == 1
    cp = live[0]
    assert cp["action"] == CHECKPOINT and cp["outcome"] == "sealed" and cp["actor"] == "node:t"
    assert cp["prev_hash"] == head == cp["params"]["head"]
    assert cp["params"] == {"segment": "ledger.000001.jsonl", "rows": 30, "sha256": man["sha256"], "head": head,
                            "grant_rows": 6, "grants_sha256": man["grants"]["sha256"]}
    assert cp["params_hash"] == jcs.sha256(jcs.canonicalize(cp["params"]))
    assert open(path + ".prose").read().startswith(cp["prev_hash_chain"][:12] + " [")
    fresh = Ledger(path)
    assert fresh.verify_chain() and fresh.head() == cp["prev_hash_chain"]
    assert fresh.verify(full=True)["ok"]


def test_live_rows_chain_on_and_nothing_is_removed(tmp_path):
    path, led = _sealed(tmp_path)
    before = _rows(path)
    led.seal(apply=True, actor="node:t")
    led = Ledger(path)
    _fill(led, 5)
    rows = list(led.entries(all_segments=True))
    assert rows[:30] == before and rows[30]["action"] == CHECKPOINT and len(rows) == 36
    assert [e["prev_hash"] for e in rows[1:]] == [e["prev_hash_chain"] for e in rows[:-1]]
    assert len(list(led.entries())) == 6  # live rows only by default
    assert led.verify_chain() and led.verify(full=True)["ok"]


def test_grant_budget_rows_survive_a_seal(tmp_path):
    path, led = _sealed(tmp_path, n=30, grant_every=5)
    assert len(led.rows_for_grant(GID)) == 6
    led.seal(apply=True, actor="node:t")
    assert len(led.rows_for_grant(GID)) == 6  # a seal never frees a use
    reopened = Ledger(path)
    reopened.append("agent:a", GID, "test.ping", {"i": 99}, "ok", "after the seal", scope=0)
    assert len(reopened.rows_for_grant(GID)) == 7 and len(Ledger(path).rows_for_grant(GID)) == 7


def test_two_seals_in_a_row_walk_back(tmp_path):
    path, led = _sealed(tmp_path, n=10)
    first = _rows(path)
    led.seal(apply=True, actor="node:t")
    _fill(led, 4)
    second = _rows(path)
    led.seal(apply=True, actor="node:t")
    led.seal(apply=True, actor="node:t")  # nothing appended between: a one-row segment is still a segment
    led = Ledger(path)
    _fill(led, 2)
    assert _rows(str(tmp_path / "ledger.000002.jsonl")) == second
    assert _rows(path)[0]["params"]["segment"] == "ledger.000003.jsonl"
    rows = list(led.entries(all_segments=True))
    assert rows[:10] == first and rows[10:15] == second and len(rows) == 10 + 5 + 1 + 1 + 2
    assert [e["prev_hash"] for e in rows[1:]] == [e["prev_hash_chain"] for e in rows[:-1]]
    rep = led.verify(full=True)
    assert rep["ok"] and [s["segment"] for s in rep["segments"]] == [
        "ledger.000001.jsonl", "ledger.000002.jsonl", "ledger.000003.jsonl"] and rep["rows"] == len(rows)
    assert led.verify()["ok"] and led.verify()["rows"] == len(rows)


@pytest.mark.parametrize("victim", ["segment", "grants", "manifest"])
def test_tampered_sealed_files_fail_fast_and_full(tmp_path, victim):
    path, led = _sealed(tmp_path)
    led.seal(apply=True, actor="node:t")
    _fill(led, 2)
    name = {"segment": "ledger.000001.jsonl", "grants": "ledger.000001.grants.jsonl",
            "manifest": "ledger.000001.manifest.json"}[victim]
    target = str(tmp_path / name)
    if victim == "manifest":
        _flip(target, open(target, "rb").read().index(b'"sha256": "') + 12)
    else:
        _flip(target, open(target, "rb").read().index(b'"params_hash":"') + 20)
    fresh = Ledger(path)
    assert not fresh.verify_chain() and not fresh.verify_at_start()
    assert not fresh.verify(full=True)["ok"]


def test_tampered_segment_refuses_node_start(tmp_path, hub, principal):
    n = make_node(tmp_path, "n1", hub.url, principal, start=False)
    _fill(n.ledger, 5)
    n.ledger.seal(apply=True, actor="node:n1")
    seg = os.path.join(n.home, "ledger.000001.jsonl")
    ok = nodemod.Node(n.home)
    ok.start()  # a sealed ledger starts: one sha256 for the segment, the live rows row by row
    assert [e["action"] for e in ok.ledger.entries()][-1] == "node.start"
    ok.stop()
    _flip(seg, 100)
    bad = nodemod.Node(n.home)
    with pytest.raises(LedgerCorrupt):
        bad.start()


def test_seal_refused_while_node_lock_held(tmp_path, hub, principal):
    n = make_node(tmp_path, "n1", hub.url, principal)  # started: holds node.lock
    with pytest.raises(SystemExit) as ex:
        cli.main(["--home", n.home, "ledger", "seal", "--apply"])
    assert "node.lock" in str(ex.value)
    assert not os.path.exists(os.path.join(n.home, "ledger.000001.jsonl"))
    n.stop()
    cli.main(["--home", n.home, "ledger", "seal", "--apply"])
    assert os.path.exists(os.path.join(n.home, "ledger.000001.jsonl"))
    with pytest.raises(SystemExit) as ex:
        cli.main(["--home", n.home, "ledger", "verify", "--full"])
    assert ex.value.code == 0


def test_seal_holds_node_lock_so_no_daemon_starts(tmp_path, monkeypatch):
    path, led = _sealed(tmp_path, n=3)
    seen = {}
    real = Ledger.seal

    def probe(self, **kw):
        f = open(str(tmp_path / "node.lock"), "a")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen["free"] = True
        except OSError:
            seen["free"] = False
        f.close()
        return real(self, **kw)
    monkeypatch.setattr(Ledger, "seal", probe)
    json.dump({"name": "t"}, open(str(tmp_path / "config.json"), "w"))
    cli.main(["--home", str(tmp_path), "ledger", "seal"])
    assert seen == {"free": False}


def test_checkpoint_action_is_reserved(tmp_path):
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    with pytest.raises(ValueError):
        led.append("node:t", None, CHECKPOINT, {}, "sealed", "forged")


def test_forged_checkpoint_mid_segment_breaks_the_chain(tmp_path):
    path, led = _sealed(tmp_path, n=3)
    rows = _rows(path)
    e = {"ts": rows[-1]["ts"], "actor": "node:t", "grant_id": None, "action": CHECKPOINT,
         "params_hash": "0" * 64, "outcome": "sealed", "prev_hash": rows[-1]["prev_hash_chain"]}
    e["prev_hash_chain"] = ledgermod._row_hash(e)
    with open(path, "a") as f:
        f.write(json.dumps(e, separators=(",", ":")) + "\n")
    assert not Ledger(path).verify_chain()


def test_torn_tail_recovered_on_live_segment_after_seal(tmp_path):
    path, led = _sealed(tmp_path, n=4)
    led.seal(apply=True, actor="node:t")
    _fill(led, 2)
    with open(path, "ab") as f:
        f.write(b'{"ts":"2026-10-21T00:00:00Z","actor":"node:t","gra')
    fresh = Ledger(path)  # recovers on open
    assert os.path.exists(path + ".torn") and fresh.verify_chain() and len(list(fresh.entries())) == 3
    fresh.append("node:t", None, "node.start", {}, "ok", "")
    assert Ledger(path).verify(full=True)["ok"]


def test_repair_leaves_a_sealed_chain_alone(tmp_path):
    path, led = _sealed(tmp_path, n=4)
    led.seal(apply=True, actor="node:t")
    _fill(led, 2)
    assert led.repair_forks(apply=True)["status"] == "chain already valid"


def test_interrupted_seal_before_commit_is_redone(tmp_path, monkeypatch):
    path, led = _sealed(tmp_path, n=6)
    before = _rows(path)
    real = os.replace
    calls = {"n": 0}

    def crash_at_commit(src, dst):
        calls["n"] += 1
        if dst == path:
            raise OSError("power cut")
        return real(src, dst)
    monkeypatch.setattr(os, "replace", crash_at_commit)
    with pytest.raises(OSError):
        led.seal(apply=True, actor="node:t")
    monkeypatch.setattr(os, "replace", real)
    assert _rows(path) == before and Ledger(path).verify_chain()  # nothing committed: the live chain is as it was
    assert os.path.samefile(path, str(tmp_path / "ledger.000001.jsonl"))
    res = Ledger(path).seal(apply=True, actor="node:t")
    assert res["status"] == "sealed" and _rows(str(tmp_path / "ledger.000001.jsonl")) == before
    assert Ledger(path).verify(full=True)["ok"]


def test_interrupted_seal_after_commit_is_finished(tmp_path, monkeypatch):
    path, led = _sealed(tmp_path, n=6)
    real = os.replace

    def crash_at_prose(src, dst):
        if dst == path + ".prose":
            raise OSError("power cut")
        return real(src, dst)
    monkeypatch.setattr(os, "replace", crash_at_prose)
    with pytest.raises(OSError):
        led.seal(apply=True, actor="node:t")
    monkeypatch.setattr(os, "replace", real)
    assert Ledger(path).verify_chain()  # committed: the live file is the checkpoint
    assert Ledger(path).seal(actor="node:t")["status"].startswith("interrupted seal")
    res = Ledger(path).seal(apply=True, actor="node:t")
    assert res["status"] == "finished interrupted seal" and res["verify"]["ok"]
    assert not os.path.samefile(path + ".prose", str(tmp_path / "ledger.000001.jsonl.prose"))
    assert Ledger(path).verify(full=True)["ok"]


def test_stray_segment_name_is_refused(tmp_path):
    path, led = _sealed(tmp_path, n=3)
    open(str(tmp_path / "ledger.000001.jsonl"), "w").write("not ours\n")
    with pytest.raises(LedgerCorrupt):
        led.seal(apply=True, actor="node:t")
    assert len(_rows(path)) == 3


def _synthetic(path, n):
    """A valid chain of n rows written directly (no per-row fsync)."""
    prev, out = "GENESIS", []
    for i in range(n):
        e = {"ts": "2026-10-21T00:00:00Z", "actor": "node:t", "grant_id": None, "action": "msg.recv",
             "params_hash": hashlib.sha256(b"%d" % i).hexdigest(), "outcome": "ok", "prev_hash": prev}
        body = ('{"action":"msg.recv","actor":"node:t","grant_id":null,"outcome":"ok","params_hash":"%s",'
                '"prev_hash":"%s","ts":"2026-10-21T00:00:00Z"}' % (e["params_hash"], prev))
        e["prev_hash_chain"] = prev = hashlib.sha256(body.encode()).hexdigest()
        out.append(json.dumps(e, separators=(",", ":")) + "\n")
    with open(path, "w") as f:
        f.write("".join(out))
    return prev


def test_tail_reads_backwards_without_loading_the_ledger(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    head = _synthetic(path, 120000)  # ~45 MB
    led = Ledger(path)
    assert led.verify_chain()
    tracemalloc.start()
    got = led.tail(5)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert [e["prev_hash_chain"] for e in got][-1] == head and len(got) == 5
    assert [e["prev_hash"] for e in got[1:]] == [e["prev_hash_chain"] for e in got[:-1]]
    assert peak < 2 << 20, peak  # bounded chunks, not the 45 MB file
    led.seal(apply=True, actor="node:t")
    led.append("node:t", None, "node.start", {}, "ok", "")
    across = Ledger(path).tail(4)  # runs out of live rows and continues into the sealed segment
    assert [e["action"] for e in across] == ["msg.recv", "msg.recv", CHECKPOINT, "node.start"]
    assert across[1]["prev_hash_chain"] == head


def test_parallel_full_verify_matches_sequential(tmp_path, monkeypatch):
    path = str(tmp_path / "ledger.jsonl")
    _synthetic(path, 3000)
    led = Ledger(path)
    seq = led.seal(actor="node:t")["manifest"]
    monkeypatch.setattr(ledgermod, "PARALLEL_MIN", 0)
    par = led.seal(actor="node:t", jobs=3)["manifest"]
    assert {k: v for k, v in par.items() if k != "sealed_at"} == {k: v for k, v in seq.items() if k != "sealed_at"}
    led.seal(apply=True, actor="node:t", jobs=3)
    assert led.verify(full=True, jobs=3)["ok"]
    _flip(str(tmp_path / "ledger.000001.jsonl"), 200000)
    rep = Ledger(path).verify(full=True, jobs=3)
    assert not rep["ok"] and "segment 1" in rep["error"]


def test_node_seals_between_restarts_and_keeps_messaging(tmp_path, hub, principal):
    """The scratch-node seal + restart: traffic both ways, stop, seal through
    the CLI, start again on the sealed ledger, traffic both ways again."""
    from conftest import agent_key, inbox, pump
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    alpha, beta = agent_key(n1, "alpha"), agent_key(n2, "beta")
    n1.queue_send("alpha", beta, {"kind": "text", "text": "before"})
    n2.queue_send("beta", alpha, {"kind": "text", "text": "before"})
    pump([n1, n2], rounds=6)
    before = len(list(n2.ledger.entries()))
    n2.stop()
    cli.main(["--home", n2.home, "ledger", "seal", "--apply"])
    n2 = nodemod.Node(n2.home)
    n2.start()
    live = list(n2.ledger.entries())
    assert live[0]["action"] == CHECKPOINT and live[0]["params"]["rows"] == before
    n1.queue_send("alpha", beta, {"kind": "text", "text": "after"})
    n2.queue_send("beta", alpha, {"kind": "text", "text": "after"})
    pump([n1, n2], rounds=6)
    assert [r["body"]["text"] for r in inbox(n2, "beta")].count("after") == 1
    assert [r["body"]["text"] for r in inbox(n1, "alpha")].count("after") == 1
    assert not n1.state["unacked"] and not n2.state["unacked"]  # acks crossed the seal both ways
    assert n2.ledger.verify(full=True)["ok"] and n1.ledger.verify_chain()
    assert any(e["action"] == "msg.ack" and e["outcome"] == "ok" for e in n2.ledger.entries())
