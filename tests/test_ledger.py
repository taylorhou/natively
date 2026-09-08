"""The ledger's per-grant index and its append discipline (review
2026-09-07, point 3, and the gate round on it): appends from several
writers on one home never fork the chain and never leave the index
behind the file; a row that cannot be indexed is refused before it is
written; a malformed row already on disk is chained but not indexed."""
import json
import os
import threading

import pytest

from natively.ledger import Ledger


def test_two_writers_appending_at_once_never_fork_the_chain(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    a, b = Ledger(path), Ledger(path)
    errors = []

    def writer(ledger, name):
        try:
            for i in range(40):
                ledger.append("agent:%s" % name, "grt_" + "0" * 26, "test.ping", {"i": i}, "ok", "pong")
        except Exception as e:  # pragma: no cover - the assertion below reports it
            errors.append(e)
    ta, tb = threading.Thread(target=writer, args=(a, "a")), threading.Thread(target=writer, args=(b, "b"))
    ta.start(), tb.start()
    ta.join(), tb.join()
    assert errors == []
    fresh = Ledger(path)
    assert fresh.verify_chain()
    assert len(list(fresh.entries())) == 80
    # every writer's index sees every row, its own and the other's
    for ledger in (a, b, fresh):
        assert len(ledger.rows_for_grant("grt_" + "0" * 26)) == 80
        assert ledger.head() == fresh.head()


def test_a_grant_id_that_is_not_a_string_is_refused_before_anything_is_written(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    ledger = Ledger(path)
    ledger.append("agent:a", None, "msg.send", {}, "ok", "sent")
    before = os.path.getsize(path), os.path.getsize(ledger.mirror_path)
    for bad in ({}, [], 1, True):
        with pytest.raises(TypeError):
            ledger.append("agent:a", bad, "msg.send", {}, "ok", "sent")
    with pytest.raises(TypeError):
        ledger.append("agent:a", "grt_x", "test.ping", {}, "ok", "pong", scope="0")
    assert (os.path.getsize(path), os.path.getsize(ledger.mirror_path)) == before
    assert ledger.verify_chain() and len(list(ledger.entries())) == 1


def test_a_malformed_row_already_on_disk_is_chained_but_not_indexed(tmp_path):
    """A row written by older code with a list where the grant id goes
    must not disable the ledger: the chain still reads and verifies, the
    row is simply not under any grant, and appends continue."""
    path = str(tmp_path / "ledger.jsonl")
    ledger = Ledger(path)
    first = ledger.append("agent:a", "grt_" + "0" * 26, "test.ping", {}, "ok", "pong")
    legacy = {"ts": first["ts"], "actor": "agent:a", "grant_id": [], "action": "msg.send", "params_hash": first["params_hash"],
              "outcome": "ok", "prev_hash": first["prev_hash_chain"]}
    from natively import jcs
    legacy["prev_hash_chain"] = jcs.sha256(jcs.canonicalize(legacy))
    with open(path, "a") as f:
        f.write(json.dumps(legacy, separators=(",", ":")) + "\n")
    reopened = Ledger(path)
    assert reopened.head() == legacy["prev_hash_chain"] and reopened.verify_chain()
    assert len(reopened.rows_for_grant("grt_" + "0" * 26)) == 1
    reopened.append("agent:a", "grt_" + "0" * 26, "test.ping", {}, "ok", "pong")
    assert len(reopened.rows_for_grant("grt_" + "0" * 26)) == 2 and reopened.verify_chain()


def test_rebuilding_the_index_keeps_the_stat_key(tmp_path):
    """After another writer's rows are folded in, the object remembers the
    file's stat as of that read: the next lookups on an unchanged file
    cost nothing, and the head cache stays paired with the file it came
    from (a rebuild that loses the key re-reads the whole file on every
    lookup until this object appends)."""
    path = str(tmp_path / "ledger.jsonl")
    writer, reader = Ledger(path), Ledger(path)
    gid = "grt_" + "0" * 26
    for i in range(3):
        writer.append("agent:a", gid, "test.ping", {"i": i}, "ok", "pong")
    assert len(reader.rows_for_grant(gid)) == 3
    assert reader._head_stat == reader._stat_key()
    calls = []
    real_open = open

    def counting_open(*a, **kw):
        calls.append(a[0])
        return real_open(*a, **kw)
    import builtins
    orig = builtins.open
    builtins.open = counting_open
    try:
        assert len(reader.rows_for_grant(gid)) == 3
        assert reader.head() == writer.head()
    finally:
        builtins.open = orig
    assert path not in calls
