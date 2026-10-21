"""Deferral rows and dead letters (node 96, 2026-10-21). The flush wrote
one `msg.send retry` row per waiting file on every ~5 s pass: 32.4M of
96's 36.2M ledger rows, re-verified on every restart. A waiting file is
now ledgered when it starts waiting for a reason and when that reason
changes; the terminal row is unchanged. Terminal `.err` files never left
the outbox (66,473 beside 0 live sends): past a grace period they move to
deadletter/, and are removed only past an operator-set retention."""
import os
import time
import urllib.error

from natively import crypto, node as nodemod

from conftest import agent_key, ledger_entries, make_node, outcomes


def _ghost():
    return "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))


def test_a_send_waiting_on_an_unknown_recipient_is_ledgered_once(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 3600)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n1.queue_send("alpha", _ghost(), {"kind": "text", "text": "registering soon"})
    for _ in range(6):
        n1.step()
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]  # still waiting
    assert outcomes(n1, "msg.send") == ["retry"]  # one row for six passes


def test_the_terminal_row_still_follows_the_single_deferral(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 0)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n1.queue_send("alpha", _ghost(), {"kind": "text", "text": "anyone there"})
    n1.step()
    n1.step()
    n1.step()
    assert outcomes(n1, "msg.send") == ["retry", "recipient-unknown"]
    assert n1._deferral_logged == {}
    err = [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    assert len(err) == 1
    assert time.time() - os.stat(os.path.join(n1.outbox_dir, err[0])).st_mtime < 60  # stamped when it died


def test_a_429_backed_off_send_is_ledgered_once_then_sent(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    real = n1._hub_req
    posts = []

    def full(method, path, body=None, headers=None):
        if method == "POST" and path == "/v1/msg":
            posts.append(path)
            raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
        return real(method, path, body=body, headers=headers)
    n1._hub_req = full
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "room?"})
    for _ in range(4):
        n1._backoff.clear()
        n1._rcpt_backoff.clear()  # the backoff expired: the next pass posts again
        n1.step()
    assert len(posts) == 4  # refused four times...
    assert outcomes(n1, "msg.send") == ["retry"]  # ...ledgered once
    n1._hub_req = real
    n1._backoff.clear()
    n1._rcpt_backoff.clear()
    n1.step()
    assert outcomes(n1, "msg.send") == ["retry", "queued"]


def test_a_new_deferral_reason_is_ledgered_again(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 3600)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    real = n1._hub_req
    mode = {"code": 429}

    def refusing(method, path, body=None, headers=None):
        if method == "POST" and path == "/v1/msg":
            if mode["code"] == 429:
                raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
            raise urllib.error.URLError("hub away")
        return real(method, path, body=body, headers=headers)
    n1._hub_req = refusing
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "eventually"})
    for code in (429, 429, None, None, 429):
        mode["code"] = code
        n1._backoff.clear()
        n1._rcpt_backoff.clear()
        n1.step()
    rows = [e for e in ledger_entries(n1) if e["action"] == "msg.send"]
    assert [e["outcome"] for e in rows] == ["retry", "retry", "retry"]  # 429, hub away, 429 again


def test_dead_letters_leave_the_outbox_after_the_grace_period(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 0)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n1.DEADLETTER_SWEEP_S = 0
    n1.queue_send("alpha", _ghost(), {"kind": "text", "text": "anyone there"})
    n1.step()
    n1.step()
    err = [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    assert len(err) == 1
    src = os.path.join(n1.outbox_dir, err[0])
    data = open(src, "rb").read()
    n1.step()
    assert os.path.exists(src)  # fresh: stays inside the grace period
    assert "outbox.deadletter" not in [e["action"] for e in ledger_entries(n1)]

    old = time.time() - n1.DEADLETTER_GRACE_S - 5
    os.utime(src, (old, old))
    n1.step()
    ddir = os.path.join(n1.home, "deadletter")
    assert not os.path.exists(src) and os.listdir(n1.outbox_dir) == []
    assert open(os.path.join(ddir, err[0]), "rb").read() == data  # the same bytes
    assert os.stat(ddir).st_mode & 0o777 == 0o700
    assert outcomes(n1, "outbox.deadletter") == ["swept"]
    n1.step()
    assert outcomes(n1, "outbox.deadletter") == ["swept"]  # nothing to do: no row


def test_dead_letters_are_kept_unless_the_operator_sets_a_retention(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 0)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n1.DEADLETTER_SWEEP_S = 0
    n1.DEADLETTER_GRACE_S = 0
    n1.queue_send("alpha", _ghost(), {"kind": "text", "text": "anyone there"})
    n1.step()
    n1.step()
    ddir = os.path.join(n1.home, "deadletter")
    [name] = os.listdir(ddir)
    year_ago = time.time() - 365 * 86400
    os.utime(os.path.join(ddir, name), (year_ago, year_ago))
    n1.step()
    assert os.listdir(ddir) == [name]  # no deadletter_keep_days: nothing is ever removed

    n1.cfg["deadletter_keep_days"] = 30
    n1.step()
    assert os.listdir(ddir) == []
    swept = [e for e in ledger_entries(n1) if e["action"] == "outbox.deadletter"]
    assert [e["outcome"] for e in swept] == ["swept", "swept"]  # moved, then expired


def test_the_sweep_runs_at_most_once_per_interval(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 0)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n1.DEADLETTER_GRACE_S = 0
    n1.step()  # the first sweep runs (nothing to move)
    n1.queue_send("alpha", _ghost(), {"kind": "text", "text": "anyone there"})
    n1.step()
    n1.step()
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]  # within DEADLETTER_SWEEP_S: not swept yet
    n1._last_dl_sweep = 0.0
    n1.step()
    assert not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
