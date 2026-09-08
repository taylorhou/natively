"""A persisted pairwise session records the key agreement its root came
from. An unacknowledged handshake made under the older agreement is
restarted, an acknowledged channel is kept, and only an ack for an envelope
sent under the current handshake settles it. A hub answer the strict
reader refuses is a lookup failure, not a verdict on the recipient: the
send stays queued (review 2026-09-07, point 5, gate round 2)."""
import json
import os
import time

from natively import crypto, envelope, node as nodemod

from conftest import agent_key, inbox, make_node, outcomes, pump


def _session_file(n, direction, peer):
    return os.path.join(n.home, "sessions", "%s_%s.json" % (direction, peer.fp))


def _restart(n):
    """The node restarted on this code, registered again (the hub takes
    one registration per node per second, so the wall clock may have to
    pass the previous one first)."""
    n.stop()
    nb = nodemod.Node(n.home)
    nb.start()
    for _ in range(60):
        if set(nb.agents) == nb._last_registered:
            break
        nb.step()
        time.sleep(0.05)
    assert set(nb.agents) == nb._last_registered
    return nb


def _strip_agreement(path):
    st = json.load(open(path))
    st.pop("agreement", None)  # what a node on the older code wrote
    json.dump(st, open(path, "w"))
    return st


def test_unacknowledged_handshake_under_the_old_agreement_restarts_on_the_next_send(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "one"})
    n1.step()  # sent; n2 has not polled, so the handshake is unacknowledged
    p = _session_file(n1, "to", n2)
    old = _strip_agreement(p)
    assert old["hs_pending"] is True
    n1b = _restart(n1)
    assert n1b._session("to", n2.fp) is None
    assert not os.path.exists(p)
    assert "session.reinit" in [e["action"] for e in n1b.ledger.entries()]
    n1b.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "two"})
    n1b.step()
    new = json.load(open(p))
    assert new["agreement"] == crypto.X3DH_VERSION and new["hs_pending"] is True
    assert new["x3dh_ek"] != old["x3dh_ek"]  # a fresh offer, not the old one re-attached
    pump([n2, n1b], 3)
    assert "two" in [r["body"]["text"] for r in inbox(n2, "beta")]
    assert json.load(open(p))["hs_pending"] is False  # the ack for "two" settled the new handshake


def test_acknowledged_channel_under_the_old_agreement_is_kept(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "one"})
    pump([n1, n2], 3)
    p = _session_file(n1, "to", n2)
    st = _strip_agreement(p)
    assert st["hs_pending"] is False
    n1b = _restart(n1)
    s = n1b._session("to", n2.fp)
    assert s is not None and s.agreement == 1 and os.path.exists(p)
    n1b.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "two"})
    pump([n1b, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["one", "two"]
    assert "session.reinit" not in [e["action"] for e in n1b.ledger.entries()]


def test_an_ack_for_an_earlier_channels_envelope_does_not_settle_the_new_handshake(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    beta = agent_key(n2, "beta")
    n1.queue_send("alpha", beta, {"kind": "text", "text": "one"})
    n1.step()
    p = _session_file(n1, "to", n2)
    _strip_agreement(p)
    n1b = _restart(n1)
    n1b.queue_send("alpha", beta, {"kind": "text", "text": "two"})
    n1b.step()  # restarted channel; "one" is still in the unacked table
    (old_mid,) = [m for m, r in n1b.state["unacked"].items() if json.loads(crypto.b64d(r["env"]["body"]))["x3dh_ek"]
                  != json.load(open(p))["x3dh_ek"]]
    old_env = n1b.state["unacked"][old_mid]["env"]
    # the peer acks the OLD envelope only (what a terminal drop of an
    # unreadable envelope does), never having read the new channel
    n2._ack(old_env, "beta")
    n2.step()
    n1b.step()
    assert old_mid not in n1b.state["unacked"]
    assert json.load(open(p))["hs_pending"] is True  # the new handshake is still unproven
    assert n1b._session("to", n2.fp).x3dh_ek is not None  # and keeps travelling


def test_a_refused_directory_response_keeps_the_send_queued(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    real = nodemod._http

    def refused(method, url, *a, **kw):
        if url.endswith("/v1/directory"):
            return 200, b'{"agents": {}, "agents": {}}'  # a duplicate key: the strict reader refuses it
        return real(method, url, *a, **kw)

    monkeypatch.setattr(nodemod, "_http", refused)
    n1._dir_cache = (0.0, None)
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "later"})
    n1.step()
    queued = [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]
    assert len(queued) == 1 and not any(f.endswith(".err") for f in os.listdir(n1.outbox_dir))
    assert outcomes(n1, "msg.send")[-1] == "retry"
    monkeypatch.setattr(nodemod, "_http", real)
    n1._dir_cache = (0.0, None)
    pump([n1, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["later"]
    assert not os.listdir(n1.outbox_dir)


def test_a_refused_directory_response_on_receive_leaves_the_envelope_in_the_queue(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "kept"})
    n1.step()
    mid = list(n1.state["unacked"])[0]
    real = nodemod._http

    def refused(method, url, *a, **kw):
        if url.endswith("/v1/directory"):
            return 200, b'{"agents": {}, "agents": {}}'
        return real(method, url, *a, **kw)

    monkeypatch.setattr(nodemod, "_http", refused)
    n2._dir_cache = (0.0, None)
    before = n2.state["last_seq"]
    n2.step()
    assert inbox(n2, "beta") == [] and mid not in n2.state["seen"] and n2.state["last_seq"] == before
    assert outcomes(n2, "msg.recv")[-1] == "retry"
    assert any(m["env"]["msg_id"] == mid for m in hub.state.queues[n2.fp])  # still queued at the hub
    monkeypatch.setattr(nodemod, "_http", real)
    n2._dir_cache = (0.0, None)
    pump([n2, n1], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["kept"] and n1.state["unacked"] == {}


def test_the_heal_path_reads_the_body_with_the_strict_reader(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "first"})
    pump([n1, n2], 3)
    # n2's saved session diverges (the air wedge); n1 starts a new channel
    n2.sessions.pop("from:" + n1.fp, None)
    other = crypto.DRSession.init_responder(os.urandom(32), n2.spk_sk)
    nodemod._w600(n2._session_path("from", n1.fp), json.dumps(other.to_state()).encode())
    n1.sessions.pop("to:" + n2.fp, None)
    os.remove(n1._session_path("to", n2.fp))
    s, ek = n1._session_for_send(n2.fp)
    hdr, ct = s.encrypt(b'{"kind": "text", "text": "a", "text": "b"}', aad=b"nv1-msg")  # a duplicate key
    n1._save_session("to", n2.fp)
    wire = {"dh": hdr, "ct": crypto.b64e(ct), "x3dh_ek": crypto.b64e(ek)}
    a = n1.agents["alpha"]
    env = envelope.make_message(a["card"]["agent_key"].split(":", 1)[1], agent_key(n2, "beta").split(":", 1)[1],
                                crypto.b64e(json.dumps(wire).encode()), a["seed"],
                                extra={"to": agent_key(n2, "beta"), "to_node": n2.fp})
    n2._handle_envelope(env)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["first"]  # nothing delivered from it
    assert "session.heal" not in [e["action"] for e in n2.ledger.entries()]  # a refused body commits nothing
    # the sender's next envelope under the same offer heals the pair and is read
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "healed"})
    pump([n1, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["first", "healed"]
    assert "session.heal" in [e["action"] for e in n2.ledger.entries()]


def test_a_refused_prekey_response_on_receive_leaves_the_envelope_in_the_queue(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "kept"})
    n1.step()  # the first envelope of a channel: n2 needs n1's prekey bundle to answer the handshake
    mid = list(n1.state["unacked"])[0]
    real = nodemod._http

    def refused(method, url, *a, **kw):
        if "/v1/prekey/" in url:
            return 200, b'{"node_key": "x", "node_key": "y"}'
        return real(method, url, *a, **kw)

    monkeypatch.setattr(nodemod, "_http", refused)
    before = n2.state["last_seq"]
    n2.step()
    assert inbox(n2, "beta") == [] and mid not in n2.state["seen"] and n2.state["last_seq"] == before
    assert outcomes(n2, "msg.recv")[-1] == "retry"
    assert "from:" + n1.fp not in n2.sessions
    monkeypatch.setattr(nodemod, "_http", real)
    pump([n2, n1], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["kept"] and n1.state["unacked"] == {}


def test_a_failure_after_execution_never_runs_the_action_again(tmp_path, hub, principal, monkeypatch):
    from conftest import issue_grant, send_action
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    n1.step()
    mid = list(n1.state["unacked"])[0]
    real_w600 = nodemod._w600

    def disk_full(path, data):
        if os.sep + "inbox" + os.sep in path:
            raise OSError("disk full")  # after the action ran, before the inbox record
        return real_w600(path, data)

    monkeypatch.setattr(nodemod, "_w600_sync", disk_full)
    n2.step()
    assert outcomes(n2, "test.ping") == ["ok"]  # it ran once
    assert inbox(n2, "beta") == [] and any(o.startswith("error") for o in outcomes(n2, "msg.recv", classified=True))  # the injected failure happened
    assert mid in n2.state["seen"]  # and stays seen: not the deferred class
    monkeypatch.setattr(nodemod, "_w600", real_w600)
    env = n1.state["unacked"][mid]["env"]
    from conftest import http
    assert http("POST", hub.url + "/v1/msg", body=env)[0] == 200  # the sender retries the same envelope
    pump([n2, n1], 3)
    assert outcomes(n2, "test.ping") == ["ok"]  # never twice


def test_a_session_file_this_node_cannot_write_does_not_hold_the_page(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "from alpha"})
    n1.step()
    n3.queue_send("gamma", agent_key(n2, "beta"), {"kind": "text", "text": "from gamma"})
    n3.step()
    mid1 = list(n1.state["unacked"])[0]
    real = n2._save_session

    def unwritable(direction, peer_fp):
        if peer_fp == n1.fp:
            raise PermissionError("sessions dir read-only for this peer")
        return real(direction, peer_fp)
    monkeypatch.setattr(n2, "_save_session", unwritable)
    n2.step()
    # local trouble with one peer's session is not a deferral: the message
    # is ledgered and stays seen, and the page goes on to the next peer
    assert mid1 in n2.state["seen"] and "retry" not in outcomes(n2, "msg.recv")
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["from gamma"]
    assert n2.state["last_seq"] >= 2
