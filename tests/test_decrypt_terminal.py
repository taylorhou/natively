"""Decrypt-failure classes (2026-09-08 air wedge): a diverged saved session
made the receiver ignore the peer's re-attached x3dh handshake and fail
every fresh envelope forever, while pre-repair ciphertexts that can never
decrypt churned without bound. Two rules now: heal-on-handshake (adopt the
offered session only if it reads the envelope at hand) and terminal
ack-and-drop past DEFER_DECRYPT_TTL, age anchored on the envelope's signed
ts so an old backlog drains on first sight."""
import os
import time

from natively import crypto, envelope, node as nodemod

from conftest import agent_key, inbox, make_node, outcomes, pump


def _wedge(n1, n2, to_agent="beta"):
    """Break n2's saved session with n1, then have n1 re-init and send."""
    n2.sessions.pop("from:" + n1.fp, None)
    p = n2._session_path("from", n1.fp)
    if os.path.exists(p):
        # diverge the on-disk state: an unrelated fresh session's state
        other = crypto.DRSession.init_responder(os.urandom(32), n2.spk_sk)
        nodemod._w600(p, __import__("json").dumps(other.to_state()).encode())
    n1.sessions.pop("to:" + n2.fp, None)
    p1 = n1._session_path("to", n2.fp)
    if os.path.exists(p1):
        os.remove(p1)
    n1.queue_send("alpha", agent_key(n2, to_agent), {"kind": "text", "text": "heal me"})
    n1.step()  # re-inits: x3dh_ek rides with the first ciphertext


def test_diverged_session_heals_from_reattached_handshake(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "first"})
    pump([n1, n2])
    assert [m["body"]["text"] for m in inbox(n2, "beta")] == ["first"]

    _wedge(n1, n2)
    pump([n1, n2])
    texts = [m["body"]["text"] for m in inbox(n2, "beta")]
    assert "heal me" in texts
    assert not [o for o in outcomes(n2, "msg.recv", classified=True) if o.startswith("error:")]
    assert any(e["action"] == "session.heal" and e["outcome"] == "ok" for e in n2.ledger.entries())


def test_failed_probe_commits_nothing(tmp_path, hub, principal):
    """An ek offer that does NOT read the envelope must not displace state."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    pump([n1, n2])
    env = envelope.make_message(agent_key(n1, "alpha").split(":", 1)[1],
                                agent_key(n2, "beta").split(":", 1)[1],
                                crypto.b64e(b"garbage-wire-body"),
                                n1.agents["alpha"]["seed"])
    n2._handle_envelope(env)
    assert "error" in " ".join(outcomes(n2, "msg.recv", classified=True))
    # no session installed for the failed probe
    assert "from:" + n1.fp not in n2.sessions


def test_old_undecryptable_is_acked_and_dropped_on_first_sight(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    pump([n1, n2])
    acks = []
    monkeypatch.setattr(n2, "_ack", lambda env, agent: acks.append(env["msg_id"]))
    old_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))
    orig_now_iso = envelope.now_iso
    envelope.now_iso = lambda: old_ts
    try:
        env = envelope.make_message(agent_key(n1, "alpha").split(":", 1)[1],
                                    agent_key(n2, "beta").split(":", 1)[1],
                                    crypto.b64e(b"garbage-wire-body"),
                                    n1.agents["alpha"]["seed"])
    finally:
        envelope.now_iso = orig_now_iso
    n2._handle_envelope(env)
    assert acks == [env["msg_id"]]
    assert "terminal" in outcomes(n2, "msg.recv")
    assert env["msg_id"] not in n2.state.get("dfail", {})


def test_young_failure_waits_without_ack(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    pump([n1, n2])
    acks = []
    monkeypatch.setattr(n2, "_ack", lambda env, agent: acks.append(env["msg_id"]))
    env = envelope.make_message(agent_key(n1, "alpha").split(":", 1)[1],
                                agent_key(n2, "beta").split(":", 1)[1],
                                crypto.b64e(b"garbage-wire-body"),
                                n1.agents["alpha"]["seed"])
    n2._handle_envelope(env)
    assert acks == []
    assert "terminal" not in outcomes(n2, "msg.recv")
    assert env["msg_id"] in n2.state["dfail"]
