"""Directory-unknown recipients go terminal (2026-09-08 fleet finding):
post-#43 a send to a pruned identity deferred forever - an infinite retry
class churning the outbox (96 carried 24k such files). Deferrals to a
recipient not in the directory are terminal after DEFER_UNKNOWN_TTL."""
import os

from natively import crypto, node as nodemod

from conftest import make_node, outcomes


def test_unknown_recipient_defers_then_goes_terminal(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 0)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    ghost = "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    n1.queue_send("alpha", ghost, {"kind": "text", "text": "anyone there"})
    outbox = os.path.join(n1.home, "outbox")

    n1.step()  # first deferral: recorded, still retrying
    assert len([f for f in os.listdir(outbox) if not f.endswith(".err")]) == 1
    assert "recipient-unknown" not in outcomes(n1, "msg.send")

    n1.step()  # past the TTL: terminal .err, outbox clear
    assert [f for f in os.listdir(outbox) if f.endswith(".err")]
    assert "recipient-unknown" in outcomes(n1, "msg.send")
    assert n1.state.get("deferred_since", {}) == {}


def test_unknown_recipient_still_retries_within_ttl(tmp_path, hub, principal, monkeypatch):
    monkeypatch.setattr(nodemod, "DEFER_UNKNOWN_TTL", 3600)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    ghost = "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    n1.queue_send("alpha", ghost, {"kind": "text", "text": "registering soon"})
    for _ in range(3):
        n1.step()
    assert "recipient-unknown" not in outcomes(n1, "msg.send")
    assert "retry" in outcomes(n1, "msg.send")
