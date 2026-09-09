"""Retry timers sized to the poll: sent, re-sent at 2P, 4P after that, 8P after that
(three re-sends), undelivered when the 16P deadline passes. outbox_due() only names
what is due; the attempt is counted by outbox_advance() after the adapter's send
succeeded, and outbox_mark_undelivered() is the terminal step (round 3, F11)."""

from natively.adapters.local import LocalWire
from natively.node import MAX_RESENDS

from .conftest import Clock, make_node


def test_outbox_retry_schedule(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    a.receive(b.compose_card())
    P = a.poll_s
    bundle = a.compose_info(b.card, "are you there")
    msg_id = bundle["object"]["msg_id"]
    a.outbox_record(bundle, transport_ref="gmail:1")
    (x,) = a.outbox()
    assert x["status"] == "pending" and x["attempts"] == 1
    assert a.outbox_due() == []
    clock.tick(2 * P)
    (x,) = a.outbox_due()  # first deadline: due, and untouched until the send succeeds
    assert x["status"] == "pending" and x["attempts"] == 1
    (x,) = a.outbox_due()  # asking again changes nothing
    assert x["attempts"] == 1
    assert a.outbox_advance(msg_id)["attempts"] == 2  # the re-send left the box
    assert a.outbox_due() == []
    clock.tick(4 * P - 1)
    assert a.outbox_due() == []
    clock.tick(1)
    (x,) = a.outbox_due()
    assert a.outbox_advance(msg_id)["attempts"] == 3
    clock.tick(8 * P - 1)
    assert a.outbox_due() == []
    clock.tick(1)
    (x,) = a.outbox_due()  # third and last re-send
    assert a.outbox_advance(msg_id)["attempts"] == 4 and a.outbox()[0]["status"] == "pending"
    clock.tick(16 * P - 1)
    assert a.outbox_due() == []
    clock.tick(1)
    (x,) = a.outbox_due()
    assert x["attempts"] > MAX_RESENDS  # the adapter marks it undelivered instead of sending
    assert a.outbox_mark_undelivered(msg_id) is True
    assert a.outbox()[0]["status"] == "undelivered"
    assert a.ledger.entries()[-1]["outcome"] == "undelivered"
    assert a.ledger.entries()[-1]["msg_id"] == msg_id
    assert a.outbox_due() == []  # terminal
    assert a.outbox_advance(msg_id) is None and a.outbox_mark_undelivered(msg_id) is False


def test_ack_marks_outbox_and_records_peer_head(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    wire.deliver(a, b, a.compose_info(b.card, "x"))
    (x,) = a.outbox()
    assert x["status"] == "acked"
    assert a.peer_head(b.agent.public) == b.ledger.head()
    clock.tick(100 * a.poll_s)
    assert a.outbox_due() == []  # acked entries never retry


def test_forged_ack_is_rejected_and_ledgered(tmp_path):
    from natively import ack as ackmod
    from natively import keys

    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    a.receive(b.compose_card())
    bundle = a.compose_info(b.card, "x")
    a.outbox_record(bundle)
    stranger = keys.KeyPair.generate()
    forged = ackmod.sign(
        ackmod.build(
            from_key=stranger.public,
            to_key=a.agent.public,
            ts=a.ts(),
            in_reply_to=bundle["object"]["msg_id"],
            outcome="applied",
            ledger_head="sha256:" + "0" * 64,
            ledger_entry="sha256:" + "0" * 64,
        ),
        stranger,
    )
    from natively import bundle as bundlemod

    assert a.receive(bundlemod.make("ack", forged)) == []
    assert a.outbox()[0]["status"] == "pending"
    assert a.ledger.entries()[-1]["outcome"] == "verify_failed:ack.sender.untrusted"
    assert any("ack.sender.untrusted" in r for r in reports)
