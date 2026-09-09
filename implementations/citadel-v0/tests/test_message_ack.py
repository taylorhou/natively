import base64
import json

import pytest

from natively import ack as ackmod
from natively import keys
from natively import message as msgmod
from natively.errors import VerifyError

from .conftest import uid

TS = "2026-09-07T07:00:00Z"


@pytest.fixture
def pair():
    return keys.KeyPair.generate(), keys.KeyPair.generate()


def test_info_message_roundtrip(pair):
    a, b = pair
    m = msgmod.sign(msgmod.info(from_key=a.public, to_key=b.public, ts=TS, text="hi"), a)
    msgmod.verify(m)
    assert m["msg_id"].startswith("msg_") and msgmod.is_information(m)
    assert msgmod.decode_body(m) == {"type": "info", "text": "hi"}
    assert m["in_reply_to"] is None
    with pytest.raises(VerifyError) as e:
        msgmod.verify({**m, "body": msgmod.encode_body({"type": "info", "text": "changed"})})
    assert e.value.reason == "message.sig.invalid"


def test_action_message_and_body_rules(pair):
    a, b = pair
    m = msgmod.sign(
        msgmod.action(
            from_key=a.public,
            to_key=b.public,
            ts=TS,
            action="fs.write",
            resource="host:x:scratch/y",
            params={"content": "z"},
            grant_ids=[uid("grt")],
            in_reply_to=uid("msg"),
        ),
        a,
    )
    msgmod.verify(m)
    assert not msgmod.is_information(m)
    body = msgmod.decode_body(m)
    assert body["action"] == "fs.write" and body["params"] == {"content": "z"}
    # body variants that must be rejected
    for plain in (
        {"type": "run"},
        {"type": "action", "action": "x"},
        {"type": "info", "text": 1},
        ["list"],
        {"type": "action", "action": "a", "resource": "r", "params": 1},
    ):
        bad = msgmod.sign({**m, "body": msgmod.encode_body(plain)}, a)
        with pytest.raises(VerifyError):
            msgmod.decode_body(bad)
    raw = msgmod.sign({**m, "body": base64.b64encode(b"\xff\xfe").decode()}, a)
    with pytest.raises(VerifyError) as e:
        msgmod.decode_body(raw)
    assert e.value.reason == "message.body.json"


def test_message_structure(pair):
    a, b = pair
    m = msgmod.sign(msgmod.info(from_key=a.public, to_key=b.public, ts=TS, text="hi"), a)
    for over, reason in [
        ({"grant_ids": ["nope"]}, "message.grant_ids.format"),
        ({"grant_ids": ["grt_1"]}, "message.grant_ids.format"),
        ({"grant_ids": ["grt_../../etc/passwd"]}, "message.grant_ids.format"),
        ({"in_reply_to": "x"}, "message.in_reply_to.format"),
        ({"msg_id": "msg_1"}, "message.msg_id.format"),
        ({"body": "***"}, "message.body.encoding"),
        ({"ts": "2026-09-07 07:00"}, "message.ts.format"),
        ({"extra": 1}, "message.unknown_field"),
    ]:
        with pytest.raises(VerifyError) as e:
            msgmod.verify({**m, **over})
        assert e.value.reason == reason
    with pytest.raises(ValueError):
        msgmod.sign(m, b)
    big = msgmod.encode_body({"type": "info", "text": "x" * (msgmod.MAX_BODY_BYTES + 10)})
    with pytest.raises(VerifyError) as e:
        msgmod.verify(msgmod.sign({**m, "body": big}, a))
    assert e.value.reason == "message.body.size"


def test_ack_roundtrip(pair):
    a, b = pair
    head = "sha256:" + "a" * 64
    ack = ackmod.sign(
        ackmod.build(
            from_key=b.public,
            to_key=a.public,
            ts=TS,
            in_reply_to=uid("msg"),
            outcome="refused",
            detail="scope.no_match",
            ledger_head=head,
            ledger_entry=head,
        ),
        b,
    )
    ackmod.verify(ack)
    assert ack["outcome"] == "refused:scope.no_match" and ackmod.outcome_kind(ack) == "refused"
    with pytest.raises(VerifyError):
        ackmod.verify({**ack, "ledger_head": "sha256:" + "b" * 64})
    with pytest.raises(VerifyError) as e:
        ackmod.verify(ackmod.sign({**ack, "outcome": "maybe"}, b))
    assert e.value.reason == "ack.outcome"
    with pytest.raises(ValueError):
        ackmod.build(
            from_key=b.public,
            to_key=a.public,
            ts=TS,
            in_reply_to=uid("msg"),
            outcome="maybe",
            ledger_head=head,
            ledger_entry=head,
        )
    assert json.dumps(ack)  # plain JSON
