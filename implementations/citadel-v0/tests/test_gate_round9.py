"""Round 9 (hw-i4nlj): the eighth cross-model gate's findings on the whole package —
two MAJOR and two MINOR on the edges of round 8's work — each fixed as ruled.

N1  Local state is never peer input. ONE typed loader (`state.read`) serves every
    state file read as a structure — seen.json, outbox.json, pinned.json, the wire
    cursor, revocations.check.json, seen-mail.json, the held-reply sidecars, the
    config, the replay marker, the repair intents, the peer heads, the cards and
    grants on file — checking the top-level type and the per-entry shape the code
    relies on and raising IntegrityError state.corrupt (card.corrupt for a card on
    file) naming the path and the reason. So AttributeError, TypeError and KeyError
    from a file of ours of the wrong shape are not reachable as
    verify_failed:malformed: the error is a storage failure everywhere it surfaces —
    receive refuses (nothing ledgered, nothing acked, the mail unseen, the poll
    incomplete, storage_failures counted), `_ack` and `stored_reply` raise it
    through, `pending repair` reports it by name with the path and leaves the copy,
    the CLI verbs exit 2 naming the path, a node whose config, trust store or self
    card fails does not construct.
N2  `LocalWire.deliver` validates an INPUT bundle of kind ack with
    `sender.check_reply` before it is recorded, logged or delivered, exactly as
    `MailWire.send` does: reply.invalid, nothing recorded, logged or delivered.
N3  On the send path a StorageError (card.self_corrupt, reply.invalid, any
    IntegrityError, an OSError reading state) is a storage failure of the poll —
    counted, the held copy kept, nothing transmitted, complete False, the cursor
    frozen — and only a transport failure (the send tool's non-zero exit, a timeout)
    is the transport class; the two are told apart by exception TYPE, never by
    message text.
N4  (in test_gate_round8 / test_gate_round7b) the CLI send-form test exercises its
    boundary with a fresh message, and every assertion that could pass vacuously is
    tightened.

Categories as in the earlier round modules: FAILURE BEFORE (a state file of the wrong
shape stands before the read), RESTART RECOVERY (a CLI invocation builds a fresh Node),
ORDERING (nothing recorded, logged or delivered before the boundary)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively import message as msgmod
from natively import state as statemod
from natively.adapters import mail as mailmod
from natively.adapters.local import LocalWire
from natively.adapters.mail import MailWire
from natively.cli import main
from natively.errors import IntegrityError, StorageError, VerifyError
from natively.node import REPLAY_MARKER, Node

from .conftest import Clock, make_node, uid
from .test_gate_round3 import seen_of
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv, _held_ack_over_mail
from .test_gate_round7b import _acks_out, _actions, _inbox_len, _quarantined
from .test_gate_round8 import SELF, _flip, _unseen_mail_ids
from .test_hardening import STATEMENT, fs_write_scope, pair, write_bundle

__all__ = ["pair"]  # the fixture is re-exported for this module's tests

TS = "2026-09-07T07:00:00Z"
PKG = Path(__file__).resolve().parents[1] / "natively"

# seen.json of the wrong shape, one per ruling: an empty list, a string, an object
# with a non-object value, an entry whose ack is not an object, an entry that is
# neither a stored ack nor a reservation (no ack, no ts)
SEEN_SHAPES = {
    "empty-list": lambda msg_id: "[]",
    "string": lambda msg_id: '"x"',
    "non-object-value": lambda msg_id: json.dumps({msg_id: 5}),
    "ack-not-object": lambda msg_id: json.dumps({msg_id: {"ack": "x", "ts": TS}}),
    "neither-ack-nor-reservation": lambda msg_id: json.dumps({msg_id: {"status": "in_progress"}}),
}


def _outcomes(node) -> list[str]:
    return [e["outcome"] for e in node.ledger.entries()]


def _no_transport(monkeypatch) -> list[list[str]]:
    """The CLI's own MailWire (built with the default runner) records every transport
    call here instead of running the mail helper; the tests assert the list stays empty."""
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(argv)
        raise AssertionError("the transport was called")

    monkeypatch.setattr(mailmod, "default_runner", runner)
    return calls


# ---- N1. seen.json: receive, pending repair, natively ack ------------------------------------


@pytest.mark.parametrize("shape", sorted(SEEN_SHAPES))
def test_a_malformed_seen_file_on_receive_is_a_storage_failure_the_mail_unseen(tmp_path, shape):
    """FAILURE BEFORE: seen.json of the wrong shape stands when a message arrives. The
    receive refuses — state.corrupt naming the path, in the summary errors and the
    report stream — nothing is ledgered (never verify_failed:malformed), nothing is
    acked or held, the mail stays unseen, storage_failures 1, complete False, the
    file untouched. The file removed by hand, the next poll answers as before."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    seen_path = b.state / "seen.json"
    seen_path.write_text(SEEN_SHAPES[shape](msg_id))
    raw = seen_path.read_bytes()
    ledger_before = len(b.ledger)
    inbox_before = _inbox_len(fake)
    unseen_before = _unseen_mail_ids(fake, b, wb)
    assert len(unseen_before) == 1
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert s["applied"] == 0 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert any("state.corrupt" in e and str(seen_path) in e for e in s["errors"])
    assert [r for r in reports if "state.corrupt" in r and str(seen_path) in r and "storage" in r]
    assert len(b.ledger) == ledger_before and "verify_failed:malformed" not in _outcomes(b)
    assert b.ledger.find_msg(msg_id) is None
    assert wb._pending_replies() == [] and wb._aside_replies() == []
    assert _unseen_mail_ids(fake, b, wb) == unseen_before
    assert seen_path.read_bytes() == raw  # the poll repaired nothing
    with pytest.raises(IntegrityError) as e:
        b._seen()
    assert e.value.reason == "state.corrupt" and str(seen_path) in str(e.value)
    seen_path.unlink()  # the operator's call; the poll never touches it
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert _unseen_mail_ids(fake, b, wb) == set()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("shape", sorted(SEEN_SHAPES))
def test_pending_repair_refuses_a_malformed_seen_file_by_name_and_resolves_nothing(
    tmp_path, capsys, shape
):
    """RESTART RECOVERY (the CLI's fresh Node): the stored-ack source cannot be read —
    refused by name with the path (state.corrupt), counted, the copy left unresolved,
    nothing held, nothing sent, the seen file untouched, no fallthrough to the
    completion, no traceback."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    seen_path = b.state / "seen.json"
    seen_path.write_text(SEEN_SHAPES[shape](msg_id))
    raw = seen_path.read_bytes()
    inbox_before = _inbox_len(fake)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    assert "0 rebuilt" in out.out and "0 unresolvable" in out.out
    assert "1 storage failure(s)" in out.out
    # round 14: the seen file is read FIRST by the anchored ledger check that precedes
    # the discard-record lookup (the stored acks anchor the chain): refused there
    assert f"the discard record of {aside.name}" in out.err
    assert "state.corrupt" in out.err and str(seen_path) in out.err
    assert "Traceback" not in out.err and "AttributeError" not in out.err
    assert wb._unresolved(aside) and aside.exists() and wb._pending_replies() == []
    assert seen_path.read_bytes() == raw
    assert "pending_reply.reconstructed" not in _actions(b)
    assert _inbox_len(fake) == inbox_before
    s = wb.poll_once()  # the aside still counts; nothing sent
    assert s["replies"] == 0 and s["complete"] is False and _inbox_len(fake) == inbox_before


@pytest.mark.parametrize("shape", sorted(SEEN_SHAPES))
def test_the_ack_verb_refuses_a_malformed_seen_file_naming_the_path(
    tmp_path, capsys, monkeypatch, shape
):
    """`natively ack MSG_ID` on a seen file of the wrong shape: exit 2, state.corrupt
    with the path, zero transport calls, no traceback."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    seen_path = b.state / "seen.json"
    seen_path.write_text(SEEN_SHAPES[shape](msg_id))
    calls = _no_transport(monkeypatch)
    assert main([*_argv(b), "ack", msg_id]) == 2
    err = capsys.readouterr().err
    assert "natively: state.corrupt" in err and str(seen_path) in err
    assert "Traceback" not in err and calls == []


def test_the_seen_loader_accepts_every_shape_the_node_writes(pair):
    """The shapes the node itself writes — a reservation, a stored ack — pass the
    loader; the loader is a check, never a rewrite."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    msg_id = write_bundle(a, b, g, "f.txt")["object"]["msg_id"]
    b._reserve(msg_id, g["grant_id"])
    assert statemod.seen(seen_of(b)) is None and msg_id in b._seen()
    (reply,) = b.receive(a.compose_info(b.card, "hi"))
    stored = seen_of(b)
    assert statemod.seen(stored) is None and "ack" in stored[reply["object"]["in_reply_to"]]
    assert b._seen() == stored


# ---- N1. every other state file, one wrong shape at its own read site ---------------------


@pytest.mark.parametrize("bad", ["{}", '[{"msg_id": "x"}]', "[5]"], ids=["object", "fields", "int"])
def test_a_malformed_outbox_is_a_storage_failure_at_the_ack_and_the_outbox_step(tmp_path, bad):
    """outbox.json of the wrong shape: the ack's receive refuses (state.corrupt, the
    mail unseen, nothing ledgered) and the outbox step is counted; `outbox()` raises
    naming the path; the file untouched. Restored, the ack lands."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    assert wb.poll_once()["replies"] == 1
    outbox_path = a.state / "outbox.json"
    original = outbox_path.read_bytes()
    outbox_path.write_text(bad)
    ledger_before = len(a.ledger)
    unseen_before = _unseen_mail_ids(fake, a, wa)
    assert len(unseen_before) == 1
    s = wa.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and s["storage_failures"] == 2
    assert any("storage failure on mail" in e and str(outbox_path) in e for e in s["errors"])
    assert any("reading the outbox" in e and str(outbox_path) in e for e in s["errors"])
    assert len(a.ledger) == ledger_before and "verify_failed:malformed" not in _outcomes(a)
    assert _unseen_mail_ids(fake, a, wa) == unseen_before
    assert outbox_path.read_text() == bad
    with pytest.raises(IntegrityError) as e:
        a.outbox()
    assert e.value.reason == "state.corrupt" and str(outbox_path) in str(e.value)
    outbox_path.write_bytes(original)
    s = wa.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("bad", ["[]", '{"k": "x"}'], ids=["list", "root-not-object"])
def test_a_malformed_trust_store_refuses_construction_and_the_card_import(tmp_path, capsys, bad):
    """pinned.json of the wrong shape: a fresh Node refuses (state.corrupt naming the
    path; every CLI verb exits 2, no traceback), a live node's receive of a card
    refuses as a storage failure (the mail unseen, nothing ledgered, never an empty
    trust store that holds the card as unpinned)."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    pinned_path = b.state / "pinned.json"
    original = pinned_path.read_bytes()
    pinned_path.write_text(bad)
    with pytest.raises(IntegrityError) as e:
        Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert e.value.reason == "state.corrupt" and str(pinned_path) in str(e.value)
    assert not (b.state / REPLAY_MARKER).exists()  # nothing swept, nothing written
    assert main([*_argv(b), "cards"]) == 2
    err = capsys.readouterr().err
    assert "state.corrupt" in err and str(pinned_path) in err and "Traceback" not in err
    with pytest.raises(IntegrityError):
        _ = b.pinned
    wa.send(a.compose_card())
    ledger_before = len(b.ledger)
    unseen_before = _unseen_mail_ids(fake, b, wb)
    s = wb.poll_once()
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("state.corrupt" in e and str(pinned_path) in e for e in s["errors"])
    assert len(b.ledger) == ledger_before and _unseen_mail_ids(fake, b, wb) == unseen_before
    assert pinned_path.read_text() == bad
    pinned_path.write_bytes(original)
    assert wb.poll_once()["applied"] == 1


@pytest.mark.parametrize("bad", ["[]", '{"g1": 5}'], ids=["list", "note-not-string"])
def test_a_malformed_transport_seen_file_is_a_storage_failure_never_an_empty_one(tmp_path, bad):
    """seen-mail.json of the wrong shape: nothing is fetched or applied (state.corrupt
    naming the path, counted, the outbox step still runs), the file untouched —
    never read as an empty seen file that re-reads the whole window."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    original = wb.seen_path.read_bytes()
    wb.seen_path.write_text(bad)
    wa.send(a.compose_info(b.card, "hello"))
    ledger_before = len(b.ledger)
    searches_before = len(fake.searches)
    s = wb.poll_once()
    assert s["fetched"] == 0 and s["applied"] == 0 and s["storage_failures"] == 1
    assert s["complete"] is False and len(fake.searches) == searches_before  # no fetch
    assert any("reading the seen file" in e and str(wb.seen_path) in e for e in s["errors"])
    assert any("state.corrupt" in e for e in s["errors"])
    assert len(b.ledger) == ledger_before and wb.seen_path.read_text() == bad
    with pytest.raises(IntegrityError) as e:
        wb._seen()
    assert e.value.reason == "state.corrupt" and str(wb.seen_path) in str(e.value)
    wb.seen_path.write_bytes(original)
    assert wb.poll_once()["applied"] == 1


def test_a_present_null_cursor_and_a_list_sidecar_are_state_corrupt(tmp_path, pair):
    """The wire cursor and the freshness sidecar through the same loader: a present
    `null` cursor (never "no cursor"), a list sidecar (never "never checked") —
    state.corrupt naming the path; through receive the sidecar is a storage failure
    (nothing ledgered)."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wb.cursor_path.write_text("null")
    with pytest.raises(IntegrityError) as e:
        wb.cursor()
    assert e.value.reason == "state.corrupt" and str(wb.cursor_path) in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["fetch_failures"] == 0 and s["complete"] is False
    assert any("reading the cursor" in e and str(wb.cursor_path) in e for e in s["errors"])
    a2, b2, clock2, reports = pair
    g = a2.issue_grant(
        subject_card=b2.card, scope=fs_write_scope(b2, "f.txt"), principal_statement=STATEMENT
    )
    b2.revocations.check_path.write_text("[]")
    with pytest.raises(IntegrityError) as e:
        b2.revocations.last_checked()
    assert e.value.reason == "state.corrupt" and str(b2.revocations.check_path) in str(e.value)
    before = len(b2.ledger)
    with pytest.raises(StorageError) as se:
        b2.receive(write_bundle(a2, b2, g, "f.txt"))
    assert "state.corrupt" in str(se.value) and str(b2.revocations.check_path) in str(se.value)
    assert len(b2.ledger) == before and not (b2.scratch_dir / "f.txt").exists()


@pytest.mark.parametrize("bad", ["[]", "null", '"x"'], ids=["list", "null", "string"])
def test_a_held_reply_sidecar_that_is_not_an_object_is_quarantined_never_sent(tmp_path, bad):
    """A held reply of the wrong shape through the loader: state.corrupt at the read,
    quarantined like any copy that fails (moved aside, counted, ledgered
    pending_reply.corrupt once), never sent, never deleted."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    p.write_text(bad)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert _inbox_len(fake) == inbox_before and not p.exists()
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and aside.name.startswith(p.name)
    assert aside.read_text() == bad  # the evidence, byte for byte
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert any("state.corrupt" in e and "not an object" in e and p.name in e for e in s["errors"])


@pytest.mark.parametrize("bad", ["[]", '{"k": {"head": 5}}'], ids=["list", "head-not-string"])
def test_malformed_peer_heads_refuse_the_ack_and_the_head_lookup(tmp_path, bad):
    """peer-heads.json of the wrong shape: an ack's receive refuses (state.corrupt, the
    mail unseen, the outbox entry still pending, nothing ledgered), `peer_head`
    raises naming the path. Restored, the ack lands."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1 and wa.poll_once()["applied"] == 1
    heads_path = a.state / "peer-heads.json"
    original = heads_path.read_bytes()
    wa.send(a.compose_info(b.card, "two"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    heads_path.write_text(bad)
    ledger_before = len(a.ledger)
    s = wa.poll_once()
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("state.corrupt" in e and str(heads_path) in e for e in s["errors"])
    assert len(a.ledger) == ledger_before and a.outbox_entry(msg_id)["status"] == "pending"
    with pytest.raises(IntegrityError) as e:
        a.peer_head(b.agent.public)
    assert e.value.reason == "state.corrupt" and str(heads_path) in str(e.value)
    heads_path.write_bytes(original)
    assert wa.poll_once()["applied"] == 1 and a.outbox_entry(msg_id)["status"] == "acked"
    assert a.peer_head(b.agent.public) == b.ledger.head()


@pytest.mark.parametrize(
    "bad", ["[]", '{"extensions": []}', '{"poll_s": "60"}'], ids=["list", "extensions", "poll_s"]
)
def test_a_malformed_config_refuses_construction(tmp_path, capsys, bad):
    """config.json of the wrong shape: a fresh Node refuses (state.corrupt naming the
    path), every CLI verb exits 2, no traceback (previously a TypeError)."""
    n = make_node(tmp_path, "n", Clock())
    config_path = n.state / "config.json"
    config_path.write_text(bad)
    with pytest.raises(IntegrityError) as e:
        Node(state_dir=n.state, keys_dir=n.keys_dir, scratch_dir=n.scratch_dir)
    assert e.value.reason == "state.corrupt" and str(config_path) in str(e.value)
    assert main([*_argv(n), "card", "--show"]) == 2
    err = capsys.readouterr().err
    assert "state.corrupt" in err and str(config_path) in err and "Traceback" not in err


@pytest.mark.parametrize("bad", ["[]", '{"principals": "x"}'], ids=["list", "principals"])
def test_a_malformed_replay_marker_refuses_authorization_never_reopens_it(pair, bad):
    """replay-pending.json of the wrong shape: the authorization path refuses as a
    storage failure (state.corrupt naming the path; nothing ledgered, nothing
    written to scratch, the marker left) — never "no marker"."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    marker = b.state / REPLAY_MARKER
    marker.write_text(bad)
    before = len(b.ledger)
    with pytest.raises(StorageError) as e:
        b.receive(write_bundle(a, b, g, "f.txt"))
    assert isinstance(e.value, IntegrityError) and e.value.reason == "state.corrupt"
    assert str(marker) in str(e.value)
    assert len(b.ledger) == before and marker.read_text() == bad
    assert not (b.scratch_dir / "f.txt").exists()
    with pytest.raises(IntegrityError):
        b._replay_pending()


@pytest.mark.parametrize("damage", ["not-an-object", "agent-key", "name-binding"])
def test_a_damaged_card_on_file_is_card_corrupt_at_every_read_never_malformed(
    tmp_path, capsys, pair, damage
):
    """A card under cards/ that is not an object, no longer verifies, or is not bound
    to its name: card.corrupt naming the path at EVERY read — the sender lookup
    (receive: a storage failure, nothing ledgered, never verify_failed:malformed),
    `trusted_cards`, `find_card`, the CLI (exit 2). A bundle that carries no card
    of its own re-imports nothing, so the damaged file is what the lookup reads."""
    a, b, clock, reports = pair
    (card_file,) = [
        f
        for f in (b.state / "cards").iterdir()
        if json.loads(f.read_text())["agent"]["name"] == "a"
    ]
    if damage == "not-an-object":
        card_file.write_text("[]")
        path = card_file
    elif damage == "agent-key":
        c = json.loads(card_file.read_text())
        c["agent"]["key"] = b.agent.public  # another agent's key under a's name, sig kept
        card_file.write_text(json.dumps(c))
        path = card_file
    else:
        path = card_file.with_name("b" * 64 + ".json")
        path.write_bytes(card_file.read_bytes())  # a sound card under another name
    m = {**a.compose_info(b.card, "hi"), "cards": []}  # nothing to re-import over the file
    before = len(b.ledger)
    with pytest.raises(StorageError) as e:
        b.receive(m)
    assert isinstance(e.value, IntegrityError) and e.value.reason == "card.corrupt"
    assert str(path) in str(e.value)
    assert len(b.ledger) == before and "verify_failed:malformed" not in _outcomes(b)
    for read in (b.trusted_cards, lambda: b.find_card("a"), lambda: b.card_for_key(a.agent.public)):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "card.corrupt" and str(path) in str(e.value)
    assert main([*_argv(b), "cards"]) == 2
    err = capsys.readouterr().err
    assert "card.corrupt" in err and str(path) in err and "Traceback" not in err


def test_a_damaged_pending_card_is_card_corrupt_at_the_pin_and_the_listing(tmp_path, capsys):
    """cards-pending/ through the same loader: `pin` refuses (nothing pinned, the
    held card kept) and `natively cards` exits 2, both naming the path."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    assert b.receive(a.compose_card()) == []  # held: a's principal is not pinned on b
    (held,) = list((b.state / "cards-pending").iterdir())
    held.write_text('{"card_version": "v0"}')
    with pytest.raises(IntegrityError) as e:
        b.pin(a.principal.public, "a")
    assert e.value.reason == "card.corrupt" and str(held) in str(e.value)
    # the root is published (pin writes it before promoting held cards); the damaged
    # card is never promoted and is kept where it was, named
    assert a.principal.public in b.pinned and held.exists()
    assert b.trusted_cards() == [] and list((b.state / "cards").iterdir()) == []  # not promoted
    assert main([*_argv(b), "cards"]) == 2
    err = capsys.readouterr().err
    assert "card.corrupt" in err and str(held) in err and "Traceback" not in err


@pytest.mark.parametrize("damage", ["not-an-object", "not-a-grant", "name-binding"])
def test_a_malformed_grant_on_file_is_state_corrupt_never_malformed(pair, damage):
    """A grant under grants/ that is not an object, not a grant in structure, or not
    bound to its name: state.corrupt naming the path at the identity check of the
    next message that carries it (receive: a storage failure, nothing ledgered,
    never verify_failed:malformed), at `load_grant`, at `grants_on_file`, and at
    `compose_action` on the issuing side."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "f.txt"),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    (r,) = b.receive(write_bundle(a, b, g, "f.txt"))
    assert r["object"]["outcome"] == "applied"
    for node in (a, b):
        stored = node.state / "grants" / f"{g['grant_id']}.json"
        if damage == "not-an-object":
            stored.write_text("[]")
            path = stored
        elif damage == "not-a-grant":
            stored.write_text(json.dumps({"grant_id": g["grant_id"]}))
            path = stored
        else:
            path = node.state / "grants" / f"{uid('grt')}.json"
            path.write_bytes(stored.read_bytes())
        with pytest.raises(IntegrityError) as e:
            node.grants_on_file()
        assert e.value.reason == "state.corrupt" and str(path) in str(e.value)
        if damage != "name-binding":
            with pytest.raises(IntegrityError):
                node.load_grant(g["grant_id"])
    if damage == "name-binding":
        # the file under the grant's own name is sound: the message composes and
        # the identity check reads it; the listing (`grants_on_file`) refuses above
        return
    with pytest.raises(IntegrityError) as e:
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("g.txt"),
            params={"content": "y\n"},
            grant_ids=[g["grant_id"]],
        )
    assert e.value.reason == "state.corrupt"
    m = _bundle_with_grant(a, b, g, "g.txt")  # built from the object in hand
    before = len(b.ledger)
    with pytest.raises(StorageError) as e:
        b.receive(m)
    assert isinstance(e.value, IntegrityError) and e.value.reason == "state.corrupt"
    assert str(b.state / "grants" / f"{g['grant_id']}.json") in str(e.value)
    assert len(b.ledger) == before and "verify_failed:malformed" not in _outcomes(b)
    assert not (b.scratch_dir / "g.txt").exists()


def _bundle_with_grant(a, b, g, name):
    """An action bundle carrying the grant object `g` itself (the issuing side's
    store may be damaged; the bundle is built from the object in hand)."""
    m = msgmod.sign(
        msgmod.action(
            from_key=a.agent.public,
            to_key=b.card["agent"]["key"],
            ts=a.ts(),
            action="fs.write",
            resource=b.executor().resource_for(name),
            params={"content": "y\n"},
            grant_ids=[g["grant_id"]],
        ),
        a.agent,
    )
    return bundlemod.make("message", m, cards=[a.card], grants=[g])


def test_a_repair_intent_marker_of_the_wrong_shape_refuses_every_writer_by_name(pair):
    """A <store>-repair-pending.json that is not an intent (a list here): every
    writer of that store refuses (<store>.repair.intent_corrupt naming the path),
    the repair verb refuses the same way, the marker stays."""
    a, b, clock, reports = pair
    marker = b.state / "feed-repair-pending.json"
    marker.write_text("[]")
    before = len(b.ledger)
    with pytest.raises(IntegrityError) as e:
        b.revoke(grants=[uid("grt")], principal_statement="x")
    assert e.value.reason == "feed.repair.intent_corrupt" and str(marker) in str(e.value)
    with pytest.raises(IntegrityError) as e:
        b.repair_feed()
    assert e.value.reason == "feed.repair.intent_corrupt" and str(marker) in str(e.value)
    assert marker.read_text() == "[]" and len(b.ledger) == before


def test_every_shape_names_what_it_refuses():
    """The loader's shapes, directly: each accepts what the node writes and names
    the mismatch it refuses (the top-level type, the entry, the field)."""
    ok = {
        statemod.seen: {
            "m": {"ack": {}, "ts": TS},
            "n": {"status": "in_progress", "grant_id": uid("grt"), "ts": TS},
        },
        statemod.pinned: {"k": {"name": "a", "pinned_at": TS}},
        statemod.peer_heads: {"k": {"head": "h", "entry": "e"}},
        statemod.config: {
            "poll_s": 60,
            "extensions": {"standing_denial": True},
            "peer_addresses": [],
        },
        statemod.replay_marker: {"principals": ["k"], "why": "w", "ts": TS},
        statemod.repair_intent: {
            "step": "intent",
            "file": "f",
            "truncate_to": 1,
            "bytes": 2,
            "tail_sha256": "s",
            "intent_id": uid("rpr"),  # round 15: an rpr_ id in full
        },
        statemod.cursor: {"last_complete_fetch": TS},
        statemod.check_sidecar: {"last_checked": TS},
        statemod.seen_mail: {"g1": "card:"},
        statemod.held_reply: {"kind": "ack"},
    }
    bad = {
        statemod.seen: ([], "not an object"),
        statemod.outbox: ([{"msg_id": "m"}], "entry 0: to is not a string"),
        statemod.pinned: ({"k": "x"}, "root 'k' is not an object"),
        statemod.peer_heads: ({"k": {"head": 5}}, "head is not a string"),
        statemod.config: (
            {"extensions": {"standing_denial": 1}},
            "extensions.standing_denial is not a boolean",
        ),
        statemod.replay_marker: ({"principals": [1]}, "principals is not a list of strings"),
        statemod.repair_intent: ({"step": "done"}, "not a repair intent"),
        statemod.cursor: ({"last_complete_fetch": 5}, "last_complete_fetch"),
        statemod.check_sidecar: (None, "last_checked"),
        statemod.seen_mail: ({"g1": None}, "note for 'g1' is not a string"),
        statemod.held_reply: ([], "not an object but a list"),
    }
    for shape, good in ok.items():
        assert shape(good) is None, shape.__name__
    for shape, (value, why) in bad.items():
        got = shape(value)
        assert got is not None and why in got, (shape.__name__, got)
    # round 15 (U3): a shortened or otherwise partial id is not this marker's identity
    for short in ("rpr_", "rpr_01ARZ3NDEKTSV4RRFFQ69G5F", "rpr_01ARZ3NDEKTSV4RRFFQ69G5FAVX", "i"):
        got = statemod.repair_intent({**ok[statemod.repair_intent], "intent_id": short})
        assert got is not None and "in full" in got and repr(short) in got, got
    assert statemod.seen({"m": {"ack": "x"}}) == "entry 'm': ack is not an object but a str"
    assert "neither" in statemod.seen({"m": {"status": "in_progress"}})
    for damaged in (
        {"status": "in_progress", "ts": TS},  # no grant id: the use would count for nothing
        {"status": "in_progress", "grant_id": [], "ts": TS},
        {"status": "done", "grant_id": uid("grt"), "ts": TS},
        {"status": "in_progress", "grant_id": uid("grt"), "ts": "nope"},
    ):
        assert "neither" in statemod.seen({"m": damaged}), damaged
    assert statemod.seen({"m": 5}) == "entry 'm' is not an object but a int"
    assert statemod.seen("x") == "not an object (msg_id -> entry) but a str"


def test_no_state_file_is_read_as_a_structure_except_through_the_typed_loader():
    """The guard: `read_json` (the untyped read) is called nowhere but inside the
    loader; the node, the CLI and the local wire parse no JSON of their own."""
    callers = []
    parsers = []
    for f in sorted(PKG.rglob("*.py")):
        text = f.read_text(encoding="utf-8")
        rel = f.relative_to(PKG).as_posix()
        if re.search(r"(?<![\w.])read_json\(", text) and rel not in ("durable.py", "state.py"):
            callers.append(rel)
        if ("json.load(" in text or "json.loads(" in text) and rel in (
            "node.py",
            "cli.py",
            "state.py",
            "adapters/local.py",
        ):
            parsers.append(rel)
    assert callers == [] and parsers == []


# ---- N2. the in-process wire validates an explicit ack before anything ------------------


def _local_pair(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    lw = LocalWire()
    lw.deliver(a, b, a.compose_card())
    lw.deliver(b, a, b.compose_card())
    a.mark_lookup_ok()
    b.mark_lookup_ok()
    return a, b, lw


def test_the_local_wire_validates_an_explicit_ack_before_recording_logging_or_delivering(
    tmp_path, monkeypatch
):
    """ORDERING: an explicit acknowledgement handed to `deliver` crosses the sender's
    outgoing boundary FIRST — cards holding an empty list, a damaged ack signature,
    an ack signed by another agent: reply.invalid, the receiver's receive never
    called, the log and both outboxes unchanged, nothing ledgered on either side. A
    sound explicit ack still delivers."""
    a, b, lw = _local_pair(tmp_path)
    m = a.compose_info(b.card, "hello")
    assert len(lw.deliver(a, b, m)) == 1 and a.outbox()[-1]["status"] == "acked"
    r, why = b.stored_reply(m["object"]["msg_id"])
    assert why is None
    log_before = list(lw.log)
    outboxes_before = (a.outbox(), b.outbox())
    ledgers_before = (len(a.ledger), len(b.ledger))
    received: list = []
    real_receive = a.receive
    monkeypatch.setattr(
        a, "receive", lambda bundle: received.append(bundle) or real_receive(bundle)
    )
    # the same ack re-issued by the OTHER agent (its key as from, its signature)
    by_a = ackmod.sign({**r["object"], "from": a.agent.public}, a.agent)
    for damaged in (
        {**r, "cards": [[]]},
        {**r, "object": {**r["object"], "sig": _flip(r["object"]["sig"])}},
        {**r, "object": by_a},
    ):
        with pytest.raises(IntegrityError) as e:
            lw.deliver(b, a, damaged)
        assert e.value.reason == "reply.invalid" and "nothing sent" in str(e.value)
    assert received == [] and lw.log == log_before
    assert (a.outbox(), b.outbox()) == outboxes_before
    assert (len(a.ledger), len(b.ledger)) == ledgers_before
    assert lw.deliver(b, a, r) == []  # the sound one: delivered, logged
    assert received == [r] and lw.log == log_before + [("b", "a", "ack")]
    assert len(a.ledger) == ledgers_before[0] + 1  # a's out.ack entry for the duplicate


# ---- N3. a storage failure at the final send is counted, never success -------------------


def _failing_inside_send(monkeypatch, failure: str):
    """Make the validation INSIDE `MailWire.send` fail (the second self-card read, or
    the second reply validation) while the validation before it passes: the exact
    window between the hold validation and the final send."""
    in_send = {"on": False}
    real_send = MailWire.send

    def send(self, b, **kw):
        in_send["on"] = True
        try:
            return real_send(self, b, **kw)
        finally:
            in_send["on"] = False

    monkeypatch.setattr(MailWire, "send", send)
    if failure == "reply.invalid":
        real_problem = Node.reply_problem

        def problem(self, r, msg_id, kind):
            if in_send["on"]:
                return "injected: the reply changed between the validation and the send"
            return real_problem(self, r, msg_id, kind)

        monkeypatch.setattr(Node, "reply_problem", problem)
        return
    real_card = Node._self_card

    def self_card(self):
        if in_send["on"]:
            p = self.state / SELF
            if failure == "card.self_corrupt":
                raise IntegrityError("card.self_corrupt", f"{p}: injected on the second read")
            raise OSError(5, "Input/output error", str(p))
        return real_card(self)

    monkeypatch.setattr(Node, "_self_card", self_card)


@pytest.mark.parametrize("failure", ["card.self_corrupt", "oserror", "reply.invalid"])
def test_a_storage_failure_at_the_final_send_of_a_held_reply_is_counted(
    tmp_path, monkeypatch, failure
):
    """The flush path: the hold validation passes, the validation inside the send
    fails (the self card on its second read — card.self_corrupt, an OSError — or the
    reply validation): the held reply stays, storage_failures 1, complete False,
    ZERO transport calls, the cursor unchanged; never the transport class. The
    failure gone, the next poll sends it."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    cursor_before = wb.cursor()
    assert cursor_before is not None
    clock.tick(5)  # a cursor rewrite would store a LATER value: the comparison is real
    inbox_before, sends_before = _inbox_len(fake), len(fake.sends)
    _failing_inside_send(monkeypatch, failure)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert len(fake.sends) == sends_before and _inbox_len(fake) == inbox_before
    assert p.exists() and wb._aside_replies() == [] and wb.cursor() == cursor_before
    token = {"oserror": "Input/output error"}.get(failure, failure)
    assert any(
        f"storage failure in the send of held reply {p.name}" in e and token in e
        for e in s["errors"]
    )
    assert not any("ack send failed" in e for e in s["errors"])
    assert "pending_reply.corrupt" not in _actions(b)
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and not p.exists()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("failure", ["card.self_corrupt", "oserror", "reply.invalid"])
def test_a_storage_failure_at_the_direct_send_is_counted_the_held_copy_kept(
    tmp_path, monkeypatch, failure
):
    """The same-poll path (after the hold and the seen mark): the validation before
    the direct send passes, the one inside the send fails — counted, the held copy
    kept (the obligation; the mail is seen by then), zero transport calls, complete
    False; the next poll's flush sends it."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    inbox_before, sends_before = _inbox_len(fake), len(fake.sends)
    _failing_inside_send(monkeypatch, failure)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert len(fake.sends) == sends_before and _inbox_len(fake) == inbox_before
    (held,) = wb._pending_replies()
    assert held.name == f"{msg_id}.ack.json" and wb._aside_replies() == []
    assert _unseen_mail_ids(fake, b, wb) == set()  # seen: the held copy is the obligation
    assert any(f"storage failure in the send of reply {held.name}" in e for e in s["errors"])
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and wb._pending_replies() == []
    (sent,) = _acks_out(fake, inbox_before)
    assert sent == seen_of(b)[msg_id]["ack"]
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_a_transport_failure_keeps_the_existing_accounting(tmp_path):
    """The transport class, as before: the send tool's non-zero exit leaves the held
    reply for the next poll, reported as a send failure, no storage count."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    fake.fail_sends = True
    s = wb.poll_once()
    fake.fail_sends = False
    assert s["applied"] == 1 and s["replies"] == 0 and s["storage_failures"] == 0
    assert any("ack send failed" in e for e in s["errors"])
    assert not any("storage failure in the send" in e for e in s["errors"])
    (held,) = wb._pending_replies()
    s = wb.poll_once()
    assert s["replies"] == 1 and not held.exists()


@pytest.mark.parametrize("cls", ["storage-worded-as-transport", "transport-worded-as-storage"])
def test_the_two_send_failure_classes_are_told_apart_by_type_never_by_text(
    tmp_path, monkeypatch, cls
):
    """A RuntimeError whose text talks like a storage failure is still the transport
    class; an IntegrityError whose text talks like the mail tool is still a storage
    failure: the type decides, the message never."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    if cls == "transport-worded-as-storage":
        exc: Exception = RuntimeError("IntegrityError: state.corrupt: storage failure reading")
    else:
        exc = IntegrityError("reply.invalid", "gmail-send.py failed rc=1: smtp: connection reset")

    def send(self, b, **kw):
        raise exc

    monkeypatch.setattr(MailWire, "send", send)
    s = wb.poll_once()
    assert s["replies"] == 0 and p.exists()
    if cls == "transport-worded-as-storage":
        assert s["storage_failures"] == 0 and any("ack send failed" in e for e in s["errors"])
    else:
        assert s["storage_failures"] == 1 and s["complete"] is False
        assert any("storage failure in the send of held reply" in e for e in s["errors"])
        assert not any("ack send failed" in e for e in s["errors"])


# ---- the self-gate's findings (one round; fixed inside N1 and N3) --------------------------


def _raw_ledger_line(node, **fields) -> None:
    """Append one raw JSONL line to the node's ledger, chained to its head (the line's
    OWN shape is what the test damages)."""
    e = {
        "ts": TS,
        "actor": "a",
        "grant_id": None,
        "action": "x",
        "params_hash": None,
        "outcome": "information",
        "prev_hash": node.ledger.head(),
        "msg_id": None,
        "detail": "",
        "direction": "in",
    }
    e.update(fields)
    with open(node.ledger.path, "ab") as f:
        f.write(json.dumps(e).encode() + b"\n")
    node.ledger._entries = None


@pytest.mark.parametrize(
    "damage", [{"outcome": []}, {"action": 5}, {"grant_id": {}}], ids=["outcome", "action", "grant"]
)
def test_a_ledger_line_whose_fields_are_not_their_type_is_ledger_corrupt_never_malformed(
    pair, damage
):
    """Self-gate 1 (ledger): an entry of ours whose read field is not its type is
    IntegrityError ledger.corrupt naming the line at the LOAD — the completion
    lookup, the head, the use count never reach an AttributeError; through receive
    it is a storage failure (nothing appended, never verify_failed:malformed)."""
    a, b, clock, reports = pair
    n = len(b.ledger)
    _raw_ledger_line(b, **damage)
    with pytest.raises(IntegrityError) as e:
        b.ledger.entries()
    assert e.value.reason == "ledger.corrupt" and f"line {n + 1}" in str(e.value)
    assert not isinstance(e.value, VerifyError)
    raw = b.ledger.path.read_bytes()
    with pytest.raises(StorageError) as se:
        b.receive(a.compose_info(b.card, "hello"))
    assert "ledger.corrupt" in str(se.value)
    assert b.ledger.path.read_bytes() == raw  # nothing appended, the damage untouched
    assert not (b.state / "seen.json").exists()  # nothing acked or reserved either


def test_a_feed_or_denial_line_that_is_not_its_object_is_corrupt_never_malformed(pair, capsys):
    """Self-gate 1 (the JSONL stores): a line of OUR feed or denial store holding an
    object that is not a revocation / a denial (here `{}`) is feed.corrupt /
    denial.corrupt naming the line at the load; through the authorization path the
    feed's is a storage failure (nothing ledgered, nothing written, the mail unseen);
    the verify verbs exit 2."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    with open(b.revocations.path, "ab") as f:
        f.write(b"{}\n")
    with pytest.raises(IntegrityError) as e:
        b.revocations.load()
    assert e.value.reason == "feed.corrupt" and "line 1" in str(e.value)
    assert "not a revocation" in str(e.value)
    before = len(b.ledger)
    with pytest.raises(StorageError) as se:
        b.receive(write_bundle(a, b, g, "f.txt"))
    assert "feed.corrupt" in str(se.value) and len(b.ledger) == before
    assert not (b.scratch_dir / "f.txt").exists()
    assert "verify_failed:malformed" not in _outcomes(b)
    assert main([*_argv(b), "feed", "verify"]) == 2
    assert "feed.corrupt" in capsys.readouterr().err
    with open(b.denials.path, "ab") as f:
        f.write(b'{"denial_id": "dny_x"}\n')
    with pytest.raises(IntegrityError) as e:
        b.denials.entries()
    assert e.value.reason == "denial.corrupt" and "not a denial" in str(e.value)
    assert main([*_argv(b), "denial", "verify"]) == 2
    assert "denial.corrupt" in capsys.readouterr().err


@pytest.mark.parametrize(
    "damage",
    [
        {"grant_id": "gone"},
        {"grant_id": []},
        {"status": "done"},
        {"ts": "not a time"},
    ],
    ids=["no-grant", "grant-list", "status", "ts"],
)
def test_a_malformed_reservation_never_releases_the_use_it_records(pair, damage):
    """Self-gate 2: a reservation IS a consumed use; one whose grant id, status or
    timestamp is not what `_reserve` writes is state.corrupt (the path named) at every
    read — the use is never counted as zero: the next action on that grant is a
    storage failure (nothing ledgered, nothing written), never authorized past the
    budget. A sound reservation counts as the one use it is."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "f.txt"),
        principal_statement=STATEMENT,
        max_uses=1,
    )
    reserved = uid("msg")
    b._reserve(reserved, g["grant_id"])  # an interrupted use: the budget is spent
    (r,) = b.receive(write_bundle(a, b, g, "f.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in b.ledger.entries()[-1]["detail"]  # the reservation counted
    assert not (b.scratch_dir / "f.txt").exists()
    seen = seen_of(b)
    entry = dict(seen[reserved])
    if damage.get("grant_id") == "gone":
        del entry["grant_id"]
    else:
        entry.update(damage)
    seen[reserved] = entry
    seen_path = b.state / "seen.json"
    seen_path.write_text(json.dumps(seen))
    raw = seen_path.read_bytes()
    before = len(b.ledger)
    with pytest.raises(StorageError) as se:
        b.receive(write_bundle(a, b, g, "g.txt"))
    assert isinstance(se.value, IntegrityError) and se.value.reason == "state.corrupt"
    assert str(seen_path) in str(se.value) and "reservation" in str(se.value)
    assert len(b.ledger) == before and not (b.scratch_dir / "g.txt").exists()
    assert seen_path.read_bytes() == raw
    with pytest.raises(IntegrityError):
        b.grant_uses(g, family=True)


@pytest.mark.parametrize(
    "damage", ["bundle-empty", "bundle-other-msg", "due-not-a-time", "status-unknown"]
)
def test_a_malformed_outbox_entry_is_never_transmitted_and_never_escapes_the_poll(tmp_path, damage):
    """Self-gate 3: an outbox entry whose bundle is not a message bundle bound to the
    entry, or whose deadline does not parse, or whose status is unknown, is
    state.corrupt at the outbox step (counted, the path named, nothing transmitted,
    no attempt spent, the file untouched) — never a VerifyError out of the poll,
    never a `{}` on the wire."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    other = a.compose_info(b.card, "another")
    outbox_path = a.state / "outbox.json"
    (entry,) = json.loads(outbox_path.read_text())
    if damage == "bundle-empty":
        entry["bundle"] = {}
    elif damage == "bundle-other-msg":
        entry["bundle"] = other  # a sound message bundle that is not this entry's
    elif damage == "due-not-a-time":
        entry["due"] = "not-a-time"
    else:
        entry["status"] = "sideways"
    outbox_path.write_text(json.dumps([entry]))
    raw = outbox_path.read_bytes()
    clock.tick(2 * a.poll_s + 1)
    sends_before = len(fake.sends)
    s = wa.poll_once()  # returns: the failure is contained, never a VerifyError out
    assert s["resent"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("reading the outbox" in e and "state.corrupt" in e for e in s["errors"])
    assert any(str(outbox_path) in e for e in s["errors"])
    assert len(fake.sends) == sends_before and outbox_path.read_bytes() == raw
    with pytest.raises(IntegrityError) as e:
        a.outbox_due()
    assert e.value.reason == "state.corrupt"


def test_a_storage_failure_re_sending_is_counted_the_entry_kept_the_cursor_frozen(
    tmp_path, monkeypatch
):
    """Self-gate 4: the outbox re-send classes its failures by type like a held
    reply's send: an OSError staging the wire body (ENOSPC) is a storage failure of
    the poll — counted, the entry kept with its attempt count, complete False, the
    cursor unchanged, nothing transmitted; the send tool's non-zero exit is the
    transport class as before (no count, no attempt spent)."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    clock.tick(2 * a.poll_s + 1)
    cursor_before = wa.cursor()
    assert cursor_before is not None
    sends_before = len(fake.sends)

    def no_space(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(mailmod.tempfile, "NamedTemporaryFile", no_space)
    s = wa.poll_once()
    assert s["resent"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any(f"storage failure re-sending {msg_id}" in e and "No space" in e for e in s["errors"])
    assert len(fake.sends) == sends_before and wa.cursor() == cursor_before
    assert a.outbox_entry(msg_id)["attempts"] == 1 and a.outbox_entry(msg_id)["status"] == "pending"
    monkeypatch.undo()
    fake.fail_sends = True
    s = wa.poll_once()  # the transport class: the existing accounting
    fake.fail_sends = False
    assert s["resent"] == 0 and s["storage_failures"] == 0
    assert any(f"re-send of {msg_id} failed" in e for e in s["errors"])
    assert a.outbox_entry(msg_id)["attempts"] == 1
    s = wa.poll_once()
    assert s["resent"] == 1 and a.outbox_entry(msg_id)["attempts"] == 2


def test_a_cleanup_failure_after_the_send_returned_is_reported_as_transmitted(
    tmp_path, monkeypatch
):
    """Self-gate 5: the staged wire body's removal fails AFTER the send tool
    returned: the ack DID leave the box; the failure is a storage failure of the poll
    (counted, the held copy kept, complete False) whose text says the send returned
    and names the gmail id — never "not transmitted"; the next poll sends the copy
    once more (harmless: the peer dedups on msg_id)."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    inbox_before = _inbox_len(fake)

    class NoRemoval(type(Path())):
        def unlink(self, missing_ok=False):
            raise OSError(5, "Input/output error", str(self))

    monkeypatch.setattr(mailmod, "Path", NoRemoval)
    s = wb.poll_once()
    monkeypatch.undo()
    assert _inbox_len(fake) == inbox_before + 1  # transmitted
    assert s["replies"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert p.exists()
    (err,) = [e for e in s["errors"] if f"in the send of held reply {p.name}" in e]
    assert "transmitted" in err and "could not be removed" in err and "gmail" in err
    assert "not transmitted" not in err
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and not p.exists()
    assert _inbox_len(fake) == inbox_before + 2  # the same ack once more; the peer dedups
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
