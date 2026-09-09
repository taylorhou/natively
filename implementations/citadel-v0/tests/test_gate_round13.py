"""Gate round 13 (hw-w4o7q): the twelfth cross-model gate report (3 MAJOR + 3 MINOR)
and the mayor's Fable read of round 12 (1 MAJOR, one head-anchor observation), one
ruling each.

S1  Every element of peer_addresses is validated at the typed load (a non-empty string,
    no whitespace, exactly one @, lower-cased on compare); anything else is state.corrupt
    naming the path and the index. The adapter never filters or coerces: the addresses
    are read inside the poll's storage boundary, a config that fails is a storage failure
    of the poll (nothing classified, nothing seen, the clock and the cursor unmoved), zero
    configured addresses is config.no_peers by name.
S2  ../gmail-api.py `thread --json`: a text part Gmail serves through body.attachmentId
    is fetched (messages.attachments.get); a body that cannot be obtained is an
    INCOMPLETE FETCH (truncated true, body "", body_unavailable naming why), never the
    snippet in the body field. The adapter treats such a row like a cut one: the mail
    unseen, nothing ledgered, the fetch incomplete, the retry applies. The plain-text
    output never fetches and is byte-identical (the cmp is in the READY mail).
S3  ONE Unicode-aware blank-line predicate (durable.is_blank_line / is_blank_text: Zs,
    Zl, Zp, Cc, Cf; a line that does not decode is never blank) in every reader of the
    three stores and the mirror: U+00A0, U+2003, U+202F, U+200B, U+FEFF lines are
    corruption by name, never torn, never cut.
S4  The whole proposed cut of an undecodable mirror tail is checked before any mutation:
    a blank physical line anywhere in it is ledger.repair.refused, the mirror untouched.
S5  Under a standing intent a decodable prose line torn after an ASCII prefix — a strict
    prefix of its entry's regenerated line — is regenerated (the lines before it
    validated); one that is not such a prefix is ledger.prose.mismatch, the marker
    standing, nothing written.
S6  The newline matrix (every torn-tail and blank-line test with and without the
    terminating newline where meaningful) and real failure injection: the durable
    writer's directory barrier raising after the bytes are visible at EVERY step of the
    nested stage and of the ledger's own tail stage, each followed by a resume that
    completes and a verify that exits 0.
S7  The ledger's tail is anchored to the acks this node stored: every stored ack's
    ledger_head must be the hash of an entry present in the chain as loaded
    (ledger.head.mismatch naming the ack's msg_id, a storage failure) — in
    check_intact (every receive, the pin) and in verify (the verb).
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively import state as statemod
from natively.adapters.mail import WIRE_CHARS, parse_thread_json
from natively.cli import main
from natively.durable import is_blank_line, is_blank_text, physical_lines
from natively.errors import IntegrityError, VerifyError
from natively.ledger import entry_hash, prose_line
from natively.node import LEDGER_TAIL_MARKER, Node

from .conftest import Clock, make_node
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv
from .test_gate_round7b import _acks_out, _actions, _inbox_len
from .test_gate_round8 import _unseen_mail_ids
from .test_gate_round10 import _with_history_over_mail
from .test_gate_round11 import _pin_refuses, _revoked_grant_over_mail
from .test_gate_round12 import (
    _denied_write_over_mail,
    _edit_last_completion,
    _mirror_repair_at_truncated,
    _one_use_applied_over_mail,
    _serialize,
    _storage_failure_poll,
    _torn_audit,
)
from .test_hardening import STATEMENT, fs_write_scope, write_bundle

PKG = Path(__file__).resolve().parents[1]
GMAIL_API = PKG.parent / "gmail-api.py"
NEWLINE = pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
# the code points the gate named, each a Unicode blank bytes.strip() does not know
BLANKS = {
    "U+00A0": "\u00a0",
    "U+2003": "\u2003",
    "U+202F": "\u202f",
    "U+200B": "\u200b",
    "U+FEFF": "\ufeff",
}
PEER = "taylor@houmanoids.com"  # a's address, the one b reads from
TORN_ENTRY = b'{"ts": "2026-09-07T07:00:00Z", "actor": "'  # an append torn before its newline


def _blank_bytes(cp: str) -> bytes:
    return (cp * 4).encode("utf-8")


def _write_config(node: Node, **fields) -> Path:
    """config.json written RAW (json.dumps, not the node's save), so a value of any
    shape lands in the file."""
    p = node.state / "config.json"
    p.write_text(json.dumps({**node.config, **fields}), encoding="utf-8")
    return p


def _unmoved(b, wb) -> tuple:
    """What a storage failure of the poll must leave exactly as it was."""
    return (
        b.revocations.last_checked(),
        wb.cursor(),
        b.ledger.path.read_bytes() if b.ledger.path.exists() else None,
        sorted(wb._seen()),
    )


# ---- S1. peer addresses validated at the typed load (FAILURE BEFORE) -------------------------


BAD_ADDRESSES = {
    "object": {},
    "number": 5,
    "empty": "",
    "space": "taylor @houmanoids.com",
    "nbsp": "taylor@houmanoids.com\u00a0",
    "no-at": "taylor.houmanoids.com",
    "two-at": "taylor@@houmanoids.com",
}


@pytest.mark.parametrize("bad", list(BAD_ADDRESSES), ids=list(BAD_ADDRESSES))
def test_a_peer_address_that_is_not_an_address_is_a_storage_failure_of_the_poll(tmp_path, bad):
    """S1: the peer address replaced with {}, a number, an empty string or a string
    carrying whitespace (or not one address): the typed load names the path and the
    index (state.corrupt); the poll is a storage failure — nothing classified (no
    ignored:sender), the peer's mail unseen, nothing ledgered, the freshness clock
    and the cursor unchanged, the outbox still run; the adapter filters nothing; a
    fresh node refuses to construct; the config restored, the same mail is read and
    applied."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "p.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "p.txt"))
    value = BAD_ADDRESSES[bad]
    assert statemod.address(value, "peer_addresses[0]") is not None
    cfg = _write_config(b, peer_addresses=[value])
    why = statemod.config(json.loads(cfg.read_text()))
    assert why is not None and "peer_addresses[0]" in why
    with pytest.raises(IntegrityError) as e:
        wb.peer_addresses()
    assert e.value.reason == "state.corrupt" and str(cfg) in str(e.value)
    assert "peer_addresses[0]" in str(e.value)
    with pytest.raises(IntegrityError) as e:  # a fresh node on that state
        Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert e.value.reason == "state.corrupt" and "peer_addresses[0]" in str(e.value)
    before = _unmoved(b, wb)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert s["ignored"] == 0 and s["fetched"] == 0
    assert any(
        "state.corrupt" in x and str(cfg) in x and "peer_addresses[0]" in x for x in s["errors"]
    )
    assert _unmoved(b, wb) == before and _inbox_len(fake) == inbox_before
    assert len(_unseen_mail_ids(fake, b, wb)) == 1
    assert not any(v.startswith("ignored") for v in wb._seen().values())
    assert not (b.scratch_dir / "p.txt").exists()
    b.save_config()  # the config restored
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["applied"] == 1
    assert (b.scratch_dir / "p.txt").read_text() == "x\n"
    assert _unseen_mail_ids(fake, b, wb) == set()


def test_a_config_with_no_peer_address_refuses_by_name_rather_than_ignoring_everything(
    tmp_path,
):
    """S1: the list emptied is a valid shape at the load (the CLI writes it) but the
    poll refuses by name (config.no_peers): a storage failure, nothing classified as
    ignored, the mail unseen, the clock and the cursor unchanged; the list restored,
    the mail applies."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "anyone?"))
    cfg = _write_config(b, peer_addresses=[])
    assert statemod.config(json.loads(cfg.read_text())) is None
    with pytest.raises(IntegrityError) as e:
        wb.peer_addresses()
    assert e.value.reason == "config.no_peers" and str(cfg) in str(e.value)
    before = _unmoved(b, wb)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert s["ignored"] == 0 and any("config.no_peers" in x for x in s["errors"])
    assert _unmoved(b, wb) == before and len(_unseen_mail_ids(fake, b, wb)) == 1
    assert not any(v.startswith("ignored") for v in wb._seen().values())
    b.save_config()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and s["replies"] == 1


def test_peer_addresses_are_compared_lower_cased_and_never_filtered():
    """S1: the shape names the element it refuses; a mixed-case address is an
    address (compared lower-cased); no element is ever dropped silently."""
    for value in BAD_ADDRESSES.values():
        why = statemod.config({"peer_addresses": ["ok@x.y", value]})
        assert why is not None and "peer_addresses[1]" in why, value
    assert statemod.config({"peer_addresses": ["Taylor@HOUMANOIDS.com"]}) is None
    assert statemod.address("a@b", "x") is None
    assert "whitespace" in statemod.address("a@b\u200b", "x")
    assert (
        "isinstance"
        not in Path(PKG / "natively/adapters/mail.py")
        .read_text()
        .split("def peer_addresses")[1]
        .split("def ")[0]
    )


def test_a_mixed_case_peer_address_reads_the_mail(tmp_path):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    _write_config(b, peer_addresses=["Taylor@HOUMANOIDS.com"])
    assert wb.peer_addresses() == {PEER}
    wa.send(a.compose_info(b.card, "case"))
    assert wb.poll_once()["applied"] == 1


# ---- S2. attachment-backed Gmail bodies (FAILURE BEFORE) -------------------------------------


def _gmail_api():
    spec = importlib.util.spec_from_file_location("gmail_api_under_test", GMAIL_API)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _gmail_message(gid: str, wire_text: str, *, inline: bool, extra_parts=()) -> dict:
    """A Gmail message as `messages.get(format=full)` returns it: the text/plain part
    inline (body.data) or served through an attachment id (no data)."""
    part = {"partId": "0", "mimeType": "text/plain", "filename": ""}
    if inline:
        part["body"] = {"size": len(wire_text), "data": _b64url(wire_text)}
    else:
        part["body"] = {"size": len(wire_text), "attachmentId": "ANGjdJ8_att_" + gid}
    return {
        "id": gid,
        "threadId": "t1",
        "labelIds": ["INBOX"],
        "snippet": " ".join(wire_text.split())[:200],
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "Date", "value": "Mon, 7 Sep 2026 00:01:00 -0700"},
                {"name": "From", "value": f"Citadel <{PEER}>"},
                {"name": "To", "value": "taylor@teale.com"},
                {"name": "Subject", "value": "Natively v0 wire"},
            ],
            "parts": [part, *extra_parts],
        },
    }


def _wire_text(a, b, text: str) -> str:
    return bundlemod.encode(a.compose_info(b.card, text))


def test_an_attachment_backed_body_is_fetched_and_the_bundle_applied(tmp_path):
    """S2: the text/plain part carries attachmentId; the fetch succeeds: the row's
    body is the decoded text, truncated false, no body_unavailable; injected into
    the wire, the bundle applies. A message with the body inline is unchanged."""
    api = _gmail_api()
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wire = _wire_text(a, b, "attached")
    m = _gmail_message("g-att", wire, inline=False)
    fetched: list[str] = []

    def fetch(att):
        fetched.append(att)
        return _b64url(wire)

    row = api.msg_row(m, WIRE_CHARS, fetch)
    assert fetched == ["ANGjdJ8_att_g-att"]
    assert row["body"] == wire.strip() and row["truncated"] is False
    assert "body_unavailable" not in row and row["snippet"] == m["snippet"]
    assert row["from"] == f"Citadel <{PEER}>" and row["subject"] == "Natively v0 wire"
    inline = api.msg_row(_gmail_message("g-inl", wire, inline=True), WIRE_CHARS, fetch)
    assert fetched == ["ANGjdJ8_att_g-att"]  # inline data is never fetched
    assert inline["body"] == wire.strip() and inline["truncated"] is False
    assert {k: v for k, v in inline.items() if k not in ("id", "snippet")} == {
        k: v for k, v in row.items() if k not in ("id", "snippet")
    }
    (mail,) = parse_thread_json(json.dumps([row]))
    assert mail.body == wire.strip() and mail.truncated is False and mail.unavailable == ""
    fake.inbox.setdefault("taylor@teale.com", []).append(row)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and s["replies"] == 1
    assert b.ledger.entries()[-1]["detail"] == "attached"


@pytest.mark.parametrize("failure", ["raises", "no-data", "undecodable"])
def test_a_body_that_cannot_be_obtained_is_an_incomplete_fetch_never_the_snippet(tmp_path, failure):
    """S2: the attachment fetch fails (an API error, an attachment without data, data
    that does not decode): the row is truncated true with body "" and
    body_unavailable naming the attachment — never the snippet in the body field.
    The adapter leaves the mail unseen, ledgers nothing, counts an incomplete fetch
    and advances neither freshness nor the cursor; the retry after the helper
    returns the body applies."""
    api = _gmail_api()
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wire = _wire_text(a, b, "revoke me")
    m = _gmail_message("g-bad", wire, inline=False)

    def fetch(att):
        if failure == "raises":
            raise RuntimeError("HTTP Error 404: Not Found")
        return None if failure == "no-data" else "A"

    row = api.msg_row(m, WIRE_CHARS, fetch)
    assert row["body"] == "" and row["truncated"] is True
    assert "ANGjdJ8_att_g-bad" in row["body_unavailable"] and row["snippet"] == m["snippet"]
    assert "X-Natively" not in row["body"]
    (mail,) = parse_thread_json(json.dumps([row]))
    assert mail.truncated is True and mail.body == "" and "att_g-bad" in mail.unavailable
    # the flag alone (an older helper's row without truncated) is enough
    (mail2,) = parse_thread_json(json.dumps([{**row, "truncated": False}]))
    assert mail2.truncated is True
    fake.inbox.setdefault("taylor@teale.com", []).append(row)
    before = _unmoved(b, wb)
    entries = len(b.ledger.entries())
    s = wb.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and s["storage_failures"] == 0
    assert any("could not be obtained" in x and "g-bad" in x for x in s["errors"])
    assert _unmoved(b, wb) == before and len(b.ledger.entries()) == entries
    assert _unseen_mail_ids(fake, b, wb) == {"g-bad"}
    assert "undecodable" not in json.dumps(wb._seen())
    # the helper returns the body next poll: the same mail applies
    good = api.msg_row(m, WIRE_CHARS, lambda att: _b64url(wire))
    fake.inbox["taylor@teale.com"][-1] = good
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert b.ledger.entries()[-1]["detail"] == "revoke me"


def test_the_plain_text_output_never_fetches_and_an_unavailable_part_never_falls_through():
    """S2: without a fetcher (the text dump) an attachment-backed part yields nothing,
    exactly as before, and the fetcher is never called; with one, a text part that
    cannot be obtained is raised through even when an html part follows (a shorter
    or different body is not the body)."""
    api = _gmail_api()
    wire = "X-Natively: v0\nAAAA\n"
    calls: list[str] = []

    def fetch(att):
        calls.append(att)
        raise RuntimeError("nope")

    m = _gmail_message("g-plain", wire, inline=False)
    assert api.body_of(m["payload"]) == "" and calls == []
    html = {"mimeType": "text/html", "body": {"data": _b64url("<p>other</p>")}}
    m2 = _gmail_message("g-mixed", wire, inline=False, extra_parts=(html,))
    assert api.body_of(m2["payload"]) == "other" and calls == []  # the text dump, unchanged
    with pytest.raises(api.BodyUnavailable):
        api.body_of(m2["payload"], fetch)
    assert calls == ["ANGjdJ8_att_g-mixed"]
    assert "body_unavailable" in api.msg_row(m2, 3000, fetch)
    # a message with no text part at all has no body and is not an unavailable one
    empty = {"id": "g-none", "snippet": "hi", "payload": {"mimeType": "text/calendar", "body": {}}}
    row = api.msg_row(empty, 3000, fetch)
    assert row["body"] == "" and row["truncated"] is False and row["snippet"] == "hi"


# ---- S3. a Unicode-aware blank-line rule in every reader (FAILURE BEFORE) --------------------


def test_the_blank_line_predicate_is_unicode_aware_and_never_blank_for_undecodable_bytes():
    """S3: the ONE predicate: empty, ASCII whitespace and every named code point are
    blank (bytes and text alike); a line with any other character is not; a line
    that does not decode as UTF-8 is never blank; physical_lines names such a line."""
    assert is_blank_line(b"") and is_blank_text("") and is_blank_line(b"  \t\r")
    for name, cp in BLANKS.items():
        assert is_blank_line(_blank_bytes(cp)), name
        assert is_blank_line((" " + cp + " ").encode("utf-8")), name
        assert is_blank_text(cp * 3) and not is_blank_text(cp + "x"), name
        assert not is_blank_line((cp + "{").encode("utf-8")), name
        p = Path("/x/store.jsonl")
        for data, line in (
            (b"{}\n" + _blank_bytes(cp) + b"\n", 2),
            (b"{}\n" + _blank_bytes(cp), 2),
            (_blank_bytes(cp) + b"\n{}\n", 1),
        ):
            with pytest.raises(IntegrityError) as e:
                list(physical_lines(data, p, "store.corrupt"))
            assert e.value.reason == "store.corrupt" and f"line {line}" in str(e.value), name
    assert not is_blank_line(b"\xff") and not is_blank_line(b" \xff ")
    assert not is_blank_line(b"\xe2\x80")  # a blank torn inside its own encoding
    assert list(physical_lines(b"{}\n\xff\n", Path("/x"), "r")) == [(1, b"{}"), (2, b"\xff")]


def _blank_store(sound: bytes, where: str, terminated: bool, blank: bytes) -> tuple[bytes, int]:
    if where == "record":
        return blank + (b"\n" if terminated else b""), 1
    return sound + blank + (b"\n" if terminated else b""), sound.count(b"\n") + 1


def _repair_refuses_by_name(n, capsys, store: str, path: Path, data: bytes, line: int) -> None:
    """The repair verb refuses by the store's corrupt name (never torn / truncated),
    naming the line, with the file untouched and no intent and no audit (for the
    ledger the file byte-identical IS no audit: the ledger is the corrupt store)."""
    audits = None if store == "ledger" else _actions(n).count(f"{store}.repaired")
    assert main([*_argv(n), store, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{store}.corrupt" in err and f"line {line}" in err and str(path) in err
    assert f"{store}.torn" not in err and "ledger.truncated" not in err and "terminated" not in err
    assert path.read_bytes() == data and not (n.state / f"{store}-repair-pending.json").exists()
    if audits is not None:
        assert _actions(n).count(f"{store}.repaired") == audits


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
@pytest.mark.parametrize("cp", list(BLANKS), ids=list(BLANKS))
def test_a_unicode_blank_in_the_feed_is_corruption_never_a_torn_tail(
    tmp_path, capsys, cp, where, terminated
):
    """S3, the feed: the signed revocation replaced with a Unicode blank line, or one
    after it, with and without the newline: feed.corrupt by name at every reader
    (never feed.torn), torn_tail cuts nothing (it raises), repair refuses by name
    with the file untouched, the action it forbids is a storage failure; restored,
    the retry is refused as revoked."""
    a, b, wa, wb, fake, clock, rec = _revoked_grant_over_mail(tmp_path)
    feed = b.revocations.path
    original = feed.read_bytes()
    blank, line = _blank_store(original, where, terminated, _blank_bytes(BLANKS[cp]))
    feed.write_bytes(blank)
    for read in (b.revocations.entries, b.revocations.torn_tail, b.revocations.load):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "feed.corrupt" and not isinstance(e.value, VerifyError)
        assert str(feed) in str(e.value) and f"line {line}" in str(e.value)
    _storage_failure_poll(b, wb, fake, feed, "feed.corrupt", line, "r.txt")
    assert main([*_argv(b), "feed", "verify"]) == 2
    assert "feed.corrupt" in capsys.readouterr().err
    _pin_refuses(b, capsys, "feed.corrupt", feed)
    _repair_refuses_by_name(b, capsys, "feed", feed, blank, line)
    feed.write_bytes(original)
    assert main([*_argv(b), "feed", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in b.ledger.entries()[-1]["detail"]
    assert not (b.scratch_dir / "r.txt").exists()


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
@pytest.mark.parametrize("cp", list(BLANKS), ids=list(BLANKS))
def test_a_unicode_blank_in_the_denial_store_is_corruption_never_a_torn_tail(
    tmp_path, capsys, cp, where, terminated
):
    """S3, the denial store: the same shape, denial.corrupt by name; restored, the
    retry is refused as denied."""
    a, b, wa, wb, fake, clock, rec = _denied_write_over_mail(tmp_path)
    store = b.denials.path
    original = store.read_bytes()
    blank, line = _blank_store(original, where, terminated, _blank_bytes(BLANKS[cp]))
    store.write_bytes(blank)
    for read in (b.denials.entries, b.denials.torn_tail, b.denials.load):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "denial.corrupt" and not isinstance(e.value, VerifyError)
        assert str(store) in str(e.value) and f"line {line}" in str(e.value)
    _storage_failure_poll(b, wb, fake, store, "denial.corrupt", line, "d.txt")
    assert main([*_argv(b), "denial", "verify"]) == 2
    assert "denial.corrupt" in capsys.readouterr().err
    _pin_refuses(b, capsys, "denial.corrupt", store)
    _repair_refuses_by_name(b, capsys, "denial", store, blank, line)
    store.write_bytes(original)
    assert main([*_argv(b), "denial", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:denied"
    assert not (b.scratch_dir / "d.txt").exists()


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
@pytest.mark.parametrize("cp", list(BLANKS), ids=list(BLANKS))
def test_a_unicode_blank_in_the_ledger_is_corruption_never_a_free_use(
    tmp_path, capsys, cp, where, terminated
):
    """S3, the ledger: the applied completion of a one-use grant replaced with a
    Unicode blank line, or one after it: ledger.corrupt at every reader (never
    ledger.truncated, never terminated), the second use a storage failure with the
    executor never called, repair refuses by name with both files untouched;
    restored, the retry is refused as used up."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = whole.split(b"\n")[:-1]
    blank_line = _blank_bytes(BLANKS[cp])
    if where == "record":
        line = len(lines)
        blank = b"\n".join([*lines[:-1], blank_line]) + (b"\n" if terminated else b"")
    else:
        line = len(lines) + 1
        blank = whole + blank_line + (b"\n" if terminated else b"")
    jsonl.write_bytes(blank)
    readers = [
        b.ledger.entries,
        b.ledger.check_intact,
        b.ledger.verify,
        b.ledger.torn_tail,
        lambda: b.ledger.check_prefix(len(blank)),
    ]
    if not terminated:
        readers.append(b.ledger.terminate_tail)
    for read in readers:
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "ledger.corrupt" and not isinstance(e.value, VerifyError)
        assert str(jsonl) in str(e.value) and f"line {line}" in str(e.value)
    if terminated:
        assert b.ledger.terminate_tail() is False
    assert jsonl.read_bytes() == blank
    _storage_failure_poll(b, wb, fake, jsonl, "ledger.corrupt", line, "never.txt")
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
    assert not any("ledger.truncated" in x for x in wb.poll_once()["errors"])
    assert main([*_argv(b), "ledger", "verify"]) == 2
    assert "ledger.corrupt" in capsys.readouterr().err
    _pin_refuses(b, capsys, "ledger.corrupt", jsonl)
    _repair_refuses_by_name(b, capsys, "ledger", jsonl, blank, line)
    assert mirror.read_bytes() == prose
    jsonl.write_bytes(whole)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in b.ledger.entries()[-1]["detail"]
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"


@pytest.mark.parametrize("cp", list(BLANKS), ids=list(BLANKS))
def test_a_unicode_blank_line_in_the_prose_mirror_is_a_mismatch_by_name(tmp_path, capsys, cp):
    """S3, the mirror: a Unicode blank line in place of the last prose line, beyond
    the entries, or as an unterminated tail is ledger.prose.mismatch at the receive
    and ledger.repair.refused at repair (never an excess line to cut)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = prose.split(b"\n")[:-1]
    blank = _blank_bytes(BLANKS[cp])
    blank_last = b"\n".join([*lines[:-1], blank]) + b"\n"
    for damaged in (blank_last, blank_last[:-1], prose + blank + b"\n", prose + blank):
        mirror.write_bytes(damaged)
        with pytest.raises(IntegrityError) as e:
            b.ledger.check_intact()
        assert e.value.reason == "ledger.prose.mismatch"
        if damaged not in (blank_last, blank_last[:-1]):
            with pytest.raises(IntegrityError) as e:  # beyond the entries: never excess to cut
                b.ledger.excess_prose()
            assert e.value.reason == "ledger.repair.refused"
        s = wb.poll_once()
        assert s["storage_failures"] == 1 and s["applied"] == 0
        assert main([*_argv(b), "ledger", "repair"]) == 2
        assert "ledger.repair.refused" in capsys.readouterr().err
        assert mirror.read_bytes() == damaged and jsonl.read_bytes() == whole
        assert _actions(b).count("ledger.mirror_truncated") == 0
        mirror.write_bytes(prose)
    assert wb.poll_once()["applied"] == 1


# ---- S4. the whole proposed cut is checked before any mutation (FAILURE BEFORE) --------------


@NEWLINE
@pytest.mark.parametrize("blank", ["ascii", "U+00A0"])
def test_an_undecodable_prose_line_never_hides_a_blank_line_from_the_repair(
    tmp_path, capsys, blank, terminated
):
    """S4: sound prose, then an undecodable line, then a whitespace-only line (with
    and without its newline): excess_prose and cut_undecodable_tail refuse by name
    (ledger.repair.refused naming the blank line), the repair verb exits 2 with the
    mirror untouched, no intent, no audit; without the blank line the undecodable
    line alone is the excess and the repair completes with one mirror audit."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    entries = len(b.ledger.entries())
    blank_bytes = b"   " if blank == "ascii" else _blank_bytes(BLANKS[blank])
    damaged = prose + b"\xff\n" + blank_bytes + (b"\n" if terminated else b"")
    mirror.write_bytes(damaged)
    for read in (b.ledger.excess_prose, b.ledger.cut_undecodable_tail):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "ledger.repair.refused" and str(mirror) in str(e.value)
        assert f"prose line {entries + 1} is blank" in str(e.value)
        assert mirror.read_bytes() == damaged
    with pytest.raises(IntegrityError) as e:
        b.ledger.check_intact()
    assert e.value.reason == "ledger.mirror_corrupt"
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.repair.refused" in err and f"prose line {entries + 1}" in err
    assert mirror.read_bytes() == damaged and jsonl.read_bytes() == whole
    assert not (b.state / "ledger-repair-pending.json").exists()
    assert _actions(b).count("ledger.mirror_truncated") == 0
    # the same fixture without the blank line: the undecodable line alone is the excess
    mirror.write_bytes(prose + b"\xff\n")
    assert b.ledger.excess_prose() == b"\xff\n"
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert _actions(b).count("ledger.mirror_truncated") == 1
    assert main([*_argv(b), "ledger", "verify"]) == 0
    wa.send(a.compose_info(b.card, "after"))
    assert wb.poll_once()["applied"] == 1


# ---- S5. a torn prose write under an intent regenerated (FAILURE AFTER, RESTART RECOVERY) ----


def _tear_prose_write(monkeypatch, ledger, audit_action: str, keep: int = 20) -> dict:
    """Power loss inside the REAL prose write of the audit named: the durable writer
    writes only the first `keep` bytes (an ASCII prefix: the timestamp) so they are
    visible, then raises. Returns a box counting the tear."""
    import natively.ledger as ledgermod

    real = ledgermod.append_lines
    box = {"torn": 0}

    def append_lines(p, lines):
        if p == ledger.prose_path and any(audit_action in ln for ln in lines):
            data = "".join(ln + "\n" for ln in lines).encode("utf-8")[:keep]
            assert data.isascii()
            with open(p, "ab") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            box["torn"] += 1
            raise OSError(5, "Input/output error (power loss inside the prose write)")
        return real(p, lines)

    monkeypatch.setattr(ledgermod, "append_lines", append_lines)
    return box


def _nested_stage(tmp_path):
    """The double fault: a mirror intent at step "truncated" whose audit append tore
    the JSONL's tail (round 12). Returns (b, the mirror marker)."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    _torn_audit(b, intent, "inside")
    return b, marker


def _own_stage(tmp_path):
    """A torn partial last line of the JSONL, no intent standing. Returns (b, None)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    with open(b.ledger.path, "ab") as f:
        f.write(TORN_ENTRY)
    return b, None


def _mirror_stage(tmp_path):
    """A mirror intent at step "truncated", the JSONL whole. Returns (b, the marker)."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    return b, marker


STAGES = {
    "nested": (
        _nested_stage,
        "ledger.tail_truncated",
        {"ledger.tail_truncated": 1, "ledger.mirror_truncated": 1},
    ),
    "own": (
        _own_stage,
        "ledger.tail_truncated",
        {"ledger.tail_truncated": 1, "ledger.mirror_truncated": 0},
    ),
    "mirror": (
        _mirror_stage,
        "ledger.mirror_truncated",
        {"ledger.tail_truncated": 0, "ledger.mirror_truncated": 1},
    ),
}


def _no_markers(b) -> bool:
    return (
        not (b.state / "ledger-repair-pending.json").exists()
        and not (b.state / LEDGER_TAIL_MARKER).exists()
    )


@pytest.mark.parametrize("stage", list(STAGES), ids=list(STAGES))
def test_a_prose_write_torn_after_an_ascii_prefix_is_regenerated_on_the_first_resume(
    tmp_path, capsys, monkeypatch, stage
):
    """S5, FAILURE AFTER: power loss injected into the real prose write of the
    stage's audit after an ASCII prefix (the durable writer raising after the
    partial bytes are visible): the run fails, the marker stands at "truncated"
    with the partial line on the mirror; the FIRST resume regenerates the line,
    completes, verify exits 0, exactly the stage's audits, every marker gone."""
    fixture, audit_action, audits = STAGES[stage]
    b, _marker = fixture(tmp_path)
    box = _tear_prose_write(monkeypatch, b.ledger, audit_action)
    assert main([*_argv(b), "ledger", "repair"]) == 1  # the OSError, one line
    capsys.readouterr()
    assert box["torn"] == 1
    prose = b.ledger.prose_path.read_bytes()
    tail = prose[prose.rfind(b"\n") + 1 :]  # the 20 ASCII bytes of the timestamp, no newline
    assert len(tail) == 20 and re.fullmatch(rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", tail)
    marker_file = b.state / (
        "ledger-repair-pending.json" if stage != "nested" else LEDGER_TAIL_MARKER
    )
    assert json.loads(marker_file.read_text())["step"] == "truncated"
    monkeypatch.undo()
    with pytest.raises(IntegrityError) as e:  # nothing appends while a marker stands
        b.receive(b.compose_card())
    assert e.value.reason == "ledger.repair_pending"
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert "regenerated" in out or "repaired" in out
    assert _no_markers(b)
    for action, n in audits.items():
        assert _actions(b).count(action) == n, action
    assert main([*_argv(b), "ledger", "verify"]) == 0
    assert b.ledger.prose_path.read_bytes().endswith(b"]\n")
    assert main([*_argv(b), "ledger", "repair"]) == 0  # idempotent
    for action, n in audits.items():
        assert _actions(b).count(action) == n, action


@pytest.mark.parametrize("stage", list(STAGES), ids=list(STAGES))
def test_an_unterminated_prose_line_that_is_not_a_prefix_is_refused_with_the_marker_standing(
    tmp_path, capsys, monkeypatch, stage
):
    """S5: the same crash, then the partial line replaced by bytes that are not a
    prefix of the expected line (or a blank one): the resume is
    ledger.prose.mismatch by name, every marker standing, both files
    byte-identical; the partial line put back, the resume completes."""
    fixture, audit_action, audits = STAGES[stage]
    b, _marker = fixture(tmp_path)
    _tear_prose_write(monkeypatch, b.ledger, audit_action)
    assert main([*_argv(b), "ledger", "repair"]) == 1
    capsys.readouterr()
    monkeypatch.undo()
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, torn = jsonl.read_bytes(), mirror.read_bytes()
    head = torn[: torn.rfind(b"\n") + 1]
    markers = {p: p.read_bytes() for p in b.state.glob("ledger-repair-pending*.json")}
    assert markers
    for bad in (head + b"zzz", head + b"2026-09-07T07:00:00Z  nobody:", head + b"\xc2\xa0\xc2\xa0"):
        mirror.write_bytes(bad)
        with pytest.raises(IntegrityError) as e:
            b.ledger.mend_torn_prose_tail()
        assert e.value.reason == "ledger.prose.mismatch" and str(mirror) in str(e.value)
        assert main([*_argv(b), "ledger", "repair"]) == 2
        assert "ledger.prose.mismatch" in capsys.readouterr().err
        assert mirror.read_bytes() == bad and jsonl.read_bytes() == whole
        assert {p: p.read_bytes() for p in b.state.glob("ledger-repair-pending*.json")} == markers
    mirror.write_bytes(torn)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0
    for action, n in audits.items():
        assert _actions(b).count(action) == n, action


def test_the_mend_regenerates_only_a_strict_prefix_of_the_entry_at_its_index(tmp_path):
    """S5, the method: a mirror ending in its newline or in a whole line short of
    only its newline is left to the barrier (0 written); a strict non-blank prefix of
    the line at its index — the last entry's, or an earlier one's when the
    regeneration of several lines tore — is completed durably; a prefix beyond the
    entries, a mismatching earlier line, or a blank partial line is refused."""
    n = make_node(tmp_path, "n", Clock())
    for text in ("one", "two", "three"):
        n.ledger.append(
            ts=n.ts(),
            actor="n",
            grant_id=None,
            action="s",
            params_hash=None,
            outcome="information",
            detail=text,
        )
    es = n.ledger.entries()
    mirror = n.ledger.prose_path
    whole = mirror.read_bytes()
    assert n.ledger.mend_torn_prose_tail() == 0 and mirror.read_bytes() == whole
    lines = whole.split(b"\n")[:-1]
    mirror.write_bytes(whole[:-1])  # short of only its newline
    assert n.ledger.mend_torn_prose_tail() == 0 and mirror.read_bytes() == whole[:-1]
    # the last line torn after its timestamp
    mirror.write_bytes(b"\n".join(lines[:-1]) + b"\n" + lines[-1][:20])
    assert n.ledger.mend_torn_prose_tail() == len(lines[-1]) - 20 + 1
    assert mirror.read_bytes() == whole and n.ledger.verify()
    # a regeneration of several lines torn inside the SECOND line: entry 1's prefix
    mirror.write_bytes(lines[0] + b"\n" + lines[1][:25])
    assert n.ledger.mend_torn_prose_tail() == len(lines[1]) - 25 + 1
    assert mirror.read_bytes() == b"\n".join(lines[:2]) + b"\n"
    assert n.ledger.repair() == 1 and mirror.read_bytes() == whole
    for bad, reason in (
        (whole + b"2026", "ledger.prose.mismatch"),  # beyond the entries
        (lines[0] + b"\n" + b"\xc2\xa0", "ledger.prose.mismatch"),  # a blank partial line
        (lines[0] + b"\n" + lines[2][:-3], "ledger.prose.mismatch"),  # not entry 1's prefix
        (lines[1] + b"\n" + lines[1][:25], "ledger.repair.refused"),  # line 0 is not entry 0's
    ):
        mirror.write_bytes(bad)
        with pytest.raises(IntegrityError) as e:
            n.ledger.mend_torn_prose_tail()
        assert e.value.reason == reason, bad
        assert mirror.read_bytes() == bad
    assert prose_line(es[0], entry_hash(es[0])).encode() == lines[0]


# ---- S6. real failure injection at every step (FAILURE AFTER, RESTART RECOVERY) --------------


def _dir_fsync_injector(monkeypatch, fail_at: int | None) -> dict:
    """Every directory fsync of the package counted (durable.fsync_dir and the names
    the ledger and the node bound to it); the `fail_at`-th raises OSError AFTER the
    bytes it would have made durable are visible — the write, the rename, the
    truncation or the unlink already happened. Returns the counter box."""
    import natively.durable as durable
    import natively.ledger as ledgermod
    import natively.node as nodemod

    real = durable.fsync_dir
    assert real.__module__ == "natively.durable"
    box = {"n": 0}

    def fsync_dir(d):
        box["n"] += 1
        if fail_at is not None and box["n"] == fail_at:
            raise OSError(5, f"Input/output error (power loss injected at barrier {fail_at})")
        return real(d)

    for mod, name in ((durable, "fsync_dir"), (ledgermod, "fsync_dir"), (nodemod, "_fsync_dir")):
        monkeypatch.setattr(mod, name, fsync_dir)
    return box


@pytest.mark.parametrize("stage", ["nested", "own"])
def test_a_power_loss_after_the_bytes_of_every_step_resumes_to_completion(
    tmp_path, capsys, monkeypatch, stage
):
    """S6, FAILURE AFTER at EVERY step of the real cut-and-transition sequence: the
    nested tail stage under a standing mirror intent (then the mirror stage that
    follows it) and the ledger's own tail stage. The directory barrier that ends
    each durable step — the intent write, the cut, the step advance, the audit's
    JSONL line, its prose line, the audited marker, the marker's removal, the
    mirror regeneration — raises after its bytes are visible; the run fails; ONE
    resume completes: verify exit 0, exactly one tail audit (and one mirror audit
    when nested), every marker gone. The count of barriers comes from a clean run."""
    fixture, _action, audits = STAGES[stage]
    b, _ = fixture(tmp_path / "clean")
    box = _dir_fsync_injector(monkeypatch, None)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    monkeypatch.undo()
    total = box["n"]
    assert total >= 8, total
    for action, n in audits.items():
        assert _actions(b).count(action) == n, action
    for step in range(1, total + 1):
        b, _ = fixture(tmp_path / f"step{step}")
        _dir_fsync_injector(monkeypatch, step)
        rc = main([*_argv(b), "ledger", "repair"])
        assert rc == 1, (step, rc)  # the OSError, reported on one line
        assert "power loss injected" in capsys.readouterr().err
        monkeypatch.undo()
        assert main([*_argv(b), "ledger", "repair"]) == 0, step
        capsys.readouterr()
        assert _no_markers(b), step
        for action, n in audits.items():
            assert _actions(b).count(action) == n, (step, action)
        assert main([*_argv(b), "ledger", "verify"]) == 0, step
        capsys.readouterr()
        assert main([*_argv(b), "ledger", "repair"]) == 0, step  # idempotent
        capsys.readouterr()
        for action, n in audits.items():
            assert _actions(b).count(action) == n, (step, action)


@pytest.mark.parametrize("stage", ["nested", "own"])
def test_a_power_loss_inside_the_audit_prose_write_at_every_prefix_resumes(
    tmp_path, capsys, monkeypatch, stage
):
    """S6 + S5: the audit's prose write torn after 1, 20 and 60 ASCII bytes, and
    after nothing at all (the JSONL line durable, no prose): every state resumes
    once to completion."""
    fixture, action, audits = STAGES[stage]
    for keep in (0, 1, 20, 60):
        b, _ = fixture(tmp_path / f"keep{keep}")
        _tear_prose_write(monkeypatch, b.ledger, action, keep=keep)
        assert main([*_argv(b), "ledger", "repair"]) == 1
        capsys.readouterr()
        monkeypatch.undo()
        assert main([*_argv(b), "ledger", "repair"]) == 0, keep
        capsys.readouterr()
        assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0, keep
        for a_, n in audits.items():
            assert _actions(b).count(a_) == n, (keep, a_)


# ---- S7. the ledger head anchored to the stored acks (ORDERING, FAILURE BEFORE) --------------


def test_a_last_completion_edited_with_its_mirror_line_deleted_is_caught_by_the_anchor(
    tmp_path, capsys
):
    """S7: the last completion's outcome edited (the chain holds) AND its mirror
    line deleted — the documented trailing gap: the chain, the mirror comparison
    (only the lines present) and uses() alone would pass and count zero. The anchor
    does not: the ack this node sent for that message was signed over the original
    entry's head — ledger.head.mismatch naming the msg_id, a storage failure at
    the receive (the executor never called, no reservation, the mail unseen) and
    at the pin; the verify verb refuses too (its stricter count check first). Then
    the mirror line REGENERATED from the edited entry (what the next append would
    have done): every check but the anchor passes, and the anchor refuses by name
    in check_intact and verify alike. The ledger restored, the retry is refused as
    used up."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path)
    first = a.outbox()[-2]["msg_id"]  # the applied use; the second write is [-1]
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    assert b._seen()[first]["ack"]["ledger_head"] == entry_hash(b.ledger.entries()[-1])
    _edit_last_completion(b, "jsonl")
    kept = b"".join(prose.splitlines(keepends=True)[:-1])
    mirror.write_bytes(kept)
    assert b.ledger.uses(g["grant_id"]) == 0  # the loader alone
    assert b.ledger._prose_gap(b.ledger.entries(), "x")[0]  # the mirror alone: a gap
    with pytest.raises(IntegrityError) as e:
        b.ledger.check_intact()
    assert e.value.reason == "ledger.head.mismatch" and first in str(e.value)
    assert str(jsonl) in str(e.value)
    with pytest.raises(IntegrityError) as e:
        b.ledger.verify()
    assert e.value.reason == "ledger.prose.count"  # the verb's count check comes first
    edited = b.ledger.entries()[-1]
    for regenerated in (False, True):
        if regenerated:
            # the mirror line the next append would have regenerated from the edit
            mirror.write_bytes(kept + prose_line(edited, entry_hash(edited)).encode() + b"\n")
            assert b.ledger._prose_gap(b.ledger.entries(), "x") == ([], False)
            for check in (b.ledger.check_intact, b.ledger.verify):
                with pytest.raises(IntegrityError) as e:
                    check()
                assert e.value.reason == "ledger.head.mismatch" and first in str(e.value)
        tampered = (jsonl.read_bytes(), mirror.read_bytes())
        entries_before, inbox_before = len(b.ledger.entries()), _inbox_len(fake)
        s = wb.poll_once()
        assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
        assert any("ledger.head.mismatch" in x and first in x for x in s["errors"])
        assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
        assert a.outbox()[-1]["msg_id"] not in b._seen()  # no reservation
        assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
        assert (jsonl.read_bytes(), mirror.read_bytes()) == tampered
        assert len(b.ledger.entries()) == entries_before
        assert main([*_argv(b), "ledger", "verify"]) == 2
        err = capsys.readouterr().err
        assert ("ledger.head.mismatch" if regenerated else "ledger.prose.") in err
        _pin_refuses(b, capsys, "ledger.head.mismatch", jsonl)
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in b.ledger.entries()[-1]["detail"]
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"


def test_a_fresh_node_without_acks_has_no_anchor_and_a_node_with_many_passes(tmp_path):
    """S7: a fresh node stores no ack — no anchor, every check unchanged; a node
    with many stored acks passes every check, receives and pins; a stored ack whose
    head is not a string is named."""
    n = make_node(tmp_path, "fresh", Clock())
    assert n._stored_ack_anchors() == []
    n.ledger.check_intact()
    n.ledger.verify()
    n.receive(n.compose_card())
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    for i in range(6):
        wa.send(a.compose_info(b.card, f"more {i}"))
    assert wb.poll_once()["applied"] == 6
    heads = b._stored_ack_anchors()
    assert len(heads) == 8 and all(h.startswith("sha256:") for _, h, _e in heads)
    present = {entry_hash(e) for e in b.ledger.entries()}
    assert all(h in present and e in present for _, h, e in heads)
    b.ledger.check_intact()
    assert main([*_argv(b), "ledger", "verify"]) == 0
    b.pin(a.principal.public, "a again")
    wa.send(a.compose_info(b.card, "still"))
    assert wb.poll_once()["applied"] == 1
    seen = b._seen()
    msg_id, _, _ = heads[0]
    seen[msg_id]["ack"]["ledger_head"] = None  # not even a string: the ack no longer verifies
    (b.state / "seen.json").write_text(json.dumps(seen))
    with pytest.raises(IntegrityError) as e:
        b.ledger.check_intact()
    assert e.value.reason == "seen.corrupt" and msg_id in str(e.value)


def test_the_anchor_check_runs_inside_the_full_check_before_any_authorization(
    tmp_path, monkeypatch
):
    """S7, ORDERING: the anchors are read inside check_intact — before find_msg,
    uses, the reservation and the executor; a failing anchor stops the receive
    with nothing ledgered and no cache left behind."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path, max_uses=3)
    order: list[str] = []
    real_anchors = b.ledger.anchors

    def anchors():
        order.append("anchors")
        return real_anchors()

    b.ledger.anchors = anchors
    for name in ("uses", "find_msg"):
        real = getattr(b.ledger, name)

        def logged(*args, _real=real, _name=name, **kw):
            order.append(_name)
            return _real(*args, **kw)

        monkeypatch.setattr(b.ledger, name, logged)
    real_reserve = b._reserve
    monkeypatch.setattr(
        b, "_reserve", lambda *x, **k: (order.append("reserve"), real_reserve(*x, **k))[1]
    )
    assert wb.poll_once()["applied"] == 1
    assert order[0] == "anchors" and order.index("anchors") < order.index("uses") < order.index(
        "reserve"
    )
    b.ledger.anchors = lambda: [("msg_01FAKE0000000000000000000A", "sha256:" + "f" * 64, "x")]
    n = len(b.ledger.entries())
    wa.send(write_bundle(a, b, g, "u.txt", "third\n"))
    with pytest.raises(IntegrityError) as e:
        b.receive(bundlemod.decode(fake.inbox["taylor@teale.com"][-1]["body"]))
    assert e.value.reason == "ledger.head.mismatch" and "msg_01FAKE" in str(e.value)
    assert b.ledger._entries is None and len(b.ledger.entries()) == n
    assert calls["calls"] == 1 and (b.scratch_dir / "u.txt").read_text() == "again\n"


# ---- after the self-gate: its findings inside the rulings' families, fixed in-family ---------
# (1) the stored acks are AUTHENTICATED before they anchor — structure, our signature, the
#     message they answer — so a damaged ack is seen.corrupt, never an anchor read from an
#     unverified field; and, the write side, an ack this node signs is verified before it
#     is stored (ack.self_invalid): a stored ack that fails is one damaged on disk;
# (2) nothing is rebuilt over a damaged stored ack or an edited completion — the ledger's
#     full check, its anchors included, runs before a completion is read and promoted;
# (3) the line for a mail that is not a wire body is appended only after that same check,
#     inside the poll's storage boundary; (4) the helper's --json rows decode strictly and a
#     text part that carries neither data nor an attachment id is unavailable; (5) a
#     duplicate held revocation is read, verified and compared, never trusted by its name;
# (6) the newline matrix completed (test_a_unicode_blank_line_in_the_prose_mirror above and
#     test_gate_round11.test_a_whole_record_that_fails_its_document_check_is_never_cut).


def _damage_sig(sig: str) -> str:
    return ("B" if sig[0] != "B" else "C") + sig[1:]


def test_a_stored_ack_re_pointed_at_an_earlier_entry_is_seen_corrupt_not_an_anchor(
    tmp_path, capsys
):
    """Self-gate 1 (FAILURE BEFORE): the last completion edited, its mirror line
    regenerated from the edit, AND the stored ack's head and entry re-pointed at an
    earlier entry — both hashes present in the chain, so a membership check alone
    would pass. The ack's signature no longer covers its fields: seen.corrupt naming
    the msg_id in check_intact and verify alike, never a pass and never a use count
    of zero; the receive a storage failure with the executor never called and no
    reservation; the pin refuses. Restored, the retry is refused as used up."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path)
    first = a.outbox()[-2]["msg_id"]
    jsonl, mirror, seen_path = b.ledger.path, b.ledger.prose_path, b.state / "seen.json"
    whole, prose, seen_whole = jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes()
    _edit_last_completion(b, "jsonl")
    edited = b.ledger.entries()[-1]
    kept = b"".join(prose.splitlines(keepends=True)[:-1])
    mirror.write_bytes(kept + prose_line(edited, entry_hash(edited)).encode() + b"\n")
    earlier = entry_hash(b.ledger.entries()[0])
    seen = json.loads(seen_whole)
    seen[first]["ack"]["ledger_head"] = earlier
    seen[first]["ack"]["ledger_entry"] = earlier
    seen_path.write_text(json.dumps(seen))
    assert b.ledger._prose_gap(b.ledger.entries(), "x") == ([], False)  # the mirror agrees
    for check in (b.ledger.check_intact, b.ledger.verify):
        with pytest.raises(IntegrityError) as e:
            check()
        assert e.value.reason == "seen.corrupt" and first in str(e.value)
        assert "ack.sig" in str(e.value) and str(seen_path) in str(e.value)
    tampered = (jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes())
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any("seen.corrupt" in x and first in x for x in s["errors"])
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
    assert (jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes()) == tampered
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert main([*_argv(b), "ledger", "verify"]) == 2
    assert "seen.corrupt" in capsys.readouterr().err
    _pin_refuses(b, capsys, "seen.corrupt", seen_path)
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    seen_path.write_bytes(seen_whole)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"


def test_an_ack_this_node_signs_is_verified_before_it_is_stored(tmp_path, monkeypatch):
    """Self-gate 1, the write side (FAILURE BEFORE): an ack that does not verify as it
    is signed is never stored — ack.self_invalid, an IntegrityError (a storage
    failure) with the seen file untouched and the completion standing; the signing
    sound again, the re-delivery rebuilds the ack from the completion and stores one
    that verifies, nothing re-evaluated."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    m = a.compose_info(b.card, "hello")
    msg_id = m["object"]["msg_id"]
    real_sign = ackmod.sign
    seen_path = b.state / "seen.json"
    seen_before = seen_path.read_bytes() if seen_path.exists() else None

    def bad_sign(obj, kp):
        signed = real_sign(obj, kp)
        return {**signed, "sig": _damage_sig(signed["sig"])}

    monkeypatch.setattr("natively.node.ackmod.sign", bad_sign)
    with pytest.raises(IntegrityError) as e:
        b.receive(m)
    assert e.value.reason == "ack.self_invalid" and msg_id in str(e.value)
    assert "ack.sig" in str(e.value) and "nothing stored" in str(e.value)
    assert (seen_path.read_bytes() if seen_path.exists() else None) == seen_before
    assert b.ledger.find_msg(msg_id) is not None
    n = len(b.ledger.entries())
    monkeypatch.undo()
    (r,) = b.receive(m)
    assert r["object"]["in_reply_to"] == msg_id and r["object"]["outcome"] == "information"
    assert any("but its ack was lost; rebuilding" in x for x in reports)
    assert len(b.ledger.entries()) == n and b.stored_reply(msg_id)[1] is None
    b.ledger.check_intact()  # the stored ack anchors the chain


def test_nothing_is_rebuilt_over_a_damaged_stored_ack_or_an_edited_completion(tmp_path):
    """Self-gate 2 (ORDERING, FAILURE BEFORE): the rebuild from a completion reads it
    only through the ledger's full check, the stored acks authenticated and anchored:
    an edited applied completion with its mirror line deleted AND the stored ack's
    signature damaged is seen.corrupt (the anchor cannot be read: nothing signed,
    nothing stored, both ledger files untouched); the same edit with the stored ack
    intact is ledger.head.mismatch. Restored, the rebuild stores an ack that verifies
    and the retry is refused as used up."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path)
    first = a.outbox()[-2]["msg_id"]
    jsonl, mirror, seen_path = b.ledger.path, b.ledger.prose_path, b.state / "seen.json"
    whole, prose, seen_whole = jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes()
    _edit_last_completion(b, "jsonl")
    mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    seen = json.loads(seen_whole)
    seen[first]["ack"]["sig"] = _damage_sig(seen[first]["ack"]["sig"])
    seen_path.write_text(json.dumps(seen))
    for damaged_ack, reason in ((True, "seen.corrupt"), (False, "ledger.head.mismatch")):
        if not damaged_ack:
            seen_path.write_bytes(seen_whole)  # the ack intact: the edit is caught by name
        before = (jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes())
        with pytest.raises(IntegrityError) as e:
            b.rebuild_from_completion(first)
        assert e.value.reason == reason and first in str(e.value)
        assert (jsonl.read_bytes(), mirror.read_bytes(), seen_path.read_bytes()) == before
        assert b.ledger.uses(g["grant_id"]) == 0  # what the loader alone would have counted
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    r = b.rebuild_from_completion(first)
    assert r is not None and r["object"]["outcome"] == "applied"
    stored = b._seen()[first]["ack"]
    assert stored["ledger_entry"] == entry_hash(b.ledger.entries()[-1])
    b.ledger.check_intact()
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"


def test_an_undecodable_mail_over_a_ledger_that_fails_its_full_check_is_a_storage_failure(
    tmp_path,
):
    """Self-gate 3 (ORDERING, FAILURE BEFORE): the line for a mail that is not a wire
    body is appended only after the ledger's full check, its anchors included, inside
    the poll's storage boundary: over a ledger whose last completion was edited (the
    stored ack anchors the original) the poll counts a storage failure, ledgers
    nothing, marks nothing seen, leaves the cursor and reports incomplete; restored,
    the same mail is ledgered wire.decode once and marked seen."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = whole.split(b"\n")[:-1]
    e = json.loads(lines[-1])
    e["detail"] = "two, edited"  # the chain link into it holds: the loader passes
    jsonl.write_bytes(b"\n".join([*lines[:-1], _serialize(e)]) + b"\n")
    edited = b.ledger.entries()[-1]
    kept = b"".join(prose.splitlines(keepends=True)[:-1])
    mirror.write_bytes(kept + prose_line(edited, entry_hash(edited)).encode() + b"\n")
    with pytest.raises(IntegrityError) as x:
        b.ledger.check_intact()
    assert x.value.reason == "ledger.head.mismatch"
    gid = fake.add("taylor@teale.com", PEER, "hi, is this the robot thread?")
    cursor, seen_ids = wb.cursor(), sorted(wb._seen())
    tampered = (jsonl.read_bytes(), mirror.read_bytes())
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any("ledger.head.mismatch" in x and gid in x for x in s["errors"])
    assert (jsonl.read_bytes(), mirror.read_bytes()) == tampered  # nothing appended
    assert wb.cursor() == cursor and sorted(wb._seen()) == seen_ids  # unseen, cursor unmoved
    assert gid in _unseen_mail_ids(fake, b, wb)
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True
    assert _actions(b).count("wire.decode") == 1 and gid not in _unseen_mail_ids(fake, b, wb)
    assert wb.poll_once()["complete"] is True and _actions(b).count("wire.decode") == 1


def test_a_json_row_decodes_strictly_and_a_text_part_without_bytes_is_unavailable():
    """Self-gate 4 (FAILURE BEFORE), the helper: in the --json rows, inline or
    attachment data that is not base64 (the alphabet, the padding) is an unavailable
    body — truncated true, body "", never a shorter one; a text/plain part that
    reports a size but carries neither data nor an attachment id is unavailable too.
    Bytes that are not UTF-8 are the peer's bytes: decoded with replacement (a wire
    body is ASCII, so they can never be one; an incomplete fetch there would freeze
    the reader's clocks on that one mail for good), truncated false, judged by the
    reader. The text dump decodes exactly as it always did."""
    api = _gmail_api()
    wire = "X-Natively: v0\nAAAA\n"
    m = _gmail_message("g-strict", wire, inline=False)
    for bad in ("@@@@", "A"):  # not the alphabet; a lone sextet
        row = api.msg_row(m, WIRE_CHARS, lambda att, bad=bad: bad)
        assert row["body"] == "" and row["truncated"] is True
        why = row["body_unavailable"]
        assert "does not decode" in why and "att_g-strict" in why
        (mail,) = parse_thread_json(json.dumps([row]))
        assert mail.truncated is True and mail.body == ""
        inline = _gmail_message("g-inline", wire, inline=True)
        inline["payload"]["parts"][0]["body"]["data"] = bad
        row = api.msg_row(inline, WIRE_CHARS, lambda att: pytest.fail("never fetched"))
        assert row["body"] == "" and row["truncated"] is True
        assert "inline data does not decode" in row["body_unavailable"]
    # the text dump decodes as it always did (leniently: non-alphabet characters ignored)
    inline["payload"]["parts"][0]["body"]["data"] = "@@@@"
    assert api.body_of(inline["payload"]) == ""
    # a text part with a size but neither data nor an attachment id
    sized = _gmail_message("g-sized", wire, inline=False)
    sized["payload"]["parts"][0]["body"] = {"size": 200}
    row = api.msg_row(sized, WIRE_CHARS, lambda att: pytest.fail("nothing to fetch"))
    assert row["body"] == "" and row["truncated"] is True
    assert "neither data nor an attachment id" in row["body_unavailable"]
    assert api.body_of(sized["payload"]) == ""  # the text dump: as before
    # bytes that are not UTF-8: the peer's bytes, decoded with replacement, complete
    # (round 14: the part declares the size the fetch returns, one byte — a fetch
    # that is not the declared size is unavailable, test_gate_round14.py)
    m["payload"]["parts"][0]["body"]["size"] = 1
    row = api.msg_row(m, WIRE_CHARS, lambda att: "_w")  # b"\xff"
    assert row["body"] == "\ufffd" and row["truncated"] is False
    assert "body_unavailable" not in row
    (mail,) = parse_thread_json(json.dumps([row]))
    assert mail.truncated is False and mail.unavailable == ""
    with pytest.raises(VerifyError):  # judged by the reader, never a bundle
        bundlemod.decode(mail.body)


def test_a_duplicate_held_revocation_is_read_and_compared_never_trusted_by_its_name(tmp_path):
    """Self-gate 5 (FAILURE BEFORE): a revocation from an unpinned principal received
    again while a damaged copy stands under its name: the copy is read, verified and
    compared with the authenticated document in hand — revocation.held_corrupt naming
    the path, an IntegrityError (a storage failure: the mail unseen), nothing ledgered,
    the copy kept as it was, never a hold that stands on a file it did not check.
    Restored, the same receipt is held and ledgered again."""
    from .test_gate_round3 import held_revocations
    from .test_gate_round4 import _unpinned_pair

    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    bundle = a.compose_revocation(rev)
    assert b.receive(bundle) == []
    (held,) = held_revocations(b, rev["rev_id"])
    original = held.read_bytes()
    n = _actions(b).count("revocation.received")  # the envelope's card is ledgered first
    for damaged in (b"{}", b"[]", b'{"rev_id": "' + rev["rev_id"].encode() + b'"}'):
        held.write_bytes(damaged)
        with pytest.raises(IntegrityError) as e:
            b.receive(bundle)
        assert e.value.reason == "revocation.held_corrupt" and str(held) in str(e.value)
        assert held.read_bytes() == damaged and _actions(b).count("revocation.received") == n
        assert held_revocations(b, rev["rev_id"]) == [held]
    other = dict(json.loads(original))
    other["sig"] = _damage_sig(other["sig"])  # a document that is not the one in hand
    held.write_text(json.dumps(other))
    with pytest.raises(IntegrityError) as e:
        b.receive(bundle)
    assert e.value.reason == "revocation.held_corrupt"
    assert _actions(b).count("revocation.received") == n
    held.write_bytes(original)
    assert b.receive(bundle) == [] and held.read_bytes() == original
    assert _actions(b).count("revocation.received") == n + 1
    assert _actions(b)[-1] == "revocation.received"
