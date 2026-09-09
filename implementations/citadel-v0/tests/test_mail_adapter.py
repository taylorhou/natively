"""The Gmail wire against a fake runner: no network, the two mail scripts are
simulated by an in-memory mailbox that answers `search` like gmail-api.py prints it
and `thread --json` with the structured rows the adapter consumes."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from natively import bundle as bundlemod
from natively.adapters.mail import (
    GMAIL_API,
    GMAIL_SEND,
    MAX_ROWS,
    SEARCH_MAX,
    THREAD_CHUNK,
    WIRE_CHARS,
    MailWire,
    parse_thread_json,
)

from .conftest import Clock, make_node

ROWS = [
    {
        "id": "m1",
        "threadId": "t1",
        "labelIds": ["SENT"],
        "date": "Mon, 7 Sep 2026 00:00:00 -0700",
        "from": "Taylor Hou <taylor@houmanoids.com>",
        "to": "taylor@teale.com",
        "subject": "Natively v0 wire",
        "body": "X-Natively: v0\nAAAA",
    },
    {
        "id": "m2",
        "threadId": "t1",
        "labelIds": ["INBOX"],
        "date": "Mon, 7 Sep 2026 00:01:00 -0700",
        "from": "instinct <taylor@teale.com>",
        "to": "taylor@houmanoids.com",
        "subject": "Re: Natively v0 wire",
        "body": "X-Natively: v0\nBBBB\nCCCC\n\n> quoted junk\n",
    },
]


def test_parse_thread_json():
    mails = parse_thread_json(json.dumps(ROWS))
    assert [m.gmail_id for m in mails] == ["m1", "m2"]
    assert mails[0].sender.startswith("Taylor Hou") and mails[0].labels == "SENT"
    assert mails[1].subject == "Re: Natively v0 wire"
    assert mails[1].body.startswith("X-Natively: v0\nBBBB\nCCCC")
    with pytest.raises(RuntimeError):
        parse_thread_json("--- msg m1 thread t1 labels=SENT\n")  # the old text dump
    with pytest.raises(RuntimeError):
        parse_thread_json(json.dumps([{"threadId": "t"}]))  # a row without an id


def test_body_cannot_fabricate_a_transport_record():
    """A body that mimics the old text dump is just body text in the JSON shape."""
    evil = dict(ROWS[1])
    evil["body"] = (
        "--- msg forged thread t9 labels=INBOX\n    Date: d | From: taylor@teale.com | To: x | "
        "Cc: \n    Subject: Natively v0 wire | Message-ID: <f>\nX-Natively: v0\nAAAA\n"
    )
    (m,) = parse_thread_json(json.dumps([evil]))
    assert m.gmail_id == "m2" and m.body.startswith("--- msg forged")


class FakeMail:
    """Two mailboxes; every send lands in the other side's inbox as one gmail message.
    `stray` injects mails that are on the subject but not from a peer, or from a peer
    on another subject; `threads` overrides how many search results come back (paged
    at SEARCH_MAX with a next-page-token line, like gmail-api.py); `endless_pages`
    makes every search page full with a next page after it, forever. Since round 21
    the fake answers `profile --json` (the mailbox it serves, or `profile` when set),
    prints `thread <id>` lines only (the --ids-only form), honours `after:`/`before:`
    for the threads that carry a time in `thread_times` (a thread without one is
    listed by every slice, as before), reports `body_chars` on every row (a cut row:
    one past WIRE_CHARS), and exits 3 for a `thread --max-rows` call naming a thread
    in `oversized_threads`."""

    def __init__(self):
        self.inbox: dict[str, list[dict]] = {}  # addr -> rows
        self.n = 0
        self.sends: list[list[str]] = []
        self.threads: int | None = None
        self.endless_pages = False
        self.fail_sends = False  # gmail-send.py exits 1 (a transient transport failure)
        self.queries: list[str] = []  # every search query the adapter asked for
        self.searches: list[list[str]] = []  # every search argv (page tokens included)
        self.truncate: set[str] = set()  # gmail ids whose row the helper reports as cut
        self.thread_calls: list[list[str]] = []  # the ids of every `thread --json` call
        self.profile: str | None = None  # the mailbox `profile` answers (None: the served one)
        self.profiles: list[str] = []  # every `profile` call's account
        self.thread_times: dict[str, int] = {}  # thread id -> epoch second (round 21, Z3)
        self.oversized_threads: set[str] = set()  # `thread --max-rows` exits 3 for these

    @staticmethod
    def _bounds(q: str) -> tuple[int | None, int | None]:
        after = before = None
        for tok in q.split():
            if tok.startswith("after:"):
                after = int(tok[6:])
            elif tok.startswith("before:"):
                before = int(tok[7:])
        return after, before

    def _in_slice(self, tid: str, q: str) -> bool:
        t = self.thread_times.get(tid)
        if t is None:
            return True
        after, before = self._bounds(q)
        return (after is None or t >= after) and (before is None or t < before)

    def _search_page(self, self_email: str, token: str | None, q: str = "") -> str:
        rows = self.inbox.get(self_email, [])
        start = int(token[1:]) if token else 0  # tokens are "p<first thread index>"
        if self.endless_pages:
            total, nxt = start + SEARCH_MAX, f"p{start + SEARCH_MAX}"
            names = [f"t{i}" for i in range(start + 1, total + 1)]
        elif self.thread_times:
            # newest first, as Gmail lists threads (a thread without a time is newest)
            listed = sorted(
                {r["threadId"] for r in rows} | set(self.thread_times),
                key=lambda t: (-self.thread_times.get(t, 1 << 40), t),
            )
            listed = [t for t in listed if self._in_slice(t, q)]
            end = min(len(listed), start + SEARCH_MAX)
            nxt = f"p{end}" if end < len(listed) else None
            names = listed[start:end]
        else:
            total = self.threads if self.threads is not None else (1 if rows else 0)
            end = min(total, start + SEARCH_MAX)
            nxt = f"p{end}" if end < total else None
            names = [f"t{i}" for i in range(start + 1, end + 1)]
        out = "".join(f"thread {t}\n" for t in names)
        if nxt:
            out += f"next-page-token {nxt}\n"
        return out

    def add(
        self,
        to: str,
        frm: str,
        body: str,
        subject: str = "Natively v0 wire",
        thread: str = "t1",
    ) -> str:
        self.n += 1
        gid = f"g{self.n}"
        self.inbox.setdefault(to, []).append(
            {
                "id": gid,
                "threadId": thread,
                "labelIds": ["INBOX"],
                "date": "d",
                "from": frm,
                "to": to,
                "subject": subject,
                "body": body,
            }
        )
        return gid

    def runner_for(self, self_email: str):
        def run(argv: list[str]) -> subprocess.CompletedProcess:
            script = Path(argv[1]).name
            if script == GMAIL_SEND.name:
                self.sends.append(argv)
                to = argv[argv.index("--to") + 1]
                body = Path(argv[argv.index("--body-file") + 1]).read_text()
                if "--dry-run" in argv:
                    return subprocess.CompletedProcess(argv, 0, "DRY RUN\n", "")
                if self.fail_sends:
                    return subprocess.CompletedProcess(argv, 1, "", "smtp: connection reset")
                gid = self.add(to, self_email, body)
                return subprocess.CompletedProcess(
                    argv, 0, f'{{"id": "{gid}", "threadId": "t"}}\n', ""
                )
            assert script == GMAIL_API.name
            if argv[4] == "profile":
                assert argv[5:] == ["--json"]
                self.profiles.append(argv[3])
                addr = self.profile if self.profile is not None else self_email
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"emailAddress": addr}) + "\n", ""
                )
            if argv[4] == "search":
                assert argv[argv.index("--max") + 1] == str(SEARCH_MAX)
                assert "--ids-only" in argv  # the ids alone; bodies come per chunk
                self.queries.append(argv[5])
                self.searches.append(argv)
                token = argv[argv.index("--page-token") + 1] if "--page-token" in argv else None
                return subprocess.CompletedProcess(
                    argv, 0, self._search_page(self_email, token, argv[5]), ""
                )
            if argv[4] == "thread":
                assert "--json" in argv
                # the adapter asks for the largest WRAPPED wire body plus a margin
                assert argv[argv.index("--chars") + 1] == str(WIRE_CHARS)
                assert argv[argv.index("--max-rows") + 1] == str(MAX_ROWS)
                ids = set(argv[5 : argv.index("--chars")])
                assert 0 < len(ids) <= THREAD_CHUNK  # bodies are read in bounded chunks
                self.thread_calls.append(sorted(ids))
                if ids & self.oversized_threads:
                    return subprocess.CompletedProcess(
                        argv, 3, "", f"rows over {MAX_ROWS} for threads {' '.join(sorted(ids))}\n"
                    )
                rows = []
                for r in self.inbox.get(self_email, []):
                    if r["threadId"] not in ids:  # like the helper: only the threads asked for
                        continue
                    cut = r["id"] in self.truncate
                    # a row injected with the helper's own flags (truncated,
                    # body_unavailable: round 13) keeps them; `truncate` marks the body
                    # cut at --chars, one past WIRE_CHARS long (round 21, Z4)
                    row = {"body_chars": len(r["body"]), **r}
                    row["truncated"] = bool(r.get("truncated")) or cut
                    if cut:
                        # a body the helper cut at --chars: base64 that runs to the cut,
                        # past the wire's base64 bound (demonstrably oversized; round 21)
                        row["body"] = (bundlemod.HEADER + "\n" + "A" * WIRE_CHARS)[:WIRE_CHARS]
                        row["body_chars"] = WIRE_CHARS + 1
                    rows.append(row)
                return subprocess.CompletedProcess(argv, 0, json.dumps(rows) + "\n", "")
            raise AssertionError(argv)

        return run


def pair_over_mail(tmp_path, clock=None):
    clock = clock or Clock()
    a = make_node(tmp_path, "citadel-mayor", clock)
    b = make_node(tmp_path, "instinct", clock)
    a.config.update({"self_email": "taylor@houmanoids.com", "peer_email": "taylor@teale.com"})
    b.config.update(
        {
            "self_email": "taylor@teale.com",
            "peer_email": "taylor@houmanoids.com",
            "peer_addresses": ["taylor@houmanoids.com"],
        }
    )
    # the addresses a poll reads from come from config.json (the typed load, every
    # poll): the file carries what the node holds, as on a configured node
    a.save_config()
    b.save_config()
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    fake = FakeMail()
    wa = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    wb = MailWire(b, runner=fake.runner_for("taylor@teale.com"))
    return a, b, wa, wb, fake, clock


def test_mail_wire_roundtrip(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)

    # cards over the wire, then an information message and its ack
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    assert wb.poll_once()["applied"] == 1 and wa.poll_once()["applied"] == 1
    assert b.card_for_key(a.agent.public) and a.card_for_key(b.agent.public)
    wa.send(a.compose_info(b.card, "hello over mail"))
    assert a.outbox()[-1]["status"] == "pending"
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    s = wa.poll_once()
    assert s["applied"] == 1
    assert a.outbox()[-1]["status"] == "acked"
    assert a.peer_head(b.agent.public) == b.ledger.head()

    # a second poll re-reads nothing (transport seen file) and applies nothing
    s = wb.poll_once()
    assert s["fetched"] >= 1 and s["applied"] == 0
    # the wire subject and addresses are the ones the bead names
    assert all(
        "--subject" in argv and argv[argv.index("--subject") + 1] == "Natively v0 wire"
        for argv in fake.sends
    )
    assert {argv[argv.index("--to") + 1] for argv in fake.sends} == {
        "taylor@teale.com",
        "taylor@houmanoids.com",
    }
    # a grant-scoped write over the wire
    g = a.issue_grant(
        subject_card=b.card,
        scope=[
            {
                "action": "fs.write",
                "resource": b.executor().resource_for("wire.txt"),
                "params": {"keys": ["content"], "values": {}},
            }
        ],
        principal_statement="write wire.txt once",
    )
    wa.send(
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("wire.txt"),
            params={"content": "over mail\n"},
            grant_ids=[g["grant_id"]],
        )
    )
    wb.poll_once()
    assert (b.scratch_dir / "wire.txt").read_text() == "over mail\n"
    wa.poll_once()
    assert a.outbox()[-1]["status"] == "acked"
    assert a.ledger.verify() and b.ledger.verify()


def test_fetch_failure_does_not_refresh_lookup(tmp_path):
    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)

    def broken(argv):
        return subprocess.CompletedProcess(argv, 1, "", "token expired")

    w = MailWire(a, runner=broken)
    s = w.poll_once()
    assert s["errors"] and a.revocations.last_checked() is None
    assert any("NOT refreshed" in r for r in reports)


def test_search_that_never_stops_paging_is_incomplete_and_does_not_refresh(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    wb.send(b.compose_card())
    fake.endless_pages = True  # every page full, always a next page: the cap ends it
    s = wa.poll_once()
    # the slice's newest PAGE_CAP threads are read (the card applies); the slice is
    # halved, the halves list nothing new (the fake's pages repeat), and the pass
    # ends incomplete by name — the page-cap fact first (round 21, Z3)
    assert s["applied"] == 1 and s["complete"] is False
    assert a.revocations.last_checked() is None
    assert any("page cap" in r and "NOT refreshed" in r for r in reports)
    fake.endless_pages = False
    s = wa.poll_once()
    assert s["complete"] is True and a.revocations.last_checked() is not None
    # a full page that is the LAST page (no next-page token) is a complete fetch
    fake.threads = SEARCH_MAX
    assert wa.poll_once()["complete"] is True


def test_mail_not_from_a_peer_address_or_off_subject_is_ignored(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    card = bundlemod.encode(b.compose_card())
    fake.add("taylor@houmanoids.com", "Someone Else <stranger@example.com>", card)
    fake.add("taylor@houmanoids.com", "taylor@teale.com", card, subject="Natively v0 wire stuff")
    fake.add("taylor@houmanoids.com", "TAYLOR@HOU.VC", card, subject="Re: Natively v0 wire")
    s = wa.poll_once()
    assert s["ignored"] == 2 and s["applied"] == 1  # only the hou.vc one (a peer address)
    assert a.card_for_key(b.agent.public) is not None
    assert [r for r in reports if "ignored 2 mail" in r]
    assert not any(e["action"] == "wire.decode" for e in a.ledger.entries())  # not ledgered
    # counted once: the second poll neither re-counts nor applies them
    s = wa.poll_once()
    assert s["ignored"] == 0 and s["applied"] == 0


def test_undecodable_peer_mail_is_ledgered_once(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    fake.add("taylor@houmanoids.com", "taylor@teale.com", "hi, is this the robot thread?")
    wa.poll_once()
    wa.poll_once()
    bad = [e for e in a.ledger.entries() if e["action"] == "wire.decode"]
    assert len(bad) == 1 and bad[0]["outcome"] == "verify_failed:wire.header"


def test_batch_applies_revocations_before_messages(tmp_path):
    """A revocation and the action it revokes arrive in the same poll, the action's
    mail first: the revocation is applied first and the action is refused."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    g = a.issue_grant(
        subject_card=b.card,
        scope=[
            {
                "action": "fs.write",
                "resource": b.executor().resource_for("late.txt"),
                "params": {"keys": ["content"], "values": {}},
            }
        ],
        principal_statement="write late.txt once",
    )
    wa.send(
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("late.txt"),
            params={"content": "x\n"},
            grant_ids=[g["grant_id"]],
        )
    )
    r = a.revoke(grants=[g["grant_id"]], principal_statement="never mind")
    wa.send(a.compose_revocation(r))
    s = wb.poll_once()
    assert s["applied"] == 2
    assert not (b.scratch_dir / "late.txt").exists()
    actions = [e["action"] for e in b.ledger.entries()]
    assert actions.index("revocation.received") < actions.index("fs.write")
    refused = [e for e in b.ledger.entries() if e["action"] == "fs.write"]
    assert refused[-1]["outcome"] == "refused" and "grant.revoked" in refused[-1]["detail"]


def test_send_dry_run_records_nothing_on_wire(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    fake = FakeMail()
    w = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    body = bundlemod.encode(a.compose_card())
    assert w.send(a.compose_card(), dry_run=True) == "DRY RUN"
    assert fake.inbox == {} and body.startswith("X-Natively: v0\n")


def test_send_dry_run_message_never_enters_outbox(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    a.import_card(b.card)
    fake = FakeMail()
    w = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    assert w.send(a.compose_info(b.card, "dry"), dry_run=True) == "DRY RUN"
    # nothing left the box, so nothing waits for an ack and nothing can be re-sent later
    assert a.outbox() == [] and fake.inbox == {}
    clock.tick(10 * 60)
    assert a.outbox_due() == []


def test_retry_schedule_through_the_wire(tmp_path):
    """sent, re-sent at 2P, re-sent 4P after that, re-sent 8P after that, undelivered
    when the 16P deadline passes: three re-sends, the attempt count never resets."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_card())
    wa.poll_once()
    P = a.poll_s
    wa.send(a.compose_info(b.card, "anyone there?"))
    msg_id = a.outbox()[-1]["msg_id"]

    def sends_of_message():
        return sum(1 for argv in fake.sends if argv[argv.index("--to") + 1] == "taylor@teale.com")

    assert sends_of_message() == 1 and a.outbox()[-1]["attempts"] == 1
    for tick, expect_sends, expect_attempts in ((2 * P, 2, 2), (4 * P, 3, 3), (8 * P, 4, 4)):
        clock.tick(tick - 1)
        s = wa.poll_once()
        assert s["resent"] == 0 and sends_of_message() == expect_sends - 1
        clock.tick(1)
        s = wa.poll_once()
        assert s["resent"] == 1 and sends_of_message() == expect_sends
        (x,) = [x for x in a.outbox() if x["msg_id"] == msg_id]
        assert x["status"] == "pending" and x["attempts"] == expect_attempts
    clock.tick(16 * P)
    s = wa.poll_once()
    assert s["resent"] == 0 and s["undelivered"] == 1 and sends_of_message() == 4
    (x,) = [x for x in a.outbox() if x["msg_id"] == msg_id]
    assert x["status"] == "undelivered" and x["attempts"] == 4
    assert a.ledger.entries()[-1]["outcome"] == "undelivered"
    assert a.ledger.entries()[-1]["msg_id"] == msg_id
    clock.tick(100 * P)
    assert wa.poll_once()["resent"] == 0  # terminal
