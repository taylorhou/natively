"""Round 19: the fresh whole-package review's findings on enforcement, grants, state,
config and the CLI, a ruling each (Y1 to Y14), pinned.

Y1  the enforcement configuration (the extension flags, poll_s) is read from
    config.json at every authorization through the typed loader, never from the copy
    cached at construction: a denial filed from a second process refuses the next
    action in the first, by name, with zero executor calls.
Y2  no unlocked state writer and no shared temp name: `write_json` creates its temp
    file exclusively under a unique name (two interleaved writers both succeed and the
    file holds the last writer's complete content; a pre-existing <file>.tmp is left
    alone); `save_config`, the config verb and `make_card` write under the state lock
    (a held lock blocks them; two processes setting one config keep both keys).
Y3  a member name repeated inside one object of a file of ours is local corruption by
    that file's name (state.corrupt, feed.corrupt), never last-value-wins.
Y4  the scratch root is kept apart from the state directory and the code: equal,
    inside or containing refuse (ValueError, exit 1) before any file is touched.
Y5  a delegation honours every restriction asked for — the expiry never past the
    parent's, the uses never more than the parent's remaining budget (None: that
    budget; an explicit 0 a Usage error), the window never looser — and refuses a
    looser one by name.
Y6  a freshness sidecar in the future of the clock (a clock stepped back) is stale by
    name until the next complete poll; the monotonic clock decides too, the stricter.
Y7  validity (expiry, not_before, revocation, freshness) is rechecked immediately
    before the executor runs: a grant that expired in between is refused by name, the
    refusal ledgered, the reservation released, zero executor calls, no use consumed.
Y8  `natively card` never writes a card its own loader refuses (an empty agent name):
    exit 1 naming the reason, the existing card byte-identical.
Y10 every CLI and config value is validated before any work and before any write —
    one exit code (1), the value named, nothing written; the accepted shapes unchanged.
Y11 a constraint pattern's grammar is bounded before any compile (a quantifier above
    256, a quantified group containing a quantifier: grant.constraint.pattern by name at
    receive and at load) and the signature is checked before any pattern compiles.
Y12 `config --set` validates before it writes (the G3 shape refuses, nothing written)
    and repairs a config no verb could load with one set.
Y13 a send tool that times out is one line and exit 1 for send, send --dry-run,
    send --card and revoke; the outbox is unchanged.
Y14 `_receive_ack` ledgers before it marks: a failed append leaves the entry pending
    and the head unwritten; the retry records one true out.ack line.

Y9 (pending repair exits 1 when a requested repair remains unsuccessful) is pinned by
the round-7b, 8, 9 and 14 tests whose rc assertions moved from 0 to 1 this round.

The self-gate's reviewer found three gaps in this round's own work, fixed in-family and
pinned in the last section: a record carrying a member name twice, short of its newline,
was offered for the cut as a torn tail (Y3); regex syntax the scan could not follow
(verbose mode, a comment group, branch reset, a conditional, the fuzzy brace) carried a
nested repetition past the grammar bound (Y11); the grant store and the card import wrote
state outside the lock when a verb called them (Y2).

The self-gate's SECOND run found eight more, fixed in-family and pinned in the final
section: a brace after a plain escape is a quantifier (\\d{257}) and global flags keep the
atom before them ((a{2})(?i){2}) (Y11); the time window is judged last, on a clock read
after every slow read (Y7); `~` is expanded once so the separation checks judge the path
the executor uses (Y4); `--window ""` is refused, `--param` is parsed before the node is
built, argparse's own refusals are one line and exit 1 (Y10); a failure before the temp
file object closes the descriptor (Y2); the configuration is validated before anything
of a bundle lands (Y1).

The self-gate's THIRD run found eight more, fixed in-family without a further self-gate
(the mayor's ruling: one self-gate, then the mayor re-gates) and pinned in the closing
section: the separation checks compare filesystem identity, not spelling (Y4); a POSIX
class is consumed whole and a bare bracket inside a class is refused (Y11); the monotonic
anchor is set at the sidecar read, verdict or not (Y6); the pre-executor recheck reads
everything first and judges freshness and the time window after (Y7); a member named
twice inside a TORN prefix is corruption too (Y3); regex constraints and an expiry
ceiling are validated before the node (Y10); a send timeout says delivery unknown (Y13).

Kinds: RESTART RECOVERY (Y14 the retry), two processes on one home (Y1, Y2), clock
and time (Y6, Y7), bounds (Y11), the CLI's validation (Y5, Y10, Y12, Y13).

Round 20 replaced the regex scanner these Y11 and self-gate tests were written
against with the constraint language and its parser (tests/test_gate_round20.py):
every shape the scanner refused is still refused, by the language's own names; the
shapes the scanner ADMITTED that the language excludes (counted quantifiers, every
`(?` form, lazy and possessive modifiers, property and hex escapes, POSIX classes,
escapes inside a class beyond \\] \\\\ \\^ \\-) are pinned here as refused, and the
README's migration note lists them."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import regex

from natively import bundle as bundlemod
from natively import cli, durable, keys
from natively import denial as denialmod
from natively import grant as grantmod
from natively import message as msgmod
from natively import node as nodemod
from natively import revocation as revmod
from natively import state as statemod
from natively.adapters import mail as mailmod
from natively.cli import main
from natively.errors import IntegrityError, StorageError, VerifyError
from natively.executor import Executor
from natively.node import Node
from natively.timeutil import fmt, now_utc, parse, plus

from .conftest import Clock, make_node
from .test_gate_round7 import _argv
from .test_hardening import STATEMENT, fs_write_scope, latest, pair, write_bundle

__all__ = ["pair"]  # the fixture is re-exported for this module's tests
PKG = Path(__file__).resolve().parents[1]


def _env(n: Node) -> dict[str, str]:
    """The environment a second PROCESS runs the CLI in against `n`'s home."""
    return {
        **os.environ,
        "NATIVELY_STATE": str(n.state),
        "NATIVELY_KEYS": str(n.keys_dir),
        "NATIVELY_SCRATCH": str(n.scratch_dir),
        "PYTHONPATH": str(PKG),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _cli(n: Node, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", "-m", "natively", *argv],
        env=_env(n),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _naming(a, b, g, name):
    """An action from a to b naming `g` without attaching it (b reads its own file)."""
    m = msgmod.sign(
        msgmod.action(
            from_key=a.agent.public,
            to_key=b.card["agent"]["key"],
            ts=a.ts(),
            action="fs.write",
            resource=b.executor().resource_for(name),
            params={"content": "x\n"},
            grant_ids=[g["grant_id"]],
        ),
        a.agent,
    )
    return bundlemod.make("message", m, cards=[a.card])


def _count_executor_calls(monkeypatch) -> list[int]:
    calls = [0]
    real = Executor.apply

    def apply(self, *a, **kw):
        calls[0] += 1
        return real(self, *a, **kw)

    monkeypatch.setattr(Executor, "apply", apply)
    return calls


# ---- Y1. a running node honours newly enabled enforcement configuration -----------------------


def test_a_denial_filed_from_a_second_process_refuses_the_next_action_in_the_first(
    pair, monkeypatch
):
    """Y1: node b is alive with standing denials OFF (the construction-time copy); a
    second process enables the flag with `config --set` and files a denial. The next
    action in the first process is refused by name (denied) with zero executor
    calls: the flags were read from config.json at that authorization, never from
    the cached copy."""
    a, b, clock, reports = pair
    assert b.config["extensions"]["standing_denial"] is False
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "y1.txt"), principal_statement=STATEMENT
    )
    r = _cli(b, "config", "--set", "extensions.standing_denial=true")
    assert r.returncode == 0, r.stderr
    r = _cli(
        b, "deny", "--action", "fs.write", "--resource", "*", "--statement", "never in this home"
    )
    assert r.returncode == 0, r.stderr
    assert b.config["extensions"]["standing_denial"] is False  # the snapshot, untouched
    assert b.extensions["standing_denial"] is True  # the file, read now
    calls = _count_executor_calls(monkeypatch)
    (rep,) = b.receive(write_bundle(a, b, g, "y1.txt"))
    assert rep["object"]["outcome"] == "refused:denied"
    assert calls == [0] and not (b.scratch_dir / "y1.txt").exists()
    assert latest(b)["outcome"] == "refused" and "denied" in latest(b)["detail"]


def test_a_config_the_loader_refuses_fails_every_authorization_closed(pair, monkeypatch):
    """Y1: the config damaged while the node runs (a hand edit): the next
    authorization is a storage failure (state.corrupt naming the path), nothing
    executed, nothing ledgered, the reservation never written — never the cached
    copy standing in for a file that no longer loads."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "y1b.txt"), principal_statement=STATEMENT
    )
    cfg = b.state / "config.json"
    cfg.write_text('{"extensions": {"standing_denial": "yes"}}', encoding="utf-8")
    calls = _count_executor_calls(monkeypatch)
    before = len(b.ledger)
    with pytest.raises(StorageError) as e:
        b.receive(write_bundle(a, b, g, "y1b.txt"))
    assert "state.corrupt" in str(e.value) and str(cfg) in str(e.value)
    assert calls == [0] and len(b.ledger) == before
    assert b._reservations() == []  # never reserved


# ---- Y2. no unlocked writer, no shared temp name -------------------------------------------


def test_write_json_leaves_a_pre_existing_tmp_alone_and_uses_a_unique_temp(tmp_path):
    """Y2: the fixed temp name is gone — a `<file>.tmp` that already exists is never
    opened, truncated or renamed (before, it was the temp file of every writer), and
    no temp file remains after the write."""
    p = tmp_path / "config.json"
    stale = tmp_path / "config.json.tmp"
    stale.write_bytes(b"not ours")
    durable.write_json(p, {"a": 1})
    assert json.loads(p.read_text()) == {"a": 1}
    assert stale.read_bytes() == b"not ours"
    assert sorted(x.name for x in tmp_path.iterdir()) == ["config.json", "config.json.tmp"]


def test_two_interleaved_writers_of_one_file_both_succeed_with_a_whole_last_write(
    tmp_path, monkeypatch
):
    """Y2, the collision (Fable I1) made deterministic in one process: writer B opens
    and writes its temp file and pauses at its fsync; writer A then runs a whole
    write_json on the same target; B resumes. Both succeed and the file holds B's
    complete content (B renamed last). With one fixed temp name A's open truncated
    B's inode and B's rename raised FileNotFoundError."""
    p = tmp_path / "state.json"
    at_fsync, go = threading.Event(), threading.Event()
    real_fsync = os.fsync

    def fsync(fd):
        if threading.current_thread().name == "writer-B" and not at_fsync.is_set():
            at_fsync.set()
            assert go.wait(10)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    errors: list[BaseException] = []

    def b_writes():
        try:
            durable.write_json(p, {"writer": "B", "n": 2})
        except BaseException as e:  # noqa: BLE001 — recorded for the assertion
            errors.append(e)

    t = threading.Thread(target=b_writes, name="writer-B")
    t.start()
    assert at_fsync.wait(10)
    durable.write_json(p, {"writer": "A", "n": 1})
    go.set()
    t.join(10)
    assert not t.is_alive() and errors == []
    assert json.loads(p.read_text()) == {"writer": "B", "n": 2}
    assert sorted(x.name for x in tmp_path.iterdir()) == ["state.json"]


@pytest.mark.parametrize("verb", ["config", "card"], ids=["save_config", "make_card"])
def test_the_config_and_the_self_card_are_written_under_the_state_lock(tmp_path, verb):
    """Y2: while another holder has the state lock, `config --set` and `natively card`
    block — the file is unchanged until the lock is released, then written. Before,
    both wrote outside the lock."""
    n = make_node(tmp_path, "n", Clock())
    n.save_config()  # a config on file to change
    target = n.state / ("config.json" if verb == "config" else "self.card.json")
    before = target.read_bytes()
    argv = (
        ["config", "--set", "subject=locked out"]
        if verb == "config"
        else ["card", "--agent-name", "renamed"]
    )
    rcs: list[int] = []
    t = threading.Thread(target=lambda: rcs.append(main([*_argv(n), *argv])))
    with n.locked():
        t.start()
        time.sleep(0.5)
        assert t.is_alive() and target.read_bytes() == before
    t.join(10)
    assert rcs == [0] and target.read_bytes() != before


def test_two_processes_setting_one_config_at_a_shared_start_keep_both_keys(tmp_path):
    """Y2: two processes each `config --set` a different key at a shared start: both
    exit 0 and the file holds BOTH keys — each read-modify-write ran under the lock,
    and neither renamed the other's bytes."""
    n = make_node(tmp_path, "n", Clock())
    start = time.time() + 0.8
    script = (
        "import sys, time\n"
        f"time.sleep(max(0, {start!r} - time.time()))\n"
        "from natively.cli import main\n"
        "sys.exit(main(['config', '--set', sys.argv[1]]))\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-B", "-c", script, kv],
            env=_env(n),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        for kv in ("subject=from one", "poll_s=45")
    ]
    outs = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], outs
    cfg = json.loads((n.state / "config.json").read_text())
    assert cfg["subject"] == "from one" and cfg["poll_s"] == 45
    assert statemod.config(cfg) is None


# ---- Y3. duplicate JSON members are local corruption ---------------------------------------


def test_a_seen_file_with_one_message_key_twice_is_state_corrupt(pair, capsys):
    """Y3: seen.json carrying the same msg_id twice (two reservations for different
    grants) refuses by name at every read — the reservation count, the ack verb (exit
    2 naming the path) — never last-value-wins erasing the first reservation."""
    a, b, clock, reports = pair
    g1 = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "d1.txt"), principal_statement=STATEMENT
    )
    g2 = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "d2.txt"), principal_statement=STATEMENT
    )
    msg_id = write_bundle(a, b, g1, "d1.txt")["object"]["msg_id"]
    ts = fmt(b.now())
    seen = b.state / "seen.json"
    seen.write_text(
        "{"
        + f'"{msg_id}": {{"status": "in_progress", "grant_id": "{g1["grant_id"]}", "ts": "{ts}"}}, '
        + f'"{msg_id}": {{"status": "in_progress", "grant_id": "{g2["grant_id"]}", "ts": "{ts}"}}'
        + "}",
        encoding="utf-8",
    )
    with pytest.raises(IntegrityError) as e:
        b._reservations()
    assert e.value.reason == "state.corrupt" and str(seen) in str(e.value)
    assert "duplicate member name" in str(e.value) and msg_id in str(e.value)
    assert main([*_argv(b), "ack", msg_id]) == 2
    err = capsys.readouterr().err
    assert "state.corrupt" in err and "duplicate member" in err and "Traceback" not in err


def test_a_feed_line_with_a_repeated_member_is_feed_corrupt(pair):
    """Y3, the line-framed stores share the rule: a revocation record on the feed
    with `revokes` twice is feed.corrupt naming the line, never a record read with
    its second value."""
    a, b, clock, reports = pair
    r = a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
    line = json.dumps(r, ensure_ascii=False, separators=(",", ":"))
    dup = line[:-1] + ',"revokes":{"cards":[],"grants":[]}}'
    a.revocations.path.write_text(dup + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError) as e:
        a.revocations.entries()
    assert e.value.reason == "feed.corrupt" and "line 1" in str(e.value)
    assert "duplicate member name 'revokes'" in str(e.value)


# ---- Y4. the scratch root is kept apart from the state ---------------------------------------


@pytest.mark.parametrize("shape", ["equal", "inside", "containing", "code"])
def test_a_scratch_root_overlapping_the_state_or_the_code_refuses_before_any_file(tmp_path, shape):
    """Y4: scratch equal to the state directory, inside it, containing it, or the code
    directory itself: the node does not construct (ValueError by name) and no
    directory was created; the same paths through --scratch and NATIVELY_SCRATCH
    exit 1 by name."""
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    root = tmp_path / "home"
    if shape == "equal":
        state, scratch = root / "x", root / "x"
    elif shape == "inside":
        state, scratch = root / "state", root / "state" / "scratch"
    elif shape == "containing":
        state, scratch = root / "scratch" / "state", root / "scratch"
    else:
        state, scratch = root / "state", keys.CODE_DIR
    with pytest.raises(ValueError) as e:
        Node(state_dir=state, keys_dir=kd, scratch_dir=scratch)
    assert "scratch dir" in str(e.value) or "the state directory" in str(e.value)
    assert not root.exists()
    rc = main(["--state", str(state), "--keys", str(kd), "--scratch", str(scratch), "cards"])
    assert rc == 1 and not root.exists()
    env = {**os.environ, "NATIVELY_STATE": str(state), "NATIVELY_KEYS": str(kd)}
    env["NATIVELY_SCRATCH"] = str(scratch)
    env["PYTHONPATH"] = str(PKG)
    r = subprocess.run(
        [sys.executable, "-B", "-m", "natively", "cards"], env=env, capture_output=True, text=True
    )
    assert r.returncode == 1 and "scratch" in r.stderr and "Traceback" not in r.stderr
    assert not root.exists()


def test_keygen_refuses_an_overlapping_scratch_too(tmp_path):
    """Y4: `keygen` runs the same separation before it writes a key."""
    kd = tmp_path / "keys"
    rc = main(
        [
            "--state",
            str(tmp_path / "s"),
            "--keys",
            str(kd),
            "--scratch",
            str(tmp_path / "s"),
            "keygen",
        ]
    )
    assert rc == 1 and not kd.exists()


# ---- Y5. a delegated grant honours the restrictions it was asked for -------------------------


def _parent_for(a, b, *, window=None, max_uses=7):
    """A parent from a's principal to a (a delegates), with a's extension on when a
    window is asked for. The fixture's clock is moved to the real time first: the
    grant verb runs in a node on the real clock, and the parent's window must hold
    there."""
    a.clock.t = now_utc()
    if window is not None:
        a.config["extensions"]["max_uses_per_window"] = True
        a.save_config()
    return a.issue_grant(
        subject_card=a.card,
        scope=fs_write_scope(a, "d.txt", regex=None),
        principal_statement=STATEMENT,
        expires_in_s=3600,
        max_uses=max_uses,
        max_uses_per_window=window,
    )


def _grant_argv(a, parent, *rest):
    return [
        *_argv(a),
        "grant",
        "--to",
        "b",
        "--file",
        "d.txt",
        "--action",
        "fs.write",
        "--param",
        "content=in:ok",
        "--statement",
        STATEMENT,
        "--parent",
        parent["grant_id"],
        *rest,
    ]


def test_the_codex_delegation_request_refuses_by_name_and_issues_nothing(pair, capsys):
    """Y5: one second, zero uses and a window (the gate's request) — refused at the
    verb (an explicit --max-uses 0 is a Usage error), nothing under grants/. Before,
    the child had seven uses, two hours and no window."""
    a, b, clock, reports = pair
    parent = _parent_for(a, b, window={"n": 2, "window_s": 300})
    before = sorted(p.name for p in (a.state / "grants").iterdir())
    rc = main(_grant_argv(a, parent, "--expires-in", "1", "--max-uses", "0", "--window", "1,600"))
    assert rc == 1 and "--max-uses must be at least 1" in capsys.readouterr().err
    assert sorted(p.name for p in (a.state / "grants").iterdir()) == before


def test_a_tighter_delegation_request_produces_a_child_with_exactly_those_bounds(pair, capsys):
    """Y5: --expires-in 60, --max-uses 1 and --window 1,600 against a parent of an
    hour, seven uses and 2 per 300 s: the child carries exactly those bounds and
    verifies as a document; the expiry is the requested one, not the parent's."""
    a, b, clock, reports = pair
    parent = _parent_for(a, b, window={"n": 2, "window_s": 300})
    rc = main(_grant_argv(a, parent, "--expires-in", "60", "--max-uses", "1", "--window", "1,600"))
    assert rc == 0
    gid = capsys.readouterr().out.split()[1]
    child = a.load_grant(gid)
    assert child is not None and child["parent_grant"]["grant_id"] == parent["grant_id"]
    # the verb's clock is the real one: the requested 60 s, within a few seconds
    assert 0 <= (parse(child["expires_at"]) - plus(a.now(), 60)).total_seconds() <= 5
    assert child["max_uses"] == 1
    assert child["max_uses_per_window"] == {"n": 1, "window_s": 600}
    grantmod.check_document(child, extensions=grantmod.ANY_EXTENSION)


@pytest.mark.parametrize(
    "rest, name",
    [
        (["--expires-in", "7200"], "grant.delegation.expiry"),
        (["--max-uses", "8"], "grant.delegation.max_uses"),
        (["--window", "3,300"], "grant.delegation.max_uses_per_window"),
        (["--window", "2,60"], "grant.delegation.max_uses_per_window"),
    ],
    ids=["expiry-past-the-parents", "more-uses-than-remaining", "wider-n", "shorter-window"],
)
def test_a_looser_delegation_request_refuses_by_name(pair, capsys, rest, name):
    """Y5: an expiry past the parent's, more uses than the parent has remaining, a
    window with a larger n or a shorter window_s: refused by name, nothing issued.
    Before, the expiry and the window were silently dropped."""
    a, b, clock, reports = pair
    parent = _parent_for(a, b, window={"n": 2, "window_s": 300})
    before = sorted(p.name for p in (a.state / "grants").iterdir())
    assert main(_grant_argv(a, parent, *rest)) == 1
    err = capsys.readouterr().err
    assert name in err and "nothing issued" in err
    assert sorted(p.name for p in (a.state / "grants").iterdir()) == before


def test_no_use_count_means_the_parents_remaining_budget(pair):
    """Y5: max_uses None is the parent's REMAINING budget across its family — after
    one applied use of a two-use parent the child gets one use, and a child asking
    for two refuses by name."""
    a, b, clock, reports = pair
    parent = a.issue_grant(
        subject_card=a.card,
        scope=fs_write_scope(a, "p.txt", regex=None),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    # b sends a an action naming the parent (on a's file): a executes it, one use
    # on a's ledger
    (rep,) = a.receive(_naming(b, a, parent, "p.txt"))
    assert rep["object"]["outcome"] == "applied"
    tighter = [{**parent["scope"][0], "params": {"keys": [], "values": {}}}]
    child = a.delegate_grant(
        parent=parent, subject_card=b.card, scope=tighter, principal_statement="one"
    )
    assert child["max_uses"] == 1
    with pytest.raises(ValueError) as e:
        a.delegate_grant(
            parent=parent, subject_card=b.card, scope=tighter, principal_statement="two", max_uses=2
        )
    assert "grant.delegation.max_uses" in str(e.value) and "1 remaining" in str(e.value)


# ---- Y6. a clock rollback fails closed -----------------------------------------------------


def _fresh_pair(pair):
    """A ten-use grant valid for ten days, issued two days before the tests' now, so a
    clock stepped back a day is still inside its window."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "t.txt"),
        principal_statement=STATEMENT,
        expires_in_s=10 * 86400,
        max_uses=10,
    )
    clock.tick(2 * 86400)
    return a, b, clock, g


def test_a_sidecar_in_the_future_of_the_clock_is_stale_until_the_next_complete_poll(pair):
    """Y6: the last lookup at T, the clock stepped back a day: refused
    revocation.stale naming the sidecar's timestamp as in the future; a complete
    poll at the stepped-back time rewrites the sidecar and the action applies."""
    a, b, clock, g = _fresh_pair(pair)
    b.mark_lookup_ok()
    stamp = fmt(b.now())
    clock.tick(-86400)
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "one\n"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    d = latest(b)["detail"]
    assert "revocation.stale" in d and stamp in d and "future" in d
    assert not (b.scratch_dir / "t.txt").exists()
    b.mark_lookup_ok()  # a complete poll landed at the stepped-back time
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "two\n"))
    assert rep["object"]["outcome"] == "applied"


def test_the_monotonic_elapsed_time_refuses_when_the_wall_clock_was_stepped_back(pair, monkeypatch):
    """Y6: the wall clock says 10 s since the lookup (stepped back) but the
    monotonic clock says the limit plus one: refused revocation.stale naming the
    monotonic elapsed; the stricter of the two decides."""
    a, b, clock, g = _fresh_pair(pair)
    mono = [1000.0]
    monkeypatch.setattr(revmod, "_monotonic", lambda: mono[0])
    b.mark_lookup_ok()
    limit = g["revocation"]["max_check_interval_s"] + b.poll_s
    clock.tick(limit + 200)
    clock.tick(-(limit + 190))  # the wall clock: 10 s after the lookup
    mono[0] += limit + 1
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "one\n"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    d = latest(b)["detail"]
    assert "revocation.stale" in d and "monotonic" in d and f"{limit + 1}s" in d
    mono[0] = 5000.0
    b.mark_lookup_ok()  # a new lookup re-anchors both clocks
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "two\n"))
    assert rep["object"]["outcome"] == "applied"


def test_a_lookup_by_another_process_is_anchored_when_first_seen(pair, monkeypatch):
    """Y6: a sidecar value this process never wrote (another process's poll) counts
    from the moment it is first read here — fresh then, stale once the monotonic
    elapsed since that read passes the limit."""
    a, b, clock, g = _fresh_pair(pair)
    mono = [1000.0]
    monkeypatch.setattr(revmod, "_monotonic", lambda: mono[0])
    durable.write_json(b.revocations.check_path, {"last_checked": fmt(b.now())})
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "one\n"))
    assert rep["object"]["outcome"] == "applied"
    limit = g["revocation"]["max_check_interval_s"] + b.poll_s
    mono[0] += limit + 1
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "two\n"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "monotonic" in latest(b)["detail"]


# ---- Y7. validity is rechecked at the point of execution -------------------------------------


def test_a_grant_that_expires_between_verification_and_execution_does_not_run(pair, monkeypatch):
    """Y7, the gate's shape: verified at T, expired at T+2, the clock at T+3 when the
    executor would run (advanced inside the reservation step): refused by name
    (grant.expired), the refusal ledgered saying nothing executed, the reservation
    released by the stored ack, zero executor calls, no use consumed, no file."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "late.txt"),
        principal_statement=STATEMENT,
        expires_in_s=2,
    )
    real_reserve = b._reserve

    def reserve(msg_id, grant_id):
        real_reserve(msg_id, grant_id)
        clock.tick(3)  # the slow step: the executor would run after the expiry

    monkeypatch.setattr(b, "_reserve", reserve)
    calls = _count_executor_calls(monkeypatch)
    m = write_bundle(a, b, g, "late.txt")
    (rep,) = b.receive(m)
    assert rep["object"]["outcome"] == "refused:grant.expired"
    e = latest(b)
    assert e["outcome"] == "refused" and e["grant_id"] == g["grant_id"]
    assert "grant.expired" in e["detail"] and "nothing executed" in e["detail"]
    assert "crossed between verification and execution" in e["detail"]
    assert calls == [0] and not (b.scratch_dir / "late.txt").exists()
    assert b.grant_uses(g) == (0, None) and b._reservations() == []
    seen = json.loads((b.state / "seen.json").read_text())
    assert "ack" in seen[m["object"]["msg_id"]]


def test_a_revocation_landing_between_verification_and_execution_does_not_run(pair, monkeypatch):
    """Y7: the grant revoked (the feed written by the principal) inside the
    reservation step: refused grant.revoked, zero executor calls."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "rev.txt"), principal_statement=STATEMENT
    )
    real_reserve = b._reserve

    def reserve(msg_id, grant_id):
        real_reserve(msg_id, grant_id)
        b.receive(a.compose_revocation(a.revoke(grants=[g["grant_id"]], principal_statement="x")))

    monkeypatch.setattr(b, "_reserve", reserve)
    calls = _count_executor_calls(monkeypatch)
    (rep,) = b.receive(write_bundle(a, b, g, "rev.txt"))
    assert rep["object"]["outcome"] == "refused:grant.revoked"
    assert calls == [0] and not (b.scratch_dir / "rev.txt").exists()
    assert b.grant_uses(g) == (0, None)


# ---- Y8. make_card never writes a card its own loader refuses --------------------------------


def test_the_card_verb_refuses_an_empty_agent_name_and_leaves_the_old_card(tmp_path, capsys):
    """Y8: `natively card --agent-name ""` exits 1; the existing self card is
    byte-identical and `card --show` still reads it. Round 20 (R6): the verb refuses
    the empty name BEFORE the node is built (one Usage line), and the node's own
    guard behind it still refuses by the loader's name (card.agent.name.format)."""
    n = make_node(tmp_path, "n", Clock())
    card = n.state / "self.card.json"
    before = card.read_bytes()
    assert main([*_argv(n), "card", "--agent-name", ""]) == 1
    err = capsys.readouterr().err
    assert "--agent-name must not be empty" in err and "Traceback" not in err
    assert card.read_bytes() == before
    with pytest.raises(ValueError) as e:
        n.make_card(agent_name="", node_name="n-node", principal_name="p")
    assert "card.agent.name.format" in str(e.value) and "untouched" in str(e.value)
    assert card.read_bytes() == before
    assert main([*_argv(n), "card", "--show"]) == 0


# ---- Y10. CLI and config values are validated before work and before persistence -------------


def _state_bytes(n: Node) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in n.state.iterdir() if p.is_file() and p.name != ".lock"}


@pytest.mark.parametrize(
    "argv, needle",
    [
        (["run", "--interval", "0", "--once"], "--interval 0"),
        (["run", "--interval", "-5", "--once"], "--interval -5"),
        (["run", "--interval", "4", "--once"], "--interval 4"),
        (["run", "--interval", "86401", "--once"], "--interval 86401"),
        (["ledger", "show", "--tail", "-1"], "--tail -1"),
        (["config", "--set", "poll_s=0"], "poll_s 0 is outside"),
        (["config", "--set", "poll_s=-5"], "poll_s -5 is outside"),
        (["config", "--set", "poll_s=abc"], "not an integer"),
        (["config", "--set", "self_email="], "self_email is an empty string"),
        (["config", "--set", "self_email=not an address"], "self_email"),
        (["config", "--set", "=x"], "bad --set"),
        (["config", "--set", "extensions.zzz=1"], "not an extension flag"),
        (["config", "--set", "extensions.standing_denial=maybe"], "not a boolean"),
        (["config", "--set", "bogus=1"], "not a config key"),
        (["config", "--set", "peer_addresses="], "names no address"),
        (["config", "--set", "subject= "], "subject is empty"),
        (["ack", "nope"], "'nope' is not a msg_"),
        (["send", "--to", "b", "--action", "fs.write", "--file", "f", "--grant", "bad"], "'bad'"),
        (["pin", "bad-key", "--name", "x"], "'bad-key' is not a principal key"),
        (["revoke", "--grant", "bad", "--statement", "x"], "'bad' is not a grt_"),
        (["revoke", "--card", "sha256:zz", "--statement", "x"], "not sha256:<64 hex>"),
        (["revoke", "--statement", "x"], "at least one --grant"),
    ],
    ids=[
        "interval-0",
        "interval-negative",
        "interval-under-floor",
        "interval-over-ceiling",
        "tail-negative",
        "poll_s-0",
        "poll_s-negative",
        "poll_s-text",
        "self_email-empty",
        "self_email-not-an-address",
        "empty-key",
        "unknown-flag",
        "flag-not-boolean",
        "unknown-key",
        "peer_addresses-empty",
        "subject-empty",
        "ack-bad-id",
        "send-bad-grant-id",
        "pin-bad-key",
        "revoke-bad-grant-id",
        "revoke-bad-card-hash",
        "revoke-names-nothing",
    ],
)
def test_a_bad_cli_value_is_one_exit_code_named_with_nothing_written(
    pair, capsys, monkeypatch, argv, needle
):
    """Y10 (and Y12's G3 sibling shapes): every listed shape exits 1 naming the
    value, before any work (no poll ran) and before any write (every state file
    byte-identical)."""
    a, b, clock, reports = pair
    polls = []
    monkeypatch.setattr(mailmod.MailWire, "poll_once", lambda self: polls.append(1))
    before = _state_bytes(a)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err, err
    assert polls == [] and _state_bytes(a) == before


@pytest.mark.parametrize(
    "rest, needle",
    [
        (["--expires-in", "0"], "--expires-in must be at least 1"),
        (["--expires-in", "-5"], "--expires-in must be at least 1"),
        (["--max-uses", "0"], "--max-uses must be at least 1"),
        (["--window", "1"], "bad --window '1'"),
        (["--window", "1,x"], "bad --window '1,x'"),
        (["--window", "0,60"], "at least 1"),
        (["--param", "k=range:nan,1"], "finite number"),
        (["--param", "k=range:1,2,3"], "range is lo,hi"),
        (["--param", "k=range:a,1"], "not a number"),
        (["--parent", "grt_bad"], "'grt_bad' is not a grt_"),
        # round 20 (AA5, AB2): two finite bounds; the last three values before the
        # node; a file name the executor cannot honour
        (["--param", "k=range:,5"], "two finite bounds"),
        (["--param", "k=range:1,"], "two finite bounds"),
        (["--statement", ""], "--statement must not be empty"),
        (["--audience", "bad"], "is not a principal key"),
        (["--file", "../seen.json"], "bad scratch name"),
    ],
    ids=[
        "expires-0",
        "expires-negative",
        "max-uses-0",
        "window-one-value",
        "window-text",
        "window-zero",
        "range-nan",
        "range-three",
        "range-text",
        "parent-bad-id",
        "range-open-low",
        "range-open-high",
        "statement-empty",
        "audience-bad",
        "file-dot-dot",
    ],
)
def test_a_bad_grant_value_is_refused_by_name_with_nothing_stored(pair, capsys, rest, needle):
    """Y10: the grant verb's values — an expiry or a use count below 1, a window that
    does not parse, a range bound that is not a finite number, a parent id of the
    wrong form — exit 1 naming the value; nothing under grants/, no ledger line."""
    a, b, clock, reports = pair
    before = _state_bytes(a)
    argv = [
        *_argv(a),
        "grant",
        "--to",
        "b",
        "--file",
        "f.txt",
        "--action",
        "fs.write",
        "--statement",
        STATEMENT,
        *rest,
    ]
    assert main(argv) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err, err
    assert _state_bytes(a) == before


def test_the_accepted_shapes_are_unchanged(pair, capsys, monkeypatch):
    """Y10: `config --set poll_s=30` stores 30; `ledger show --tail 1` prints one
    entry; `run --interval 5 --once` runs exactly one poll; `grant --expires-in 60
    --max-uses 2` issues; the defaults (an hour, one use) when neither is given."""
    a, b, clock, reports = pair
    assert main([*_argv(a), "config", "--set", "poll_s=30"]) == 0
    assert json.loads((a.state / "config.json").read_text())["poll_s"] == 30
    assert a.poll_s == 30
    capsys.readouterr()
    assert main([*_argv(a), "ledger", "show", "--tail", "1"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == 1
    polls = []
    summary = {
        "fetched": 0,
        "applied": 0,
        "replies": 0,
        "resent": 0,
        "undelivered": 0,
        "errors": [],
    }
    monkeypatch.setattr(mailmod.MailWire, "poll_once", lambda self: polls.append(1) or summary)
    assert main([*_argv(a), "run", "--interval", "5", "--once"]) == 0
    assert polls == [1] and "polling every 5s" in capsys.readouterr().err
    base = [*_argv(a), "grant", "--to", "b", "--file", "f.txt", "--action", "fs.write"]
    assert main([*base, "--statement", STATEMENT, "--expires-in", "60", "--max-uses", "2"]) == 0
    g = a.load_grant(capsys.readouterr().out.split()[1])
    # the verb's clock is the real one: the requested expiry within a few seconds
    assert g["max_uses"] == 2
    assert abs((parse(g["expires_at"]) - plus(now_utc(), 60)).total_seconds()) <= 5
    assert main([*base, "--statement", STATEMENT]) == 0
    g = a.load_grant(capsys.readouterr().out.split()[1])
    assert g["max_uses"] == 1
    assert abs((parse(g["expires_at"]) - plus(now_utc(), 3600)).total_seconds()) <= 5


def test_the_typed_loader_refuses_unknown_keys_flags_and_out_of_range_values():
    """Y10, the loader's rules directly: an unknown key, an unknown flag, poll_s out
    of range, an address field that is not an address, an empty subject — each named;
    the defaults and an empty peer_addresses list pass."""
    for v, why in (
        ({"bogus": 1}, "'bogus' is not a config key"),
        ({"extensions": {"zzz": True}}, "extensions.zzz is not an extension flag"),
        ({"poll_s": 4}, "poll_s 4 is outside 5..86400"),
        ({"poll_s": 86401}, "poll_s 86401 is outside"),
        ({"self_email": ""}, "self_email is an empty string"),
        ({"peer_email": "a b@c"}, "peer_email carries whitespace"),
        ({"subject": "  "}, "subject is empty"),
    ):
        got = statemod.config(v)
        assert got is not None and why in got, (v, got)
    from natively.node import DEFAULT_CONFIG

    assert statemod.config(DEFAULT_CONFIG) is None
    assert statemod.config({"peer_addresses": [], "poll_s": 5}) is None


# ---- Y11. a constraint pattern's compile cost is bounded and paid after the signature --------


HEAVY = "(a{9999}){9999}"  # fifteen characters; 7.8 s and 26 GB in a fresh process before


def _grant_with_pattern(a, b, pattern, *, sign=True):
    g = grantmod.build(
        issuer={"principal": a.card["principal"]["name"], "key": a.principal.public},
        subject={"agent": grantmod.cardmod.card_hash(b.card), "key": b.card["agent"]["key"]},
        audience_executor=b.card["node"]["key"],
        scope=fs_write_scope(b, "pat.txt", regex=pattern),
        principal_statement=STATEMENT,
        issued_at=a.ts(),
        expires_at=fmt(plus(a.now(), 3600)),
        max_check_interval_s=a.poll_s * 5,
    )
    g = grantmod.sign(g, a.principal)
    if not sign:  # one character flipped in the middle: still base64 of 64 bytes
        s = g["sig"]
        g = {**g, "sig": s[:10] + ("A" if s[10] != "A" else "B") + s[11:]}
    return g


def _attach(a, b, g):
    """An info message from a to b carrying `g` as an attached grant."""
    return bundlemod.make(
        "message", a.compose_info(b.card, "carrying a grant")["object"], cards=[a.card], grants=[g]
    )


def _compile_calls(monkeypatch) -> list[str]:
    """Every pattern the document check compiles (round 20: the `regex` engine, from
    the parser's emission)."""
    calls: list[str] = []
    real = grantmod.regex.compile

    def compile_(pat, *a_, **kw):
        calls.append(pat)
        return real(pat, *a_, **kw)

    monkeypatch.setattr(grantmod.regex, "compile", compile_)
    return calls


def test_the_heavy_pattern_refuses_by_name_in_milliseconds_at_receive_signed(pair, monkeypatch):
    """Y11, signed by a pinned principal: refused at receive by name
    (grant.constraint.pattern) with no compile and in well under a second; nothing
    stored under grants/."""
    a, b, clock, reports = pair
    calls = _compile_calls(monkeypatch)
    g = _grant_with_pattern(a, b, HEAVY)
    t0 = time.monotonic()
    b.receive(_attach(a, b, g))
    assert time.monotonic() - t0 < 2.0
    outcomes = [e["outcome"] for e in b.ledger.entries()]
    assert "verify_failed:grant.constraint.pattern" in outcomes
    assert HEAVY not in calls
    assert not (b.state / "grants" / f"{g['grant_id']}.json").exists()


def test_a_garbage_signed_grant_is_refused_by_its_signature_before_any_compile(pair, monkeypatch):
    """Y11 (a): a grant whose signature does not hold, carrying a pattern within the
    grammar, is refused grant.sig.invalid with regex.compile never called for it —
    the signature is checked before any pattern compiles. Before, every pattern was
    compiled first (33.7 s under the lock for the heavy shape)."""
    a, b, clock, reports = pair
    calls = _compile_calls(monkeypatch)
    pattern = "^[a-z]+$"
    g = _grant_with_pattern(a, b, pattern, sign=False)
    b.receive(_attach(a, b, g))
    outcomes = [e["outcome"] for e in b.ledger.entries()]
    assert "verify_failed:grant.sig.invalid" in outcomes
    assert pattern not in calls and grantmod.emit_pattern(pattern) not in calls
    assert not (b.state / "grants" / f"{g['grant_id']}.json").exists()


def test_a_stored_grant_outside_the_bound_refuses_at_load_by_name(pair, capsys):
    """Y11: a grant on file (from before this round) with the heavy pattern is
    state.corrupt at the load naming grant.constraint.pattern — never compiled — and
    an action naming it is a storage failure (nothing executed, the mail unseen)."""
    a, b, clock, reports = pair
    g = _grant_with_pattern(a, b, HEAVY)
    stored = b.state / "grants" / f"{g['grant_id']}.json"
    stored.write_text(json.dumps(g), encoding="utf-8")
    t0 = time.monotonic()
    with pytest.raises(IntegrityError) as e:
        b.load_grant(g["grant_id"])
    assert time.monotonic() - t0 < 2.0
    assert e.value.reason == "state.corrupt" and str(stored) in str(e.value)
    assert "grant.constraint.pattern" in str(e.value)
    with pytest.raises(StorageError):
        b.receive(_naming(a, b, g, "pat.txt"))
    assert not (b.scratch_dir / "pat.txt").exists()


@pytest.mark.parametrize(
    "pattern",
    [HEAVY, "a{99999999}", "x{257}", "a{,300}", "(a{2}){2}", "(a+)+", "(a*)?", "((a{99}){99}){99}"],
)
def test_patterns_outside_the_bounded_grammar_are_refused_at_issue(pair, pattern):
    """Y11 (b): a counted quantifier above 256 or a quantified group containing a
    quantifier is refused at issue by name, nothing stored; the scan costs
    milliseconds."""
    a, b, clock, reports = pair
    t0 = time.monotonic()
    assert grantmod.pattern_problem(pattern) is not None
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "p.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert time.monotonic() - t0 < 1.0
    assert "grant.constraint.pattern" in str(e.value)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[a-z0-9_\-]+$",
        "[{}]+",
        r"\d+",
        "(ab)|(cd)",
        "a+",
        "^abc$",
        r"[^\]]*",
        r"\.\*",
        "x?y*z+",
    ],
)
def test_patterns_within_the_grammar_still_compile_and_match(pair, pattern):
    """Y11 (round 20: the constraint language): ordinary constraints — classes,
    shorthands, plain groups under alternation, the three quantifiers on single
    atoms, anchors, escaped punctuation — issue and verify as documents. (Round
    19's list carried counted repeats, `(?:` and named groups, a lazy modifier, a
    flag and a property escape: all outside the language now, refused below and
    listed in the README's migration note.)"""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(pattern) is None
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "ok.txt", regex=pattern),
        principal_statement=STATEMENT,
    )
    grantmod.check_document(g, extensions=grantmod.ANY_EXTENSION)
    assert grantmod.pattern_problem(pattern) is None


def test_a_normal_pattern_still_matches_end_to_end(pair):
    """Y11: an action under a grant with an ordinary pattern applies as before."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "m.txt", regex="^[a-z]+\n$"),
        principal_statement=STATEMENT,
    )
    (rep,) = b.receive(write_bundle(a, b, g, "m.txt", "hello\n"))
    assert rep["object"]["outcome"] == "applied"
    assert (b.scratch_dir / "m.txt").read_text() == "hello\n"


# ---- Y12. config --set cannot lock the node out ----------------------------------------------


def test_the_g3_shape_refuses_at_set_with_nothing_written(pair, capsys):
    """Y12, the Fable G3 shape: `config --set peer_addresses=taylor@teale.com,a b@c`
    exits 1 naming peer_addresses[1]; the file is byte-identical and every verb
    still runs."""
    a, b, clock, reports = pair
    cfg = a.state / "config.json"
    assert not cfg.exists()  # the defaults, nothing on file yet
    rc = main([*_argv(a), "config", "--set", "peer_addresses=taylor@teale.com,a b@c"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "peer_addresses[1]" in err and "nothing written" in err
    assert not cfg.exists()
    assert main([*_argv(a), "cards"]) == 0


@pytest.mark.parametrize(
    "damage",
    [
        '{"peer_addresses": ["taylor@teale.com", "a b@c"], "poll_s": 60}',
        "{not json",
        '{"bogus": 1}',
    ],
    ids=["bad-element", "not-json", "unknown-key"],
)
def test_a_hand_corrupted_config_is_repaired_by_one_set(pair, capsys, damage):
    """Y12: a config no verb can load (state.corrupt on every verb, the config verb
    included before): `config` reports what it could not read and exits 2; one
    `config --set self_email=me@example.com` writes a complete valid config from the
    loadable parts and the defaults, reports what it replaced, and every verb runs
    again."""
    a, b, clock, reports = pair
    cfg = a.state / "config.json"
    cfg.write_text(damage, encoding="utf-8")
    assert main([*_argv(a), "cards"]) == 2
    assert "state.corrupt" in capsys.readouterr().err
    assert main([*_argv(a), "config"]) == 2
    out = capsys.readouterr()
    assert "state.corrupt" in out.err and json.loads(out.out)["poll_s"] == 60
    assert main([*_argv(a), "config", "--set", "self_email=me@example.com"]) == 0
    out = capsys.readouterr()
    assert "repaired by this write" in out.err
    written = json.loads(cfg.read_text())
    assert statemod.config(written) is None and written["self_email"] == "me@example.com"
    assert set(written) == set(statemod.CONFIG_KEYS)
    if damage.startswith('{"peer'):
        assert written["peer_addresses"] == ["taylor@teale.com", "taylor@hou.vc"]  # the default
    Node(state_dir=a.state, keys_dir=a.keys_dir, scratch_dir=a.scratch_dir)
    assert main([*_argv(a), "cards"]) == 0


def test_a_set_that_survives_keeps_the_other_keys(pair):
    """Y12: a set of one key leaves every other loadable key as it was."""
    a, b, clock, reports = pair
    assert main([*_argv(a), "config", "--set", "subject=one"]) == 0
    assert main([*_argv(a), "config", "--set", "poll_s=42"]) == 0
    cfg = json.loads((a.state / "config.json").read_text())
    assert cfg["subject"] == "one" and cfg["poll_s"] == 42


# ---- Y13. a send tool that times out is one line, not a traceback ----------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--to", "b", "--info", "hi"],
        ["send", "--to", "b", "--info", "hi", "--dry-run"],
        ["send", "--card"],
        ["revoke", "--statement", "x", "--grant", "GRANT"],
    ],
    ids=["send", "send-dry-run", "send-card", "revoke"],
)
def test_a_send_tool_that_times_out_is_one_line_and_exit_1(pair, capsys, monkeypatch, argv):
    """Y13: the runner raising subprocess.TimeoutExpired: exit 1, one line naming
    the timeout, no traceback; the outbox unchanged (nothing was sent, nothing
    recorded); the revocation's feed line landed first, as before."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "t.txt"), principal_statement=STATEMENT
    )
    argv = [g["grant_id"] if x == "GRANT" else x for x in argv]

    def runner(cmd):
        raise subprocess.TimeoutExpired(cmd, 120)

    monkeypatch.setattr(mailmod, "default_runner", runner)
    feed_before = len(a.revocations.entries())
    assert main([*_argv(a), *argv]) == 1
    out = capsys.readouterr()
    lines = [x for x in out.err.splitlines() if x.strip()]
    assert len(lines) == 1 and "did not return" in lines[0] and "TimeoutExpired" in lines[0]
    # delivery is UNKNOWN after a timeout (the mailbox may have taken the message first):
    # the line never promises "nothing sent" (round-19 self-gate, third run)
    assert "delivery unknown" in lines[0] and "nothing sent" not in lines[0]
    assert "Traceback" not in out.err
    assert a.outbox() == []
    assert len(a.revocations.entries()) == feed_before + (1 if argv[0] == "revoke" else 0)


def test_main_catches_a_subprocess_error_from_any_verb(pair, capsys, monkeypatch):
    """Y13: `main` turns a SubprocessError that escapes a verb into one line, exit 1."""
    a, b, clock, reports = pair

    def boom(self):
        raise subprocess.SubprocessError("the helper died")

    monkeypatch.setattr(mailmod.MailWire, "poll_once", boom)
    assert main([*_argv(a), "poll"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == "natively: the helper died"


# ---- Y14. _receive_ack ledgers before it marks -----------------------------------------------


def test_a_failed_ack_append_leaves_the_entry_pending_and_the_retry_records_it_once(
    pair, monkeypatch
):
    """Y14, the Fable G4 shape: the out.ack append raises EIO — StorageError, the
    outbox entry still pending, the peer head unwritten, nothing ledgered; the retry
    applies with ONE out.ack line whose detail names no missing entry, the entry
    acked once, the head written."""
    a, b, clock, reports = pair
    bundle = a.compose_info(b.card, "hello")
    msg_id = bundle["object"]["msg_id"]
    a.outbox_record(bundle)
    (ack,) = b.receive(bundle)
    real_append = a.ledger.append
    state = {"fail": True}

    def append(**kw):
        if state["fail"] and kw["action"] == "out.ack":
            state["fail"] = False
            raise OSError(5, "Input/output error")
        return real_append(**kw)

    monkeypatch.setattr(a.ledger, "append", append)
    before = len(a.ledger)
    with pytest.raises(StorageError):
        a.receive(ack)
    assert a.outbox_entry(msg_id)["status"] == "pending"
    assert a.peer_head(b.agent.public) is None and len(a.ledger) == before
    assert a.receive(ack) == []
    lines = [e for e in a.ledger.entries() if e["action"] == "out.ack" and e["msg_id"] == msg_id]
    assert len(lines) == 1 and "no outbox entry" not in lines[0]["detail"]
    assert "already" not in lines[0]["detail"]
    assert a.outbox_entry(msg_id)["status"] == "acked"
    assert a.peer_head(b.agent.public) == b.ledger.head()


def test_a_re_delivered_ack_names_the_entrys_state_in_its_line(pair):
    """Y14: the same ack delivered twice: the second line says the entry was already
    acked (the store as it stands), never "(no outbox entry)" for an entry that
    exists."""
    a, b, clock, reports = pair
    bundle = a.compose_info(b.card, "hello")
    msg_id = bundle["object"]["msg_id"]
    a.outbox_record(bundle)
    (ack,) = b.receive(bundle)
    assert a.receive(ack) == [] and a.receive(ack) == []
    lines = [e for e in a.ledger.entries() if e["action"] == "out.ack" and e["msg_id"] == msg_id]
    assert len(lines) == 2
    assert "no outbox entry" not in lines[0]["detail"] and "already acked" in lines[1]["detail"]
    assert "no outbox entry" not in lines[1]["detail"]


# ---- the round-19 self-gate: three findings on this round's own work, fixed in-family ---------


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
def test_a_repeated_member_in_an_unterminated_last_line_is_corruption_never_a_torn_tail(
    pair, store
):
    """Self-gate (Y3): the last line of the ledger, the feed or the denial store with one
    member twice and NO newline is that store's corruption by name (ledger.corrupt,
    feed.corrupt, denial.corrupt) at every read — never `<store>.torn`, never offered by
    `torn_tail` for the cut — and the repair verb exits 2 with the file byte-identical.
    Before, the duplicate failed the parse like a torn write and `torn_tail()` returned
    the whole record for the cut (the reviewer's probe: 420 bytes of feed, 399 of
    denials, the ledger's last entry)."""
    a, b, clock, reports = pair
    if store == "ledger":
        # the fixture's last entry (a's card received) is anchored by no stored ack:
        # the damage is judged as framing, not as a tear inside an anchored entry
        # (that is ledger.head.mismatch by name — refused too, never cut)
        node, obj, name, member, verb = b, b.ledger, "ledger", "outcome", ["ledger", "repair"]
    elif store == "feed":
        a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
        node, obj, name, member, verb = a, a.revocations, "feed", "revokes", ["feed", "repair"]
    else:
        kp = keys.KeyPair.generate()
        d = denialmod.sign(
            denialmod.build(
                principal_key=kp.public,
                ts=fmt(b.now()),
                deny=[{"action": "*", "resource": "*"}],
                principal_statement="stop",
            ),
            kp,
        )
        b.denials.path.write_text(
            json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        node, obj, name, member, verb = b, b.denials, "denial", "deny", ["denial", "repair"]
    path = obj.path
    data = path.read_bytes()
    assert data.endswith(b"\n") and obj.entries()  # a sound store to damage
    lines = data[:-1].split(b"\n")
    rec = json.loads(lines[-1])
    dup = lines[-1][:-1] + b"," + json.dumps({member: rec[member]}, ensure_ascii=False)[1:].encode()
    damaged = b"\n".join([*lines[:-1], dup])  # a whole record, one member twice, no newline
    assert durable.is_torn_text(dup) is False
    path.write_bytes(damaged)
    for read in (obj.torn_tail, obj.entries):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == f"{name}.corrupt", (read.__name__, e.value)
        assert f"duplicate member name '{member}'" in str(e.value)
    assert main([*_argv(node), *verb]) == 2
    assert path.read_bytes() == damaged


def test_a_torn_write_is_still_cut_and_a_whole_record_is_still_terminated(pair):
    """Self-gate (Y3), the other side: `is_torn_text` keeps the two shapes the repair
    handles — a tail that ends early is torn (cut), a whole record short of only its
    newline is not (terminated) — and nothing but a repeated member changes class."""
    a, b, clock, reports = pair
    a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
    path = a.revocations.path
    line = path.read_bytes()[:-1]
    assert durable.is_torn_text(line[: len(line) // 2]) is True
    assert durable.is_torn_text(line) is False
    # round 20 (the prefix rule): an invalid byte is bytes this node never wrote —
    # corruption, never a tear (before, any decode failure read as a torn write)
    assert durable.is_torn_text(b"\xff\xfe{") is False
    assert durable.is_torn_text(b'{"a":"\xe2\x82') is True  # an incomplete character at the end
    path.write_bytes(line + b"\n" + line[: len(line) // 2])
    assert a.revocations.torn_tail() == line[: len(line) // 2]
    path.write_bytes(line)
    assert a.revocations.torn_tail() == b"" and len(a.revocations.entries()) == 1


VARIANT_SHAPES = [
    "(?x)(a{2}) {2}",  # verbose mode: whitespace between the group and its quantifier
    "(?x)(a{2})#c\n{2}",  # verbose mode: a comment between them
    "(?|a{2}){2}",  # branch reset
    "(a)(?(1)a{2}|b){2}",  # a conditional
    "(?#c)a",  # a comment group
    "(?R)",  # recursion
    "(?1)",  # a subroutine call by number
    "(?&n)",  # ... by name
    "(?P>n)",  # ... the other spelling
    "(?P=n)",  # a named backreference the scan does not follow
    "(?V1)[[a]--[b]]{2}",  # the version flag: nested sets move where a class ends
    "(?:a){e<=3}",  # the engine's fuzzy brace
    "a{}",
    "a{,}",
    "a{b}",
]


@pytest.mark.parametrize("pattern", VARIANT_SHAPES)
def test_group_constructs_and_braces_the_scan_cannot_follow_are_refused_at_issue(pair, pattern):
    """Self-gate (Y11): a `(?` construct outside the admitted set, or a brace outside a
    class that is not a counted quantifier, is refused by name at issue (nothing
    stored), in milliseconds. Before, the scan passed over any `(?…` and read any other
    brace as a literal, so `(?x)(a{256}) {256}` and `(?|a{256}){256}` carried a nested
    repetition to the engine."""
    a, b, clock, reports = pair
    why = grantmod.pattern_problem(pattern)
    assert why is not None and "outside the constraint language" in why
    t0 = time.monotonic()
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "v.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert time.monotonic() - t0 < 1.0
    assert "grant.constraint.pattern" in str(e.value)
    assert not list(a.state.glob("grants/*.json"))


def test_the_engine_reads_a_nested_repetition_in_the_shapes_the_scan_refuses():
    """Self-gate (Y11): the four bypass shapes compile in the engine and match as the
    nested repetition they are — so the scan's refusal is what stands between the wire
    and the compile, and the reviewer's small forms stand for the 256-by-256 ones."""
    for pattern, text in [
        ("(?x)(a{2}) {2}", "aaaa"),
        ("(?x)(a{2})#c\n{2}", "aaaa"),
        ("(?|a{2}){2}", "aaaa"),
        ("(a)(?(1)a{2}|b){2}", "aaaaa"),
    ]:
        assert regex.fullmatch(pattern, text) is not None, pattern
        assert grantmod.pattern_problem(pattern) is not None


@pytest.mark.parametrize(
    "pattern",
    [
        "(?-i:a)+",
        "(?>ab)+",
        r"\x41",
        "(?<=a)b",
        "(?<!a)b",
        "(?P<n>x)+",
        "(?i:a)b",
        "a{2}+",
    ],
)
def test_the_constructs_the_old_scanner_admitted_are_refused_by_the_language(pair, pattern):
    """Self-gate (Y11), reversed by round 20: scoped and negated flags, an atomic
    group, a hex escape, a bare brace inside a class, both lookbehinds, the
    P-spelled named group and a possessive quantifier were inside the scanner's
    whitelist; the constraint language refuses every one by name (the README's
    migration note lists them)."""
    a, b, clock, reports = pair
    why = grantmod.pattern_problem(pattern)
    assert why is not None and "outside the constraint language" in why, pattern
    with pytest.raises(ValueError, match="grant.constraint.pattern"):
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "ok.txt", regex=pattern),
            principal_statement=STATEMENT,
        )


def test_the_grant_store_and_the_card_import_write_under_the_state_lock(
    pair, tmp_path, monkeypatch
):
    """Self-gate (Y2): `issue_grant`, `delegate_grant` and `import_card` — the writes a
    verb reaches without the receive's lock — run under the state lock (the lock depth
    is at least 1 at every write), and every state write in node.py goes through
    `Node._write_state` (the one call of the writer in the file). Before, the reviewer's
    probe saw the grant files written at lock depth 0."""
    a, b, clock, reports = pair
    c = make_node(tmp_path, "c", clock)  # a principal b has not pinned
    writes: list[tuple[str, int]] = []
    real = nodemod._write_json
    node = a

    def spy(path, obj):
        writes.append((f"{path.parent.name}/{path.name}", node._lock_depth))
        real(path, obj)

    monkeypatch.setattr(nodemod, "_write_json", spy)
    g = a.issue_grant(  # to a itself, so a (the subject) may delegate it on to b
        subject_card=a.card,
        scope=fs_write_scope(a, "l.txt", regex=None),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    a.delegate_grant(
        parent=g,
        subject_card=b.card,
        scope=fs_write_scope(a, "l.txt", regex=None),
        principal_statement=STATEMENT,
    )
    assert [w[0].split("/")[0] for w in writes] == ["grants", "grants"]
    assert all(depth >= 1 for _, depth in writes), writes
    writes.clear()
    node = b
    h, trusted = b.import_card(c.card)
    assert not trusted and writes == [(f"cards-pending/{h[7:]}.json", 1)]
    src = Path(nodemod.__file__).read_text(encoding="utf-8")
    assert re.findall(r"\b_write_json\(", src) == ["_write_json("]


def test_the_grant_verb_blocks_while_another_holder_has_the_state_lock(tmp_path):
    """Self-gate (Y2): while another holder has the state lock, `natively grant` writes
    nothing — the grants directory stays empty until the lock is released, then the
    grant lands and the verb exits 0."""
    n = make_node(tmp_path, "n", Clock())
    grants = n.state / "grants"
    argv = ["grant", "--to", "self", "--file", "g.txt", "--action", "fs.write", "--statement", "s"]
    rcs: list[int] = []
    t = threading.Thread(target=lambda: rcs.append(main([*_argv(n), *argv])))
    with n.locked():
        t.start()
        time.sleep(0.5)
        assert t.is_alive() and list(grants.iterdir()) == []
    t.join(10)
    assert rcs == [0] and len(list(grants.glob("*.json"))) == 1


# ---- the round-19 self-gate, second run: eight findings, fixed in-family --------------------


@pytest.mark.parametrize(
    "pattern",
    [r"\d{257}", r"(\d{2}){2}", "(a{2})(?i){2}", r"\w{1000000000}", r"(\p{L}{2}){2}", r"\s{300}"],
)
def test_a_brace_after_a_plain_escape_is_a_quantifier_and_global_flags_keep_the_atom(pair, pattern):
    """Second run, finding 1: only \\p \\P \\N take a brace ARGUMENT — a brace after any
    other escape is a quantifier on it and is bounded like a{257}; and a quantifier
    after global flags applies to the atom before them ((a{2})(?i){2} matches aaaa in
    the engine), so the flags leave the scan's view of the previous token alone."""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(pattern) is not None
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "e.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert "grant.constraint.pattern" in str(e.value)
    assert regex.fullmatch("(a{2})(?i){2}", "aaaa") is not None  # the engine's reading


@pytest.mark.parametrize(
    "pattern",
    [r"\p{L}{1,3}", r"\d{1,256}", "(?i)a{2}", r"\N{LATIN SMALL LETTER A}{2}"],
)
def test_escape_arguments_and_bounded_escape_quantifiers_are_refused_too(pair, pattern):
    """Second run, reversed by round 20: a property escape with its argument, a
    bounded counted quantifier, a global flag and a named character are outside the
    constraint language (no \\p \\P \\N, no braces, no `(?`), refused by name."""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(pattern) is not None, pattern
    with pytest.raises(ValueError, match="grant.constraint.pattern"):
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "e.txt", regex=pattern),
            principal_statement=STATEMENT,
        )


def test_the_time_window_is_judged_on_a_clock_read_after_every_slow_read(pair, monkeypatch):
    """Second run, finding 2: `grant.verify` reads its `now` before the card, the pins,
    the config and the feed are read; a clock that moves during the recheck's own
    revocation read (T+3, the grant expiring at T+2) judged the window at the earlier
    reading and ran the executor. `grant.check_time` is now the recheck's LAST step
    on a fresh reading: refused grant.expired, zero executor calls, no use consumed."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "late2.txt"),
        principal_statement=STATEMENT,
        expires_in_s=2,
    )
    real = b.revocations.grant_revoked_by
    calls = [0]

    def revoked_by(*args, **kw):
        calls[0] += 1
        if calls[0] == 2:  # the recheck's read, after `verify` read its `now`
            clock.tick(3)
        return real(*args, **kw)

    monkeypatch.setattr(b.revocations, "grant_revoked_by", revoked_by)
    executor_calls = _count_executor_calls(monkeypatch)
    (rep,) = b.receive(write_bundle(a, b, g, "late2.txt"))
    assert rep["object"]["outcome"] == "refused:grant.expired"
    e = latest(b)
    assert "crossed between verification and execution" in e["detail"]
    assert executor_calls == [0] and not (b.scratch_dir / "late2.txt").exists()
    assert b.grant_uses(g) == (0, None) and b._reservations() == []


def test_tilde_is_expanded_once_so_the_checks_judge_the_path_the_executor_uses(
    tmp_path, monkeypatch
):
    """Second run, finding 3: the separation checks expanded `~` and the node did not,
    so a scratch `~/x` beside a state `./~/x` passed both checks while the executor's
    root WAS the state directory. The node (and the CLI's _dirs) expand `~` once, so the
    path judged is the path used: the pair constructs with distinct directories, an
    equal pair refuses, and the CLI hands the node expanded paths."""
    monkeypatch.setenv("HOME", str(tmp_path))
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    literal = tmp_path / "~" / "x"  # a directory literally named ~
    literal.mkdir(parents=True)
    n = Node(state_dir=literal, keys_dir=kd, scratch_dir=Path("~/x"))
    assert n.scratch_dir == tmp_path / "x" and (tmp_path / "x").is_dir()
    assert n.state == literal and n.scratch_dir.resolve() != n.state.resolve()
    with pytest.raises(ValueError) as e:
        Node(state_dir=Path("~/x"), keys_dir=kd, scratch_dir=Path("~/x"))
    assert "the executor's root never is" in str(e.value)
    ns = argparse.Namespace(state="~/s", keys="~/k", scratch="~/x")
    assert cli._dirs(ns) == (tmp_path / "s", tmp_path / "k", tmp_path / "x")


def _grant_verb(a, *rest):
    return [
        *_argv(a),
        "grant",
        "--to",
        "b",
        "--file",
        "w.txt",
        "--action",
        "fs.write",
        "--statement",
        "s",
        *rest,
    ]


def test_an_explicit_empty_window_is_refused(pair, capsys):
    """Second run, finding 4: `--window ""` is a window given and malformed, refused by
    name with nothing issued — before it was read as no window at all."""
    a, b, clock, reports = pair
    assert main(_grant_verb(a, "--window", "")) == 1
    err = capsys.readouterr().err
    assert "--window" in err and err.count("\n") == 1
    assert not list(a.state.glob("grants/*.json"))


def test_a_bad_param_is_refused_before_the_node_is_constructed(pair, capsys, monkeypatch):
    """Second run, finding 5: every --param is parsed before the node is built (its
    startup sweep replays held revocations and writes the ledger), so a bad value
    does no work at all."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before --param was validated")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main(_grant_verb(a, "--param", "x=range:nan,1")) == 1
    assert "bad --param" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["grant", "--to", "b", "--action", "info", "--statement", "s", "--max-uses", "abc"],
        ["run", "--interval", "nope"],
        ["ledger", "show", "--tail", "nope"],
        ["nonesuch"],
    ],
    ids=["max_uses", "interval", "tail", "verb"],
)
def test_argparses_own_refusal_is_one_line_and_exit_1(pair, capsys, argv):
    """Second run, finding 6: a value argparse itself refuses (a non-integer --max-uses,
    an unknown verb) is a Usage error like every other bad value — one line, exit 1 —
    not argparse's usage block and exit 2."""
    a, b, clock, reports = pair
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert err.startswith("natively: ") and err.count("\n") == 1, err
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0


def test_a_failure_before_the_file_object_closes_the_temp_descriptor(tmp_path, monkeypatch):
    """Second run, finding 7: an fchmod failure after mkstemp left the raw descriptor
    open (the cleanup removed the name only). It is closed before the error
    propagates, and no temp file remains."""
    fds: list[int] = []
    real_mkstemp = durable.tempfile.mkstemp

    def mkstemp(*a, **kw):
        fd, name = real_mkstemp(*a, **kw)
        fds.append(fd)
        return fd, name

    monkeypatch.setattr(durable.tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(
        durable.os, "fchmod", lambda *a: (_ for _ in ()).throw(OSError("chmod failed"))
    )
    with pytest.raises(OSError, match="chmod failed"):
        durable.write_json(tmp_path / "state.json", {"a": 1})
    (fd,) = fds
    with pytest.raises(OSError):
        os.fstat(fd)  # closed: not leaked to the process
    assert list(tmp_path.iterdir()) == []


def test_a_config_the_loader_refuses_lands_nothing_of_the_bundle(pair, tmp_path):
    """Second run, finding 8: the configuration is read (validated) before anything of a
    bundle lands — before, an attached card from an unpinned principal was written to
    cards-pending and ledgered card.received before the read refused, and a retry
    repeated the audit. Now: state.corrupt with no pending card, no ledger line, no
    reservation, for a card bundle and for an action bundle alike."""
    a, b, clock, reports = pair
    c = make_node(tmp_path, "c", clock)  # a principal b has not pinned
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "cfg.txt"), principal_statement=STATEMENT
    )
    (b.state / "config.json").write_text("{not json", encoding="utf-8")
    ledger_before = b.ledger.path.read_bytes()
    for bundle in (c.compose_card(), write_bundle(a, b, g, "cfg.txt")):
        with pytest.raises(StorageError) as e:
            b.receive(bundle)
        assert "state.corrupt" in str(e.value)
    assert list((b.state / "cards-pending").iterdir()) == []
    assert b.ledger.path.read_bytes() == ledger_before
    assert b._reservations() == [] and not (b.scratch_dir / "cfg.txt").exists()


# ---- the round-19 self-gate, third run: eight findings, fixed in-family -----------------------


def test_the_separation_checks_compare_filesystem_identity_not_spelling(tmp_path):
    """Third run, finding 1: the scratch checks compared resolved paths lexically, so a
    case alias of the state directory on a case-insensitive filesystem (`../NATIVELY/
    state`) passed and the executor's root WAS the state. The checks now compare
    (device, inode) identity of every existing ancestor: the case alias and a symlink
    alias both refuse, before any file is touched."""
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    state = tmp_path / "state"
    state.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(tmp_path)
    with pytest.raises(ValueError, match="the executor's root never is"):
        Node(state_dir=state, keys_dir=kd, scratch_dir=link / "state")
    with pytest.raises(ValueError, match="inside the state directory"):
        Node(state_dir=state, keys_dir=kd, scratch_dir=link / "state" / "sub")
    swapped = Path(str(tmp_path).swapcase()) / "state"
    if not swapped.exists():
        pytest.skip("case-sensitive filesystem: the case alias does not exist here")
    with pytest.raises(ValueError, match="the executor's root never is"):
        Node(state_dir=state, keys_dir=kd, scratch_dir=swapped)
    with pytest.raises(ValueError, match="inside the state directory"):
        Node(state_dir=state, keys_dir=kd, scratch_dir=swapped / "sub")
    assert keys._same(swapped, state) and keys._within(swapped / "sub", state)
    assert not keys._within(state, swapped)
    assert not (tmp_path / "sub").exists()


@pytest.mark.parametrize(
    "pattern", ["(a{2}[[:alpha:])(]){2}", "[[a]{2}]", "[[.a.]]{300}", "(a{2}[[:alpha:]){2}", "[abc"]
)
def test_a_posix_class_is_consumed_whole_and_a_bare_bracket_in_a_class_is_refused(pair, pattern):
    """Third run, finding 2: the class scan ended at the `]` of a POSIX class and read
    the rest of the class as grouping syntax, so `(a{2}[[:alpha:])(]){2}` passed as a
    nested repetition (the engine matches it against aabaac). A POSIX class is consumed
    whole; any other bracket inside a class is outside the grammar."""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(pattern) is not None
    with pytest.raises(ValueError, match="grant.constraint.pattern"):
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "px.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert regex.fullmatch("(a{2}[[:alpha:])(]){2}", "aabaac") is not None


@pytest.mark.parametrize("pattern", ["[[:alpha:]]+", "[[:digit:]-]{1,3}", r"[\[]+", "[[:^alpha:]]"])
def test_posix_classes_and_an_escaped_bracket_in_a_class_are_refused_too(pair, pattern):
    """Third run, reversed by round 20: a POSIX class, a counted quantifier and the
    escape `\\[` inside a class are outside the constraint language (a class holds
    literal characters, ranges and the escapes \\] \\\\ \\^ \\-; a literal `[` is
    written outside a class as `\\[`), refused by name."""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(pattern) is not None, pattern
    with pytest.raises(ValueError, match="grant.constraint.pattern"):
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "px.txt", regex=pattern),
            principal_statement=STATEMENT,
        )


def test_a_refused_first_freshness_check_still_anchors_the_monotonic_clock(pair, monkeypatch):
    """Third run, finding 3: the anchor was set only after the wall-clock verdicts
    passed, so a first check that refused (age 361 of 360) left none, and 400
    monotonic seconds later a wall clock stepped back to T+10 made the unchanged
    sidecar pass. The anchor is set when the value is first read, verdict or not."""
    a, b, clock, g = _fresh_pair(pair)
    mono = [1000.0]
    monkeypatch.setattr(revmod, "_monotonic", lambda: mono[0])
    b.mark_lookup_ok()
    s = g["scope"][0]
    limit = g["revocation"]["max_check_interval_s"] + b.poll_s
    b.revocations._anchor = None  # as a fresh process would find it
    clock.tick(limit + 1)
    with pytest.raises(VerifyError, match="revocation.stale"):
        b.revocations.assert_fresh(g, s, b.now(), grace_s=b.poll_s)
    assert b.revocations._anchor is not None  # anchored by the refused read
    mono[0] += 400
    clock.tick(-(limit + 1) + 10)  # the wall clock: 10 s after the lookup
    with pytest.raises(VerifyError, match="monotonic"):
        b.revocations.assert_fresh(g, s, b.now(), grace_s=b.poll_s)


def test_freshness_is_judged_after_every_read_of_the_recheck(pair, monkeypatch):
    """Third run, finding 4: the recheck judged freshness before `_grant_valid_now`'s
    reads; a lookup age crossing the limit during the recheck's own revocation read
    applied. Now the sidecar and every other read come first and freshness is judged
    on a clock reading after them: refused revocation.stale, zero executor calls."""
    a, b, clock, g = _fresh_pair(pair)
    b.mark_lookup_ok()
    limit = g["revocation"]["max_check_interval_s"] + b.poll_s
    real = b.revocations.grant_revoked_by
    calls = [0]

    def revoked_by(*args, **kw):
        calls[0] += 1
        if calls[0] == 2:  # the recheck's revocation read
            clock.tick(limit + 1)
        return real(*args, **kw)

    monkeypatch.setattr(b.revocations, "grant_revoked_by", revoked_by)
    executor_calls = _count_executor_calls(monkeypatch)
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "one\n"))
    assert rep["object"]["outcome"] == "refused:revocation.stale"
    assert "crossed between verification and execution" in latest(b)["detail"]
    assert executor_calls == [0] and not (b.scratch_dir / "t.txt").exists()


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
def test_a_member_named_twice_inside_a_torn_prefix_is_corruption_too(pair, store):
    """Third run, finding 5: the parser's hook runs only when an object closes, so a
    torn prefix carrying two complete `revokes` members read as a torn write and every
    store's `torn_tail` offered it for the cut. `is_torn_text` scans a prefix that does
    not parse for a member named twice: corruption by the store's name at every read,
    never cut."""
    a, b, clock, reports = pair
    if store == "ledger":
        node, obj, name, member, verb = b, b.ledger, "ledger", "outcome", ["ledger", "repair"]
    elif store == "feed":
        a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
        node, obj, name, member, verb = a, a.revocations, "feed", "revokes", ["feed", "repair"]
    else:
        kp = keys.KeyPair.generate()
        d = denialmod.sign(
            denialmod.build(
                principal_key=kp.public,
                ts=fmt(b.now()),
                deny=[{"action": "*", "resource": "*"}],
                principal_statement="stop",
            ),
            kp,
        )
        b.denials.path.write_text(
            json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        node, obj, name, member, verb = b, b.denials, "denial", "deny", ["denial", "repair"]
    path = obj.path
    data = path.read_bytes()
    lines = data[:-1].split(b"\n")
    rec = json.loads(lines[-1])
    dup = (
        lines[-1][:-1] + b"," + json.dumps({member: rec[member]}, ensure_ascii=False)[1:-1].encode()
    )
    # a torn PREFIX: the object never closes, the two members are both complete
    assert durable.is_torn_text(dup) is False
    assert durable.is_torn_text(lines[-1][:-1]) is True  # the same prefix without the repeat
    damaged = b"\n".join([*lines[:-1], dup])
    path.write_bytes(damaged)
    for read in (obj.torn_tail, obj.entries):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == f"{name}.corrupt", (read.__name__, e.value)
    assert main([*_argv(node), *verb]) == 2
    assert path.read_bytes() == damaged


def test_regex_constraints_and_an_expiry_ceiling_are_validated_before_the_node(
    pair, capsys, monkeypatch
):
    """Third run, findings 6 and 7: `--param content=regex:(a{2}){2}` and
    `--expires-in 999999999999999999999999` reached node startup (the sweep replays
    revocations and writes the ledger) before their refusal — the second as an
    uncaught OverflowError. Both are Usage errors before `_node`."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was validated")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main(_grant_verb(a, "--param", "content=regex:(a{2}){2}")) == 1
    err = capsys.readouterr().err
    assert "bad --param" in err and "grant.constraint.pattern" in err and err.count("\n") == 1
    assert main(_grant_verb(a, "--expires-in", "999999999999999999999999")) == 1
    err = capsys.readouterr().err
    assert "--expires-in must be at most" in err and err.count("\n") == 1
    assert main(_grant_verb(a, "--window", f"1,{cli.MAX_SECONDS + 1}")) == 1
    assert "SECONDS at most" in capsys.readouterr().err
