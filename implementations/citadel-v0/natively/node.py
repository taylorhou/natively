"""The node: identity, trust store, grants, ledger, feeds, executor, and the receive
pipeline. Transport-free; adapters hand it bundles and send what it returns.

State directory layout (public material only; keys live in the keys dir):
  config.json            peer_email, peer_addresses, self_email, subject, poll_s, extensions
  self.card.json         this agent's signed card
  pinned.json            principal roots this node accepts, key -> {name, pinned_at}
  cards/<hash>.json      cards from pinned principals (trusted; revocation checked at use)
  cards-pending/<hash>.json  cards seen but not yet pinned (never trusted)
  grants/<id>.json       every grant issued, or received TOP-LEVEL (authenticated first);
                         the only grants a message may name for execution
  grants-embedded/<id>.json  parents first met inside a delegated child: read for identity
                         and budget checks, never executable until the same parent
                         arrives top-level
  ledger.jsonl + ledger.prose.txt
  revocations.jsonl + revocations.check.json
  denials.jsonl
  seen.json              msg_id -> the ack we produced, or an in_progress reservation
  outbox.json            our sends awaiting acks, with retry deadlines
  peer-heads.json        the ledger head each peer reported in its last ack
  revocations-pending/<rev_id>-<12 hex of the body hash>.json  revocations from principals
                         not pinned yet (signature already checked against the key they
                         name); never overwritten; pin() and the startup sweep replay them
  replay-pending.json    written by a startup sweep that could NOT replay (the feed is
                         torn): the principals whose held revocations are not in the feed
                         yet. While it exists nothing is authorized: _apply_action first
                         attempts the replay itself (the feed may have been repaired by
                         another process); a replay that fails is the storage failure it
                         is (the feed still torn or corrupt, the held directory unreadable,
                         a held copy corrupt: the mail unseen, nothing ledgered, nothing
                         acked, re-evaluated next poll); `feed repair` replays and removes it
  ledger-repair-pending.tail.json  the subordinate tail stage under a standing MIRROR
                         intent: the mirror repair's own audit append may tear the JSONL's
                         tail (power loss inside it, the mirror marker at step
                         "truncated"); `ledger repair` cuts that torn tail under this nested
                         marker (the same machine, ledgered ledger.tail_truncated) and then
                         resumes the mirror repair; it exists only beside a mirror intent
  feed-repair-pending.json / denial-repair-pending.json / ledger-repair-pending.json
                         the intent of a repair verb, a small resumable state machine:
                         step "intent" (which file, the byte offset to cut at, the hash of
                         the bytes to be cut, an intent id) written BEFORE the truncation;
                         the truncation, fsynced (file, then directory); step "truncated";
                         the <store>.repaired / ledger.mirror_truncated ledger entry naming
                         the intent id; step "audited" with that entry's hash; then the
                         marker removed. A retry or a restart resumes at the recorded step,
                         so a crash anywhere in between truncates once and audits once
  .lock                  flock held by EVERY ledger writer (re-entrant per Node instance)

No state directory is ever enumerated with Path.glob or Path.iterdir (both read an
unreadable directory as empty, and an empty revocations-pending/ is an authorization
decision): every listing goes through durable.list_dir, and an enumeration failure is
a storage failure — the startup sweep writes the replay marker, the authorization path
refuses, the repair verb leaves the marker.

No state file is read as a structure except through state.read, the ONE typed loader
(state.py: the top-level type and the per-entry shape the code relies on, checked at
the read; a mismatch is IntegrityError state.corrupt — card.corrupt for a card on
file, card.self_corrupt for the self card — naming the path and why). Local state is
never peer input: a file of ours of the wrong shape is a storage failure wherever it
surfaces (receive refuses with nothing ledgered and the mail unseen; the CLI exits 2
naming the path; a node whose config, trust store or self card fails does not
construct), never a verify_failed:malformed verdict on the bundle in hand.

Replay and use limits are atomic per process: every ledger writer (receive, revoke,
deny, pin, the outbox and freshness bookkeeping, the CLI ledger verbs, and the mail
adapter's whole poll) runs under one exclusive lock on state/.lock, re-entrant within
a Node instance, so two writers can never capture the same ledger head. A use is
RESERVED in seen.json before the executor runs (the file and its directory entry
fsynced), and the reservation becomes the stored ack only after the ledger entry and
the ack are written. A re-delivered message whose ack was never stored is answered
from its ledger completion entry (nothing re-evaluated or re-executed); an
interrupted reservation (no ledger entry) fails closed: the use stays consumed and
the re-delivery is acked "failed:interrupted", once. An executor failure after its
side effect existed is "failed:post_commit" and consumes the use too. A local storage
failure while a bundle is applied (OSError) is a StorageError, never "malformed": the
adapter leaves that mail unseen and moves neither the cursor nor the freshness clock.
The mail seen-file assumes a single poller per state directory (README)."""

from __future__ import annotations

import fcntl
import os
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from . import ack as ackmod
from . import bundle as bundlemod
from . import card as cardmod
from . import denial as denialmod
from . import grant as grantmod
from . import keys
from . import message as msgmod
from . import revocation as revmod
from . import state as statemod
from .canon import canonicalize, hash_of, sha256_hex
from .durable import (
    fsync_dir,
    fsync_existing,
    is_blank_line,
    list_dir,
    torn_text_problem,
    write_json,
)
from .errors import IntegrityError, PostCommitError, RefusedError, StorageError, VerifyError
from .executor import Executor
from .ledger import OUT_ACK, OUT_SEND, OUTBOUND_PREFIX, Ledger, entry_hash, outcome_kind
from .objects import check_id, is_id, new_id
from .timeutil import fmt, now_utc, parse, plus

DEFAULT_CONFIG = {
    "peer_email": "taylor@teale.com",
    "peer_addresses": ["taylor@teale.com", "taylor@hou.vc"],
    "self_email": "taylor@houmanoids.com",
    "mail_account": "taylor",  # the helper's --account; the profile it answers must be self_email
    "subject": "Natively v0 wire",
    "poll_s": 60,
    "extensions": {"max_uses_per_window": False, "standing_denial": False},
}
# Wait after send number 1, 2, 3, 4 (x poll_s): sent, re-sent at 2P, re-sent 4P after
# that, re-sent 8P after that, then undelivered when the 16P deadline passes.
RETRY_MULTIPLIERS = (2, 4, 8, 16)
MAX_RESENDS = 3
REPLAY_MARKER = "replay-pending.json"
REPAIR_STEPS = statemod.REPAIR_STEPS
# the nested marker of the JSONL-tail stage that runs UNDER a standing mirror intent
# (the mirror repair's own audit append tore the JSONL's tail); beside
# ledger-repair-pending.json only, never on its own
LEDGER_TAIL_MARKER = "ledger-repair-pending.tail.json"
# the store each repair audit records, by the audit's action: a found audit is bound to
# the marker's store name through it before it is trusted (`_repair_audit`)
AUDIT_STORES = {
    "ledger.tail_truncated": "ledger.jsonl",
    "ledger.mirror_truncated": "ledger.prose.txt",
    "feed.repaired": "revocations.jsonl",
    "denial.repaired": "denials.jsonl",
}
_MISSING = object()  # a state file that is ABSENT (a present `null` is not "absent")


# the durable primitives live in durable.py (shared with the feed and the adapter);
# these names stay for the callers that import them from here (the tests inject
# write failures through them). Reads go through state.read, never read_json.
_fsync_dir = fsync_dir
_write_json = write_json


def _msg_id_of(b: Any) -> str | None:
    if isinstance(b, dict) and isinstance(b.get("object"), dict):
        v = b["object"].get("msg_id")
        if is_id(v, "msg_"):
            return v
    return None


@contextmanager
def state_lock(state_dir: Path) -> Iterator[None]:
    """The state lock of `state_dir` for a caller that has NO node — the config
    verb repairing a config no node constructs over (`cli.cmd_config`): the same
    exclusive flock on state/.lock every ledger writer and every state write holds,
    not re-entrant (one holder per call). The directory is created when missing,
    as a node's construction would."""
    d = Path(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    fd = os.open(d / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def effective_config(state_dir: Path) -> dict[str, Any]:
    """config.json under `state_dir` read NOW through the typed loader
    (state.config: the known keys of their types, else state.corrupt naming the
    path), the package defaults beneath it and the default extension flags beneath
    its extensions. The one way the enforcement configuration is read."""
    cfg = {**DEFAULT_CONFIG, **statemod.read(Path(state_dir) / "config.json", {}, statemod.config)}
    cfg["extensions"] = {**DEFAULT_CONFIG["extensions"], **cfg.get("extensions", {})}
    return cfg


class Node:
    def __init__(
        self,
        *,
        state_dir: Path,
        keys_dir: Path,
        scratch_dir: Path,
        clock: Callable[[], datetime] | None = None,
        report: Callable[[str], None] | None = None,
    ):
        # `~` expanded ONCE, here, so the paths the checks compare are the paths the
        # node and the executor use: with the checks expanding and the node not, a
        # scratch `~/x` beside a state `./~/x` passed both checks and the executor's
        # root was the state directory (round-19 self-gate, second run)
        self.state = Path(state_dir).expanduser()
        self.keys_dir = Path(keys_dir).expanduser()
        self.scratch_dir = Path(scratch_dir).expanduser()
        keys.check_separation(self.keys_dir, state_dir=self.state, scratch_dir=self.scratch_dir)
        # the executor's root kept apart from the state and the code (ValueError
        # before any file is touched): a scratch equal to, inside or containing the
        # state directory let a scratch-scoped grant naming seen.json or
        # revocations.jsonl replace enforcement state (round-19 gate, finding 4)
        keys.check_scratch_separation(self.scratch_dir, state_dir=self.state)
        self.state.mkdir(parents=True, exist_ok=True)
        # the scratch root is created once, here, and its identity (dev, ino) is what
        # every executor this node builds must find at the configured path — and
        # NOW, with both directories existing, the separation is judged again by
        # filesystem identity alone (`check_scratch_identity`): a case or
        # normalization pair the fold could not see (the interpreter's Unicode
        # tables lag the kernel's; round-20 Fable read, N1 and N2) is refused here,
        # before any file is written under either directory — no lock file, no
        # subdirectory, no state file, no executor write
        self.scratch_identity = Executor.create_root(self.scratch_dir)
        keys.check_scratch_identity(self.scratch_dir, state_dir=self.state)
        self.clock = clock or now_utc
        self.report = report or (lambda s: print(s, file=sys.stderr))
        # every state file read as a structure comes through state.read (the typed
        # loader): a config of the wrong shape refuses construction, state.corrupt.
        # This copy is the construction-time snapshot the adapter's addresses and
        # `save_config` use; what gates ENFORCEMENT (`extensions`, `poll_s`) is read
        # from the file again at every use (`_config_now`), never from this cache
        self.config = effective_config(self.state)
        self.ledger = Ledger(self.state / "ledger.jsonl")
        # every ledger append refuses while a repair of the mirror is unfinished
        self._repair_active: str | None = None
        self.ledger.guard = lambda: self._refuse_if_repairing("ledger", "ledger.prose.txt")
        # every full check of the ledger (check_intact: every receive and the pin;
        # verify: the verb) anchors the chain's tail to the acks this node stored,
        # each authenticated first
        self.ledger.anchors = self._stored_ack_anchors
        self.revocations = revmod.RevocationFeed(self.state / "revocations.jsonl")
        self.denials = denialmod.DenialStore(self.state / "denials.jsonl")
        for d in ("cards", "cards-pending", "grants", "grants-embedded"):
            (self.state / d).mkdir(exist_ok=True)
        self._keys: dict[str, keys.KeyPair] = {}
        # the self card, when there is one, is verified at construction (structure,
        # both signatures, bound to this node's own keys): a node never starts as an
        # identity that is not its own — card.self_corrupt, a storage failure
        if (self.state / "self.card.json").exists():
            self._self_card()
        self._lock_guard = threading.RLock()
        self._lock_fd: int | None = None
        self._lock_depth = 0
        # Startup sweep: a held revocation whose principal is already pinned (a pin
        # that died after publishing trust, or a state written by an older node) is
        # replayed before anything in this process can authorize a grant it covers.
        with self._locked():
            self._startup_sweep()

    def _startup_sweep(self) -> None:
        # the trust store is read FIRST, outside the sweep's containment: a
        # pinned.json that does not parse or has the wrong shape (state.corrupt), or
        # cannot be read, refuses construction like a self card that fails — a node
        # never starts on a trust store it cannot read, and a replay marker naming
        # "every pinned principal" would name nothing
        pinned = self.pinned
        try:
            for pk in pinned:
                self._replay_pending_revocations(pk, why="startup sweep: principal pinned")
        except (OSError, StorageError) as e:
            # the feed is torn or does not verify (IntegrityError), or
            # revocations-pending/ could not be enumerated or read (OSError: an
            # unreadable directory looks like "nothing held" only to a tool that
            # swallows it), or a replay's own write failed, or the ledger refuses the
            # replay entry (IntegrityError: a mirror longer than the JSONL — `ledger
            # repair` needs a constructed node to run), or a repair of the feed is
            # unfinished (its intent marker stands): nothing can be replayed now.
            # Every fault in a file of ours is a StorageError; a VerifyError is a
            # verdict on peer input and none is read here. The ledger's own check
            # runs before the first feed line (`_replay_pending_revocations`), so a
            # ledger that fails it leaves the feed untouched and is named here — the
            # node still constructs, since `natively ledger repair` needs a
            # constructed node (round 7). The held copies stay
            # (fail closed, and
            # loudly), and a DURABLE marker keeps every authorization blocked until
            # they are replayed — a feed repaired by another process, or an older
            # tool, must not reopen authorization on its own. The marker is cleared
            # only when the enumeration AND every replay succeeded.
            skipped = self._held_principals(pinned)
            self.report(
                f"natively: startup sweep skipped, the held revocations could not be "
                f"replayed (`natively feed repair`); nothing is authorized until the "
                f"held revocations of {skipped} are replayed: {type(e).__name__}: {e}"
            )
            self._write_state(
                self.state / REPLAY_MARKER,
                {"principals": skipped, "why": f"{type(e).__name__}: {e}", "ts": self.ts()},
            )
            return
        self._clear_replay_marker()

    def _held_principals(self, pinned: set[str]) -> list[str]:
        """The pinned principals with held revocations on disk (the ones a skipped
        sweep left unreplayed); every pinned principal when the held files themselves
        cannot be listed or read."""
        try:
            return [pk for pk in sorted(pinned) if self._held_revocations(pk)]
        except (OSError, StorageError):
            return sorted(pinned)

    def _replay_pending(self) -> dict[str, Any] | None:
        """The marker a skipped startup sweep left, read fresh (another process may
        have repaired the feed and removed it). A marker of the wrong shape is
        state.corrupt — a storage failure of the authorization path, never "no
        marker": nothing is authorized over a marker that cannot be read."""
        return statemod.read(self.state / REPLAY_MARKER, None, statemod.replay_marker)

    def _clear_replay_marker(self) -> None:
        p = self.state / REPLAY_MARKER
        if p.exists():
            p.unlink()
            _fsync_dir(self.state)

    # ---- repair verbs (the CLI's feed / denial / ledger repair) --------------------------
    def repair_feed(self) -> int:
        """`natively feed repair`, whole under the lock: resume or start the repair of
        a torn partial last line of the revocation feed (the intent state machine,
        `_repair_store`); then replay every held revocation of every pinned
        principal and remove the replay marker — authorization reopens only once
        the enumeration AND every replay ran, never on the truncation alone (an
        enumeration or replay failure propagates and leaves the marker). Returns the
        torn bytes truncated by THIS run (0 on a pure resume)."""
        with self._locked():
            removed = self._repair_store(
                what="feed",
                fname="revocations.jsonl",
                path=self.revocations.path,
                excess=self.revocations.torn_tail,
                validate=lambda i: self._check_store_resume("feed", self.revocations, i),
                whole=self.revocations.load,
                audit_action="feed.repaired",
                describe=lambda n: (
                    f"truncated a torn partial last line ({n} bytes) of revocations.jsonl"
                ),
            )
            for pk in self.pinned:
                self._replay_pending_revocations(pk, why="feed repaired")
            self._clear_replay_marker()
            return removed

    def repair_denials(self) -> int:
        """`natively denial repair`: the same machine for the standing-denial store.
        Returns the torn bytes truncated by THIS run."""
        with self._locked():
            return self._repair_store(
                what="denial",
                fname="denials.jsonl",
                path=self.denials.path,
                excess=self.denials.torn_tail,
                validate=lambda i: self._check_store_resume("denial", self.denials, i),
                whole=self.denials.load,
                audit_action="denial.repaired",
                describe=lambda n: (
                    f"truncated a torn partial last line ({n} bytes) of denials.jsonl"
                ),
            )

    def repair_ledger(self) -> tuple[int, int, int]:
        """`natively ledger repair`, under the lock, three stages, the JSONL first
        because it is the source of truth. (1) An unterminated JSONL tail (an append
        interrupted before its newline): a whole entry of this chain short of only
        its newline is terminated (`Ledger.terminate_tail`, nothing cut); a torn
        partial line is cut by the intent machine and ledgered
        `ledger.tail_truncated` — only when the part before it is this ledger's
        chain in full (else refused by that fault's name, ledger.chain /
        ledger.corrupt, nothing written); a mirror line beyond the entries the cut
        left (an older tool's, before the power cut) is cut under the same intent
        so the audit can land. (2) A mirror with MORE lines than the JSONL has
        entries, or one that does not DECODE (a write torn inside a multibyte
        character; the whole lines before the damage must be their entries'
        prose), is cut back to the JSONL's prose by the same machine, ledgered
        `ledger.mirror_truncated` — entries are never invented from prose, and a
        JSONL that is damaged refuses by its own name with nothing written. (3) The
        missing trailing prose lines are regenerated (`Ledger.repair`, the JSONL
        fsynced before any mirror write). A standing intent names the file it
        cuts, and only that stage resumes; every resumed step validates the JSONL
        (the chain and the framing of the part it stands on, anchored to the acks
        this node stored: an anchored entry is never cut) AND the current mirror
        against it BEFORE it touches either file or the marker
        (`_validate_mirror_resume`, `_validate_tail_resume`), and the audited
        step mends, regenerates and verifies the mirror before the marker goes
        (`_drive_repair`). Under a standing MIRROR intent at step "truncated"
        — the one step at which this machine writes the JSONL (the audit append)
        — a torn JSONL tail is that append's own tear: a subordinate tail stage
        (the same machine under the nested marker ledger-repair-pending.tail.json,
        the same validation, the same audit ledger.tail_truncated) terminates or
        cuts it — only the bytes after the last complete entry that continues the
        chain, only when that prefix is this ledger's chain in full, else refused
        by name with both markers standing — and the mirror repair then resumes
        to completion with exactly one mirror audit. At any other step of a
        mirror intent the JSONL was whole when the marker was written and nothing
        of ours has written it since, so a torn tail there is not this machine's:
        refused by name (ledger.truncated), nothing written. Returns (mirror bytes
        truncated by this run, prose lines regenerated, JSONL tail bytes truncated
        by this run). The fresh run's rule: nothing is written to the JSONL unless
        the mirror is already consistent with the result the newline would produce,
        or an intent stands that can finish it — a whole last entry short of only
        its newline whose mirror line tore after an ASCII prefix (the mend case)
        first gets a TERMINATION intent for the ledger's own tail stage (the same
        marker shape, `bytes` 0, the entry bound by hash, the mirror cut point
        recorded as `mirror_to`), then the newline, the mend, the audit and the
        marker's removal under it, each step resumable; any other mirror shape is
        refused by name with both files byte-identical and no marker
        (`Ledger.fresh_mend_point`; round-14 gate, finding 2: the newline was
        written and the mirror then refused with nothing to finish the mend)."""
        with self._locked():
            intent = self._repair_intent("ledger")
            nested = self._repair_intent("ledger", LEDGER_TAIL_MARKER)
            tail_cut = 0
            if intent is _MISSING or intent["file"] != "ledger.prose.txt":
                if nested is not _MISSING:
                    raise IntegrityError(
                        "ledger.repair.intent_mismatch",
                        f"{LEDGER_TAIL_MARKER} stands (a tail cut nested under a mirror "
                        f"repair) but ledger-repair-pending.json names no mirror intent; "
                        f"nothing truncated, nothing removed: inspect both markers and the "
                        f"ledger before removing either",
                    )
            if intent is _MISSING or intent["file"] == "ledger.jsonl":
                fresh = None
                if intent is _MISSING:
                    # a fresh run over a whole last entry short of only its newline: the
                    # mirror's state is DECIDED before anything is written
                    # (`Ledger.fresh_mend_point`, the three cases in its docstring): the
                    # mirror consistent with the completed chain — the newline as before
                    # (`terminate_tail` checks it once more, a line beyond the entries
                    # being the excess the mirror stage then cuts); the mend case — a
                    # termination intent for this stage FIRST, the newline, the mend, the
                    # audit and the marker's removal under it; anything else refused by
                    # name with the JSONL and the mirror byte-identical and no marker
                    plan = self.ledger.whole_entry_tail()
                    if plan is not None:
                        es, tail = plan
                        mend_at = self.ledger.fresh_mend_point(es)
                        if mend_at is None:
                            self.ledger.terminate_tail(mirror_excess_ok=True)
                            self.report(
                                "natively: the ledger's last entry lacked only its newline "
                                "(interrupted write); terminated"
                            )
                        else:
                            fresh = self._termination_intent(tail, mend_at)
                            self.report(
                                f"natively: the ledger's last entry lacks only its newline "
                                f"(interrupted write) and its mirror line tore after "
                                f"{mend_at} bytes: a termination intent "
                                f"({fresh['intent_id']}) is written first; the newline, the "
                                f"mend and the audit follow under it"
                            )
                    else:
                        # the terminated sibling of the mend case: the last entry landed
                        # WITH its newline and its own prose write then tore after an
                        # ASCII prefix (`Ledger.terminated_mend_point`, nothing written).
                        # The same rule: a finishing intent of the termination shape
                        # FIRST (bytes 0, the entry bound by hash, the mirror cut point
                        # recorded), then the mend, the audit and the marker's removal
                        # under it — the intent step finds the newline already there.
                        # Before, this shape was refused by the fresh run and by every
                        # append and receive, a hand edit the only way out (round-15
                        # Fable read, section D)
                        mend = self.ledger.terminated_mend_point()
                        if mend is not None:
                            entry, mend_at = mend
                            fresh = self._termination_intent(entry, mend_at, terminated=True)
                            self.report(
                                f"natively: the ledger's last entry is whole and terminated "
                                f"and its mirror line tore after {mend_at} bytes (a prose "
                                f"write interrupted after an ASCII prefix): a finishing "
                                f"intent ({fresh['intent_id']}) is written first; the mend "
                                f"and the audit follow under it"
                            )
                tail_cut = self._tail_stage(fresh=fresh)
            else:
                if intent["file"] == "ledger.prose.txt" and (
                    nested is not _MISSING or intent["step"] == "truncated"
                ):
                    # the standing mirror intent's OWN retained prefix first, against
                    # the chain the JSONL holds (the part before the nested cut point
                    # under a nested marker, else the chain as the file stands, its
                    # torn tail aside): a retained prefix missing or replaced is
                    # ledger.prose.mismatch with both files and every marker as found
                    # — before the subordinate stage terminates, cuts or appends
                    # (its audit append regenerated a LOST prefix and completed
                    # before this intent validated it: round-14 self-gate)
                    if intent["step"] == "truncated":
                        # this mirror intent's OWN audit, where it is VISIBLE as the
                        # JSONL's last line (terminated, or short of only its newline),
                        # is bound to the marker FIRST — the ONE binding every found
                        # audit crosses (`_bind_visible_audit` -> `_bind_audit`: the
                        # audit of the store the marker names, the marker's tail hash)
                        # — before the termination below writes its newline and before
                        # the subordinate tail stage cuts or appends: a mismatch refuses
                        # by name with the JSONL, the mirror and the marker byte-identical
                        # on every retry. Before, the newline was written here and the
                        # binding ran only inside the mirror stage's own truncated step
                        # (round-15 gate, finding 1). A torn partial line is no audit:
                        # nothing bound, the mends name or cut it
                        self._bind_visible_audit("ledger", "ledger.mirror_truncated", intent)
                    es_now = (
                        self.ledger.check_prefix(nested["truncate_to"])
                        if nested is not _MISSING
                        else self.ledger.chain_now()[0]
                    )
                    self.ledger.check_prose_prefix(intent["truncate_to"], es_now)
                    # the subordinate tail stage: the mirror repair's own audit
                    # append (step "truncated") may have torn the JSONL's tail; a
                    # nested marker resumes whatever its own step. An audit entry
                    # short of only its newline is terminated only after the CURRENT
                    # mirror is checked against the chain it completes (the mirror
                    # is the standing intent's: nothing beyond the entries belongs
                    # to it) — the newline is never written and the mirror then
                    # refused (round-14 self-gate)
                    if nested is _MISSING and self.ledger.terminate_tail(mirror_excess_ok=False):
                        self.report(
                            "natively: the ledger's last entry (the mirror repair's audit) "
                            "lacked only its newline (interrupted write); terminated"
                        )
                    tail_cut = self._tail_stage(nested=True)
                if self.ledger.path.exists():
                    # a standing MIRROR intent: the JSONL is the source of truth, its
                    # barrier BEFORE the mirror is touched (the tail stage fsyncs it
                    # itself, clean or cut); a barrier that raises leaves the mirror
                    fsync_existing(self.ledger.path)
            truncated = self._repair_store(
                what="ledger",
                fname="ledger.prose.txt",
                path=self.ledger.prose_path,
                excess=self.ledger.excess_prose,
                validate=self._validate_mirror_resume,
                whole=self.ledger.check,
                audit_action="ledger.mirror_truncated",
                describe=lambda n: (
                    f"truncated {n} bytes of ledger.prose.txt that were not the JSONL's prose "
                    f"(lines beyond its entries, or a tail that does not decode); the lines "
                    f"cut are regenerated from the JSONL"
                ),
            )
            return truncated, self.ledger.repair(), tail_cut

    def _termination_intent(
        self, tail: bytes, mirror_to: int, *, terminated: bool = False
    ) -> dict[str, Any]:
        """The fresh mend case's intent for the ledger's own tail stage (nothing is
        cut): `truncate_to` the offset the last entry starts at — `tail` is its
        line without a newline, which the file lacks (the mend case) or already
        carries (`terminated`: the terminated sibling, one byte more before the
        end) — `bytes` 0 (what marks a termination intent), `tail_sha256` the hash
        of that entry's bytes (bound at every resume: `_validate_termination_resume`),
        `mirror_to` the byte offset of the torn mirror line the mend completes."""
        return {
            "step": "intent",
            "file": "ledger.jsonl",
            "truncate_to": os.stat(self.ledger.path).st_size - len(tail) - int(terminated),
            "bytes": 0,
            "tail_sha256": "sha256:" + sha256_hex(tail),
            "mirror_to": mirror_to,
            "intent_id": new_id("rpr"),
            "ts": self.ts(),
        }

    def _tail_stage(self, *, nested: bool = False, fresh: dict[str, Any] | None = None) -> int:
        """The JSONL-tail stage of `repair_ledger`: a torn partial last line of
        ledger.jsonl cut by the intent machine and ledgered ledger.tail_truncated —
        under the ledger's own marker when no intent stands, under the nested
        marker (`LEDGER_TAIL_MARKER`) when a mirror intent stands and this stage is
        subordinate to it. The mirror's excess is the mirror intent's to cut in the
        nested case, so this stage leaves the mirror alone there. With `fresh` (a
        termination intent the verb decided, `_termination_intent`) the stage
        starts from that intent instead of a torn tail: the same machine, the same
        audit action, its detail saying the entry was terminated and its mirror
        line mended, nothing cut — one text for both termination shapes (the
        newline put back, or already there: a resume at "truncated" cannot know
        whether an earlier run wrote it; round-16 Fable read, D2). Returns the
        bytes cut by this run."""
        return self._repair_store(
            what="ledger",
            fname="ledger.jsonl",
            path=self.ledger.path,
            excess=self.ledger.torn_tail,
            validate=lambda i: self._validate_tail_resume(i, nested=nested),
            whole=self.ledger.check,
            audit_action="ledger.tail_truncated",
            describe=lambda n: (
                (
                    f"truncated a torn partial last line ({n} bytes) of ledger.jsonl "
                    f"(an append interrupted before its newline); the chain before it "
                    f"verified" + ("; under a standing mirror repair" if nested else "")
                )
                if n
                else (
                    "terminated the last entry of ledger.jsonl (whole; its newline put back "
                    "where an append had stopped short of it, or already there) and mended "
                    "its mirror line torn after an ASCII prefix, under this intent; nothing "
                    "cut, the chain verified"
                )
            ),
            marker_name=LEDGER_TAIL_MARKER if nested else None,
            mirror_excess=not nested,
            fresh=fresh,
        )

    def _refuse_if_repairing(self, what: str, fname: str) -> None:
        """While the repair intent marker of `what` exists AT ALL — whatever step it
        shows, a step it shows may be visible and unsynced — nothing appends to that
        store (the feed, the denial store, the ledger's mirror through the ledger)
        except the repair verb itself: an append past the recorded cut point would
        make the resume refuse the mismatch forever, and an older durable marker
        restored by power loss would then find a newer tail. Only the marker's
        deletion, the machine's last step, reopens the store. A marker that is not
        an intent refuses too (<what>.repair.intent_corrupt: a human inspects it)."""
        if self._repair_active == what:
            return
        names = [f"{what}-repair-pending.json"]
        if what == "ledger":
            names.append(LEDGER_TAIL_MARKER)  # the nested tail stage closes the ledger too
        for name in names:
            intent = self._repair_intent(what, name)
            if intent is not _MISSING:
                raise IntegrityError(
                    f"{what}.repair_pending",
                    f"a repair of {fname} is unfinished ({name} stands, step "
                    f"{intent['step']!r}); nothing appends to it until `natively {what} "
                    f"repair` ran",
                )

    def _repair_intent(self, what: str, name: str | None = None) -> Any:
        """The repair intent marker of `what` (state/<what>-repair-pending.json, or
        the marker `name` names), typed (state.read): _MISSING when absent; a marker
        that is not an intent (the wrong shape, an older tool's record) is
        IntegrityError <what>.repair.intent_corrupt naming the path — nothing
        truncated, nothing audited, nothing appended, until a human inspects it."""
        return statemod.read(
            self.state / (name or f"{what}-repair-pending.json"),
            _MISSING,
            statemod.repair_intent,
            reason=f"{what}.repair.intent_corrupt",
        )

    def _check_store_resume(self, what: str, store: Any, intent: dict[str, Any]) -> None:
        """What a feed or denial-store repair validates at EVERY step, fresh or
        resumed, before any barrier, cut, audit or marker update: the sound prefix
        before the recorded cut point (`check_prefix`), then the PERMITTED SUFFIX
        for the intent's step. At step "intent" the bytes past the cut point are
        nothing (an earlier run's cut whose barrier may not have returned) or the
        bytes the intent recorded — those judged under the CURRENT prefix rule
        (`durable.torn_text_problem`): an intent a run of an older classifier left
        over bytes that are not a strict prefix of one record (`{"a":1}xyz`)
        refuses by name with nothing truncated and the intent standing (round-20
        self-gate, finding 3); bytes that are neither are the intent step's own
        intent_mismatch refusal, before any write. At step "truncated" and
        "audited" the cut ran, and nothing of ours writes to the store while the
        marker stands (`_refuse_if_repairing`), so the store must END EXACTLY at
        the cut point: any bytes past it are <what>.repair.refused with NOTHING
        written — no audit appended, no marker advanced (round-20 gate, finding 2:
        a standing "truncated" marker over `{"x":1}junk` reached the audit and the
        marker advance, and a restart saw an audit claiming a completed truncation
        over a store still corrupt). The ledger's tail stages judge theirs through
        `chain_now` (`_validate_tail_resume`)."""
        to = intent["truncate_to"]
        store.check_prefix(to)
        try:
            data = store.path.read_bytes()
        except FileNotFoundError:
            return
        tail = data[to:]
        if intent["step"] != "intent":
            if tail:
                raise IntegrityError(
                    f"{what}.repair.refused",
                    f"{store.path}: {len(tail)} bytes stand past the intent's cut point {to} at "
                    f"step {intent['step']!r}, after the cut ran and while nothing appends to "
                    f"the store; they are not a write of ours; nothing audited, nothing "
                    f"advanced, the intent stays: inspect the file and the intent before "
                    f"removing either",
                )
            return
        if not tail:
            return
        if "sha256:" + sha256_hex(tail) != intent["tail_sha256"]:
            # judged HERE, before the marker's barrier and before any step runs (the
            # intent step's own check is a second layer; round-21 self-gate, minor 2)
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"{store.path} has {len(tail)} bytes past the intent's cut point {to} and they "
                f"are not the bytes the intent recorded; nothing truncated, the intent stays: "
                f"inspect the file and the intent before removing either",
            )
        # the same physical-line rules a fresh read applies (round-20 self-gate,
        # second run, finding 3): the cut point at a line boundary, the bytes past it
        # ONE unterminated physical line, not blank, then a strict prefix of one record
        if to and data[to - 1 : to] != b"\n":
            why: str | None = f"the cut point {to} is not at a line boundary"
        elif b"\n" in tail:
            why = "more than one physical line past the cut point"
        elif is_blank_line(tail):
            why = "a whitespace-only line where a record belongs"
        else:
            why = torn_text_problem(tail)
        if why is not None:
            raise IntegrityError(
                f"{what}.repair.refused",
                f"{store.path}: the {len(tail)} bytes past the intent's cut point {to} are "
                f"not a torn write of ours ({why}); nothing truncated, the intent stays: "
                f"inspect the file and the intent before removing either",
            )

    def _self_name(self) -> str:
        try:
            return self.card["agent"]["name"]
        except FileNotFoundError:
            return "operator"

    def _repair_store(
        self,
        *,
        what: str,
        fname: str,
        path: Path,
        excess: Callable[[], bytes],
        validate: Callable[[dict[str, Any]], None],
        whole: Callable[[], Any],
        audit_action: str,
        describe: Callable[[int], str],
        marker_name: str | None = None,
        mirror_excess: bool = True,
        fresh: dict[str, Any] | None = None,
    ) -> int:
        """The repair of one store's tail as a resumable state machine driven by the
        intent marker state/<what>-repair-pending.json (or `marker_name`: the
        nested tail stage under a mirror intent), one shared implementation
        for the feed, the denial store, the ledger's JSONL tail and the ledger
        mirror (`excess` names the bytes at the end of `path` to cut, empty when
        clean; `validate` is what EVERY run checks about the store before it
        touches the file or the marker — a fresh run before its intent is written,
        a resumed run before any cut, marker advance or marker removal: the
        JSONL's chain and framing for the ledger with the CURRENT mirror against
        the chain that remains, the sound part of the feed or the store before the
        cut point — so a store found damaged leaves both exactly as found, refused
        by that fault's name (a fresh run writes no intent; a standing intent
        stands for a later run); at step "audited" the validation is the COMPLETE store
        (`whole`: the feed or the store in full, the JSONL's chain in full) and
        the ledger in full with the recorded audit entry present under the
        intent's id and its recorded hash — the last entry, for the ledger's own
        intents — before the marker goes: a torn audit suffix, a lost audit, a
        store torn past its cut point, each refuses by name with the marker and
        the file exactly as found). Each transition is written durably before the
        next step runs:
          step "intent"     {file, truncate_to, bytes, tail_sha256, intent_id} — before
                            anything is touched;
          the truncation, then fsync of the file and its directory;
          step "truncated";
          the audit entry (`audit_action`) appended to the ledger, its detail naming
                            the intent id;
          step "audited"    with the audit entry's hash;
          the marker deleted (the directory fsynced).
        A retry or a restart reads the marker and resumes at its step: at "intent",
        the tail is truncated when the bytes past the cut point still hash to what
        the intent recorded, and a file already at the cut point (an earlier run's
        truncation whose barrier may not have returned) is fsynced again and
        advances; at "truncated" the audit is appended only when the ledger holds no
        entry of that action naming this intent id; at "audited" the marker is
        deleted — for the ledger's stages only after the CURRENT mirror is validated,
        mended under the standing intent where a prose write of ours tore,
        regenerated where a cut removed lines, and verified whole with the anchors
        (`_drive_repair`). Every resumed run validates the current mirror as well
        as the store before any of this (`validate`: the ledger stages' validators
        `_validate_tail_resume` / `_validate_mirror_resume`), and every read of the
        ledger's repair family checks the stored acks' anchors against the chain
        that would remain, so an anchored entry is never cut (ledger.head.mismatch).
        Anything else under the cut point (the bytes differ, the file is
        shorter) is refused with the intent left in place for a human. With no
        marker and nothing to cut, the file is fsynced again (never a bare 0 on
        visible bytes) and nothing is written. `fresh` is an intent the verb
        decided before calling (the ledger's termination intent, `bytes` 0: nothing
        to cut, the entry past the cut point terminated at step "intent" instead):
        validated like any fresh intent, then written, then driven. Returns the
        bytes truncated by THIS run — 0 on a pure resume."""
        marker = self.state / (marker_name or f"{what}-repair-pending.json")
        intent = self._repair_intent(what, marker.name)
        self._repair_active = what  # this verb's own audit append passes the gate
        try:
            return self._repair_store_locked(
                marker,
                intent,
                what=what,
                fname=fname,
                path=path,
                excess=excess,
                validate=validate,
                whole=whole,
                audit_action=audit_action,
                describe=describe,
                mirror_excess=mirror_excess,
                fresh=fresh,
            )
        finally:
            self._repair_active = None

    def _repair_store_locked(
        self,
        marker: Path,
        intent: Any,
        *,
        what: str,
        fname: str,
        path: Path,
        excess: Callable[[], bytes],
        validate: Callable[[dict[str, Any]], None],
        whole: Callable[[], Any],
        audit_action: str,
        describe: Callable[[int], str],
        mirror_excess: bool,
        fresh: dict[str, Any] | None = None,
    ) -> int:
        if intent is not _MISSING and intent["file"] != fname:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"{marker.name} names {intent['file']!r}, not {fname}; nothing truncated, the "
                f"intent stays: inspect the file and the intent before removing either",
            )
        if intent is _MISSING:
            if fresh is not None:
                intent = fresh  # the verb's own decision (a termination intent)
            else:
                tail = excess()
                if not tail:
                    if path.exists():
                        fsync_existing(path)
                    return 0
                size = os.stat(path).st_size
                intent = {
                    "step": "intent",
                    "file": fname,
                    "truncate_to": size - len(tail),
                    "bytes": len(tail),
                    "tail_sha256": "sha256:" + sha256_hex(tail),
                    "intent_id": new_id("rpr"),
                    "ts": self.ts(),
                }
            # the same validation a resume runs, BEFORE the intent is written: for
            # the ledger's tail stages the CURRENT mirror against the chain that
            # remains (a retained prose line replaced, a blank line hidden after an
            # undecodable one) refuses by name with nothing written and no marker —
            # not after the cut, at the audit append (round-14 self-gate)
            validate(intent)
            self._write_state(marker, intent)  # the intent BEFORE anything is touched
        else:
            # the marker found is an intent (the typed read refused anything else).
            # The store it stands on is validated FIRST — before the marker's
            # barrier, before any cut, before any step advances: a JSONL whose
            # chain or framing fails (a feed or store whose sound part does not
            # verify) refuses by its name with the mirror and the marker exactly as
            # found, the intent standing for a run after the file is restored
            validate(intent)
            # the marker found may be visible and unsynced (its rename landed, its
            # directory fsync failed): its own barrier first, before anything it
            # authorizes is cut — a truncation must never outlive its intent
            fsync_existing(marker)
            self.report(
                f"natively: resuming an interrupted {what} repair (intent "
                f"{intent['intent_id']}, {intent['bytes']} bytes) at step {intent['step']!r}"
            )
        return self._drive_repair(
            marker,
            intent,
            path=path,
            what=what,
            whole=whole,
            audit_action=audit_action,
            describe=describe,
            mirror_excess=mirror_excess,
        )

    def _check_audit_recorded(self, what: str, intent: dict[str, Any], audit_action: str) -> None:
        """At step "audited": the ledger in full (`Ledger.check`: framing, every
        entry, the chain — a torn audit suffix is ledger.truncated by name) holds
        the audit entry of this intent (`audit_action` naming the intent id) with
        the hash the marker recorded; for the ledger's own intents it is the LAST
        entry (the guard admits no other append while the marker stands; a feed or
        denial marker closes only its own store, so later entries may follow theirs).
        Anything else is <what>.repair.intent_mismatch: the marker stays. The
        ledger is read in full here (`Ledger.check_intact`: the chain, the CURRENT
        mirror through the head, the anchors), so no marker goes over a mirror the
        next append would refuse; the audit's identity (`_audit_identity`) is the
        read-only half, run on its own before the audited step mends anything."""
        self.ledger.check_intact()
        self._audit_identity(what, intent, audit_action)

    def _audit_identity(self, what: str, intent: dict[str, Any], audit_action: str) -> None:
        """Read-only: the ledger's chain (the load checks it) holds the audit entry
        of this intent with the hash the marker recorded — for the ledger's own
        intents as the LAST entry. Nothing on disk is touched, so the audited step
        runs it BEFORE it mends the mirror from the entries: a last audit that is
        not the one the marker recorded is <what>.repair.intent_mismatch with the
        mirror as found, never a source of regenerated prose."""
        found = self._repair_audit(what, audit_action, intent)
        if found is None:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the marker is at step 'audited' but the ledger holds no {audit_action} entry "
                f"naming intent {intent['intent_id']}; nothing removed, the intent stays: "
                f"restore the ledger before `natively {what} repair`",
            )
        # the marker's recorded hash is REQUIRED at this step (the typed intent
        # loader refuses an audited marker without one); compared unconditionally
        recorded = intent["audit_hash"]
        if entry_hash(found) != recorded:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the {audit_action} entry naming intent {intent['intent_id']} hashes to "
                f"{entry_hash(found)}, not the {recorded} the marker recorded; nothing "
                f"removed, the intent stays: restore the ledger before `natively {what} repair`",
            )
        if what == "ledger" and entry_hash(self.ledger.entries()[-1]) != entry_hash(found):
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the {audit_action} entry naming intent {intent['intent_id']} is not the "
                f"ledger's last entry, and nothing appends while the marker stands; nothing "
                f"removed, the intent stays: inspect the ledger before `natively ledger repair`",
            )

    def _drive_repair(
        self,
        marker: Path,
        intent: dict[str, Any],
        *,
        path: Path,
        what: str,
        whole: Callable[[], Any],
        audit_action: str,
        describe: Callable[[int], str],
        mirror_excess: bool,
    ) -> int:
        step = intent["step"]
        truncated_now = 0
        if what != "ledger":
            stage = f"the {what} repair"
        elif path == self.ledger.prose_path:
            stage = "the ledger repair"
        else:
            stage = "the tail repair" if mirror_excess else "the nested tail repair"
        if step == "intent":
            to = intent["truncate_to"]
            size = os.stat(path).st_size if path.exists() else 0
            if path == self.ledger.path and intent["bytes"] == 0:
                # a termination intent (the fresh mend case, `repair_ledger`): nothing
                # is cut; the entry past the cut point — bound by hash at the
                # validation that ran first — gets its newline, durably, or already has
                # it (an earlier run's write that landed): the marker advances either way
                if self.ledger.terminate_tail():
                    self.report(
                        f"natively: the ledger's last entry lacked only its newline "
                        f"(interrupted write); terminated under intent {intent['intent_id']}"
                    )
                else:
                    fsync_existing(path)
            elif size == to:
                # the cut already happened (an earlier run, its barrier maybe not):
                # the barrier again, then advance
                if path.exists():
                    fsync_existing(path)
            elif size > to:
                with open(path, "rb") as f:
                    f.seek(to)
                    tail = f.read()
                if "sha256:" + sha256_hex(tail) != intent["tail_sha256"]:
                    raise IntegrityError(
                        f"{what}.repair.intent_mismatch",
                        f"{intent['file']} has {len(tail)} bytes past the intent's cut point "
                        f"{to} and they are not the bytes the intent recorded; nothing "
                        f"truncated, the intent stays: inspect the file and the intent "
                        f"({marker.name}) before removing either",
                    )
                with open(path, "r+b") as f:
                    f.truncate(to)
                    f.flush()
                    os.fsync(f.fileno())
                _fsync_dir(path.parent)
                truncated_now = len(tail)
            else:
                raise IntegrityError(
                    f"{what}.repair.intent_mismatch",
                    f"{intent['file']} is {size} bytes, shorter than the intent's cut point "
                    f"{to}; nothing truncated, the intent stays: inspect the file and the "
                    f"intent ({marker.name}) before removing either",
                )
            intent = {**intent, "step": "truncated"}
            self._write_state(marker, intent)
            step = "truncated"
        if step == "truncated":
            # an audit of this intent that is VISIBLE on the JSONL — terminated or
            # short of only its newline — is bound to the marker BEFORE any mend
            # below writes (its newline, a torn prose line regenerated, a torn line
            # cut): a wrong tail hash or another store's action refuses with both
            # files and the marker byte-identical (round-15 self-gate, finding 2)
            self._bind_visible_audit(what, audit_action, intent)
            if path == self.ledger.prose_path:
                # the ledger's own audit append regenerates the mirror's missing
                # lines first; a regeneration that tore on an earlier run of this
                # same intent (power loss inside a multibyte character) is cut back
                # to the sound lines so that append can land — resumable, under the
                # intent that already stands; one torn after an ASCII prefix (a
                # decodable partial line) is regenerated to its line
                self._mend_prose_tear("the ledger repair")
            elif path == self.ledger.path:
                # the JSONL's tail is cut. This stage's OWN audit append may have been
                # interrupted on an earlier run (the marker still at "truncated"):
                # the audit line whole short of only its newline is terminated, a torn
                # partial audit line is cut again (the part before it is the validated
                # prefix plus nothing else: the ledger is closed to every other writer
                # while the marker stands), and a regenerated or audit prose line torn
                # inside a multibyte character is cut back to the sound lines — so the
                # audit append that resumes the machine can land instead of meeting
                # ledger.truncated or ledger.mirror_corrupt forever
                self._mend_own_audit_tear()
                if mirror_excess:
                    # a mirror line written for the entry that never became durable
                    # (an older tool's, before the power cut) is beyond the entries
                    # now and would refuse the audit append forever; cut under this
                    # intent, regenerated by `Ledger.repair` after the audit. Not
                    # under the nested tail stage: the mirror's excess there is the
                    # standing mirror intent's to cut, by the bytes it recorded
                    cut = self.ledger.cut_excess_prose()
                    if cut:
                        self.report(
                            f"natively: the ledger repair cut {cut} bytes of ledger.prose.txt "
                            f"beyond the JSONL's entries before the audit; regenerated after it"
                        )
                    self._mend_prose_tear("the tail repair")
                else:
                    self._mend_prose_tear("the nested tail repair")
            # the ledger's full check with its anchors (`check_ledger`) BEFORE an audit
            # found on record is trusted: the same check the append branch runs
            # through `ledger_append`, so a record that only LOOKS like this intent's
            # audit (an anchored completion edited into one, its mirror line removed)
            # is ledger.head.mismatch by name here, with the marker at its step and
            # nothing barriered, promoted or regenerated over it (round-14 self-gate:
            # the feed stage found such a record, ran the barrier — which regenerated
            # the forged prose — and promoted its marker before the check refused)
            self.check_ledger()
            found = self._repair_audit(what, audit_action, intent)
            if found is not None:
                # the audit is VISIBLE but may be an unsynced tail (its append failed
                # after the bytes landed): the ledger barrier before it is promoted to
                # step "audited" and the marker goes — the audit must outlive the marker
                self.ledger.barrier()
            else:
                found = self.ledger_append(
                    ts=self.ts(),
                    actor=self._self_name(),
                    grant_id=None,
                    action=audit_action,
                    params_hash=intent["tail_sha256"],
                    outcome="recorded",
                    detail=f"{describe(intent['bytes'])}; intent {intent['intent_id']}",
                    intent_id=intent["intent_id"],
                )
            intent = {**intent, "step": "audited", "audit_hash": entry_hash(found)}
            self._write_state(marker, intent)
            step = "audited"
        if step == "audited":
            # the audit the marker recorded is IDENTIFIED first, read-only
            # (`_audit_identity`: on record, its hash the marker's, for the ledger's
            # own intents the last entry) — before any prose is mended from the
            # entries, so nothing is regenerated from an audit the marker rejects (an
            # edited last audit with a strict-prefix partial prose line had its prose
            # written before its hash refused: round-14 self-gate); the ledger in
            # full, with the mirror and the anchors, is checked again below
            self._audit_identity(what, intent, audit_action)
            if what == "ledger":
                # the CURRENT mirror validated and, where a prose write of this
                # intent's earlier run tore, mended WHILE the intent still stands
                # (`_mend_prose_tear`: an undecodable tail cut back to its sound
                # lines, a decodable strict-prefix partial line completed; anything
                # else refused by name with the marker standing, so the retry finds
                # the intent that permits the regeneration), the lines a cut removed
                # regenerated (`Ledger.repair`, the JSONL fsynced first) — never a
                # marker removed over a mirror the next append would refuse forever
                # (round-13 gate, finding 3)
                self._mend_prose_tear(f"{stage} at its audited step")
                self.ledger.repair()
            # the last step removes the marker: what it removes it over is the
            # COMPLETE store (not the part before the cut point: a torn audit
            # suffix on the JSONL passed the prefix check and lost its marker;
            # a store torn past its cut point likewise) and the ledger in full —
            # the chain, the mirror through the head, the anchors — holding the
            # audit this intent recorded, whether this run resumed at "audited" or
            # arrived here from an earlier step
            whole()
            self._check_audit_recorded(what, intent, audit_action)
            if what == "ledger":
                # the marker goes only after the mirror VERIFIES whole through the
                # head (every line, the count, the terminating newline) and the
                # anchors hold on the chain the repair leaves
                self.ledger.verify()
            marker.unlink()
            _fsync_dir(self.state)
        return truncated_now

    def _mend_prose_tear(self, stage: str) -> None:
        """At step "truncated" of any stage, before its audit append: a prose write
        of an earlier run of this same intent may have torn — inside a multibyte
        character (the mirror does not decode: cut back to the sound lines,
        `Ledger.cut_undecodable_tail`) or after an ASCII prefix (a decodable
        partial line without its newline: regenerated to its entry's line,
        `Ledger.mend_torn_prose_tail`; one that is not a prefix of that line is
        ledger.prose.mismatch, the marker standing). Either way the audit append's
        own regeneration and barrier can then land instead of meeting
        ledger.mirror_corrupt or ledger.prose.mismatch on every resume."""
        cut = self.ledger.cut_undecodable_tail()
        if cut:
            self.report(
                f"natively: resuming {stage}: {cut} torn bytes of a regenerated mirror tail "
                f"cut again before the audit"
            )
        mended = self.ledger.mend_torn_prose_tail()
        if mended:
            self.report(
                f"natively: resuming {stage}: a prose line torn after its first bytes "
                f"regenerated ({mended} bytes written) before the audit"
            )

    def _mend_own_audit_tear(self) -> None:
        """Inside a JSONL-tail stage at step "truncated": the audit append of an
        earlier run of this same intent may have torn the JSONL's tail. A whole
        entry short of only its newline is terminated (`Ledger.terminate_tail`);
        a torn partial line is cut back to the chain before it (`Ledger.torn_tail`
        names it only when that part is this ledger's chain in full), durably.
        Nothing else can have written the JSONL while the marker stood. The resume's
        validator (`_validate_tail_resume`) checked the current mirror against the
        chain the newline completes before this ran, so the termination here
        passes no mirror check of its own."""
        if self.ledger.terminate_tail():
            self.report(
                "natively: resuming the tail repair: its audit entry lacked only its newline "
                "(interrupted write); terminated"
            )
            return
        tail = self.ledger.torn_tail()
        if not tail:
            return
        size = os.stat(self.ledger.path).st_size
        with open(self.ledger.path, "r+b") as f:
            f.truncate(size - len(tail))
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self.ledger.path.parent)
        self.ledger._entries = None
        self.report(
            f"natively: resuming the tail repair: {len(tail)} torn bytes of its own audit "
            f"append cut again before the audit"
        )

    def _repair_audit(
        self, what: str, audit_action: str, intent: dict[str, Any]
    ) -> dict[str, Any] | None:
        """The ledger entry of `audit_action` recorded under `intent`, if one landed —
        matched by EQUALITY on the entry's own intent_id field, never by the
        detail's text, a substring, a prefix or containment (a marker whose id had
        become `rpr_` matched an older repair's audit inside its detail and
        promoted that audit's hash: round-14 gate, finding 3; the typed loader now
        refuses a marker whose id is not an rpr_ id in full, and the field is
        validated in full at the ledger's load) — and BOUND to the marker before it
        is trusted: the marker's store name is the store this audit action records
        (`AUDIT_STORES`) and the entry's params_hash is the tail hash the marker
        recorded. A mismatch is <what>.repair.intent_mismatch naming both, the
        marker standing at its step, nothing barriered, promoted or removed. The id
        is matched FIRST and the binding checked on whatever carries it: an entry
        under this id whose action is another store's audit is a mismatch, never
        "absent" (`_bind_audit`; before, the action was filtered first, so a
        denial.repaired entry under a ledger-tail intent's id was skipped and a
        second audit appended under the id: round-15 self-gate, finding 3). For
        the ledger's own intents the found audit is also the ledger's LAST entry
        — nothing of ours appends while the marker stands, so an entry after it
        is a hand edit or a foreign tool — checked HERE, inside the binding every
        found audit crosses, so the step-truncated caller refuses BEFORE the
        barrier and before the marker is promoted to "audited" (before, the rule
        ran only at step "audited" in `_audit_identity`, and the first refusal
        left the marker one step past where the crash left it: round-16 Fable
        read, D1); `_audit_identity` keeps the rule as its second line."""
        if AUDIT_STORES.get(audit_action) != intent["file"]:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the marker names {intent['file']!r}, which {audit_action} does not record; "
                f"nothing promoted, the intent stays: inspect the marker before removing it",
            )
        es = self.ledger.entries()
        for e in es:
            if e.get("intent_id") != intent["intent_id"]:
                continue
            self._bind_audit(what, audit_action, intent, e)
            self._refuse_displaced_audit(what, audit_action, intent, e, es)
            return e
        return None

    def _refuse_displaced_audit(
        self,
        what: str,
        audit_action: str,
        intent: dict[str, Any],
        e: dict[str, Any],
        es: list[dict[str, Any]],
    ) -> None:
        """For the ledger's own intents the entry carrying this intent's id is the
        ledger's LAST entry — nothing of ours appends while the marker stands, so
        an entry after it is a hand edit or a foreign tool: <what>.repair.intent_mismatch
        by name with nothing written, wherever a found audit is trusted (the lookup,
        `_repair_audit`; the binding before any mend, `_bind_visible_audit`)."""
        if what == "ledger" and e is not es[-1]:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the {audit_action} entry naming intent {intent['intent_id']} is not the "
                f"ledger's last entry, and nothing appends while the marker stands; "
                f"nothing barriered, promoted or removed, the intent stays at its step: "
                f"inspect the ledger before `natively ledger repair`",
            )

    def _bind_audit(
        self, what: str, audit_action: str, intent: dict[str, Any], e: dict[str, Any]
    ) -> None:
        """An entry carrying this intent's id, bound to the marker before it is
        trusted: its action is `audit_action` — the audit of the store the marker
        names (`AUDIT_STORES`) — and its params_hash the tail hash the marker
        recorded; anything else is <what>.repair.intent_mismatch naming what was
        found and what the marker says, nothing promoted, appended or removed."""
        action = e.get("action")
        if action != audit_action:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the entry recorded under intent {intent['intent_id']} is a {action!r} record "
                f"(the audit of {AUDIT_STORES.get(action, 'no store')}), not the {audit_action} "
                f"audit of the {intent['file']} the marker names; nothing promoted, nothing "
                f"appended, the intent stays: inspect the ledger and the marker before "
                f"removing either",
            )
        if e.get("params_hash") != intent["tail_sha256"]:
            raise IntegrityError(
                f"{what}.repair.intent_mismatch",
                f"the {audit_action} entry recorded under intent {intent['intent_id']} "
                f"names tail hash {e.get('params_hash')}, not the {intent['tail_sha256']} the "
                f"marker recorded; nothing promoted, nothing removed, the intent stays: "
                f"inspect the ledger and the marker before removing either",
            )

    def _bind_visible_audit(self, what: str, audit_action: str, intent: dict[str, Any]) -> None:
        """At step "truncated", BEFORE any mend writes: the JSONL's last physical line
        — terminated or short of only its newline — that is a JSON object carrying
        this intent's id is this intent's audit as it landed, and is bound to the
        marker here (`_bind_audit`) with nothing written: a wrong tail hash or
        another store's action is <what>.repair.intent_mismatch with the JSONL, the
        mirror and the marker byte-identical on every retry. Before, the mends ran
        first — `_mend_own_audit_tear` terminated the audit's line and
        `_mend_prose_tear` regenerated its prose line — and `_repair_audit` refused
        after those writes (round-15 self-gate, finding 2). A torn partial line is
        no audit (nothing to bind; the mends name or cut it), and a line under
        another id is left to the full lookup after the ledger's check. For the
        ledger's own intents the chain as the file stands (`chain_now`: an
        unterminated whole last entry included) is read too, and an entry carrying
        this intent's id that is NOT the last one is refused here — before the
        mirror path's termination newline (`repair_ledger`) and before every mend —
        with nothing written (round-17 self-gate, finding 1: the last-entry rule
        inside the lookup ran after those writes on the mirror path). Every entry
        of that chain carrying this intent's id is BOUND there too (`_bind_audit`:
        the action of the store the marker names, the marker's tail hash) before
        its displacement is judged, and a torn tail past an audit that landed
        whole is refused by name here as well — the audit's append ran once, so
        the tear is not this machine's write and not the subordinate tail stage's
        to cut. Before, the scan judged displacement only and ignored the torn
        tail: under a mirror intent the subordinate stage cut those bytes as the
        audit's own tear and appended its tail audit after the mirror audit, and
        the mirror stage then refused that displacement on every retry — stuck,
        with a cut and an append on the first run (round-17 gate, finding 1)."""
        e = self.ledger.visible_tail_object()  # the ledger parses its own lines
        if e is not None and e.get("intent_id") == intent["intent_id"]:
            self._bind_audit(what, audit_action, intent, e)
        if what == "ledger":
            es, torn = self.ledger.chain_now()
            for x in es:
                if x.get("intent_id") != intent["intent_id"]:
                    continue
                self._bind_audit(what, audit_action, intent, x)
                self._refuse_displaced_audit(what, audit_action, intent, x, es)
                if torn:
                    raise IntegrityError(
                        f"{what}.repair.intent_mismatch",
                        f"ledger.jsonl carries a torn tail ({len(torn)} bytes) past the "
                        f"{audit_action} entry naming intent {intent['intent_id']}, which "
                        f"landed whole; the audit's append ran once, so the tear is not this "
                        f"machine's write and not the subordinate tail stage's to cut; nothing "
                        f"written, nothing cut, nothing appended, the intent stays at its step: "
                        f"inspect the file and the marker before removing either",
                    )

    # ---- clock / keys ---------------------------------------------------------------
    def now(self) -> datetime:
        return self.clock()

    def ts(self) -> str:
        return fmt(self.now())

    def _config_now(self) -> dict[str, Any]:
        """The enforcement configuration read from config.json NOW through the typed
        loader (`effective_config`): a config that fails the loader is state.corrupt
        — a StorageError, so nothing authorizes over it — never the copy cached at
        construction. At authorization the read runs under the state lock the
        receive holds (`_apply_action`, `_receive`); the file is written by an
        atomic rename under that lock (`cli.cmd_config`, `save_config`), so a read
        elsewhere sees a whole file and takes no lock of its own (every ledger
        writer holds the lock exactly once, a pinned invariant). A long-running
        `run` started with standing denials off kept skipping the denial store after
        `config --set` enabled them from another process (round-19 gate, finding 1)."""
        return effective_config(self.state)

    @property
    def poll_s(self) -> int:
        return int(self._config_now()["poll_s"])

    @property
    def extensions(self) -> dict[str, bool]:
        return self._config_now()["extensions"]

    def key(self, role: str) -> keys.KeyPair:
        if role not in self._keys:
            self._keys[role] = keys.load(self.keys_dir, role)
        return self._keys[role]

    @property
    def host(self) -> keys.KeyPair:
        return self.key("host")

    @property
    def agent(self) -> keys.KeyPair:
        return self.key("agent")

    @property
    def principal(self) -> keys.KeyPair:
        return self.key("principal-standin")

    def save_config(self) -> None:
        """This node's config snapshot written whole, under the state lock like
        every other state write (round-19 gate, finding 2: an unlocked writer),
        after the typed loader admits it — nothing lands that the next construction
        would refuse. The CLI's read-modify-write (`cli.cmd_config`) serializes
        under the same lock without a node."""
        why = statemod.config(self.config)
        if why is not None:
            raise ValueError(f"refusing to write a config the loader would refuse: {why}")
        with self._locked():
            self._write_state(self.state / "config.json", self.config)

    # ---- lock -----------------------------------------------------------------------
    def locked(self):
        """The state lock, for callers outside the node (the adapter's poll, the CLI
        ledger verbs): the same flock every ledger writer holds."""
        return self._locked()

    def _write_state(self, path: Path, obj: Any) -> None:
        """EVERY write of a state file: under the state lock (re-entrant, so a writer
        already holding it — the receive, the repair machine — takes it no second
        time), through the exclusive-temp atomic writer. The grant store and the card
        import wrote outside the lock when a verb called them (`natively grant`,
        round-19 self-gate); routing every write through one method makes "no state
        write runs outside the lock" a property of this file, not of each caller."""
        with self._locked():
            _write_json(path, obj)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Exclusive, process-shared lock on state/.lock, re-entrant per Node instance
        (a depth counter guarding one flock; an RLock keeps the counter honest if two
        threads share the instance). Every ledger writer runs under it."""
        with self._lock_guard:
            if self._lock_depth == 0:
                fd = os.open(self.state / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
                self._lock_fd = fd
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    fd, self._lock_fd = self._lock_fd, None
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)

    # ---- identity -------------------------------------------------------------------
    @property
    def card(self) -> dict[str, Any]:
        """This node's own card, read through the card module's full verification on
        EVERY read (structure, both signatures) and bound to this node's own keys
        (the agent, node and principal keys equal the pairs under the keys dir —
        the self card's analogue of the hash-equals-file-name binding of cards/: a
        sound card that is not ours has another hash). A self card that fails is
        local corruption, IntegrityError card.self_corrupt naming the path — a
        storage failure: nothing is composed or acked from it, no reply validates,
        the mail stays unseen. Checked at construction and so before every ack;
        the operator removes the file and runs `natively card` again."""
        return self._self_card()

    def _self_card(self) -> dict[str, Any]:
        p = self.state / "self.card.json"
        try:
            c = statemod.read(p, _MISSING, statemod.is_object, reason="card.self_corrupt")
        except IntegrityError as e:  # a self card of ours that does not parse
            if e.reason == "card.self_corrupt":
                raise  # the shape refusal, the path already named
            raise IntegrityError("card.self_corrupt", f"{p}: {e}") from e
        if c is _MISSING:
            raise FileNotFoundError("no self card; run `natively card`")
        try:
            h = cardmod.verify(c)
        except (VerifyError, TypeError, KeyError, AttributeError) as e:
            raise IntegrityError("card.self_corrupt", f"{p}: {e}") from e
        for sect, kp in (("agent", self.agent), ("node", self.host), ("principal", self.principal)):
            if c[sect]["key"] != kp.public:
                raise IntegrityError(
                    "card.self_corrupt",
                    f"{p}: card {h} is not this node's card (its {sect} key is not this "
                    f"node's {sect} key); remove the file and run `natively card` again",
                )
        return c

    @property
    def card_hash(self) -> str:
        return cardmod.card_hash(self.card)

    @property
    def executor_keys(self) -> set[str]:
        return {self.host.public, self.agent.public}

    def executor(self) -> Executor:
        return Executor(self.host.public, self.scratch_dir, self.scratch_identity)

    def default_capabilities(self) -> list[dict[str, str]]:
        return [
            {"action": "info", "resource": f"host:{self.host.public}:*"},
            {"action": "fs.write", "resource": f"host:{self.host.public}:scratch/*"},
        ]

    def make_card(
        self,
        *,
        agent_name: str,
        node_name: str,
        principal_name: str,
        principal_kind: str = "stand-in",
        ledger_url: str = "",
        capabilities: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        c = cardmod.build(
            agent_name=agent_name,
            agent_key=self.agent.public,
            node_name=node_name,
            node_key=self.host.public,
            principal_name=principal_name,
            principal_key=self.principal.public,
            principal_kind=principal_kind,
            capabilities=capabilities or self.default_capabilities(),
            ledger_url=ledger_url or f"{node_name}:{self.ledger.path}",
            issued_at=self.ts(),
        )
        c = cardmod.sign(c, self.host, self.principal)
        # the complete card through the same checks its loader runs (`_self_card`:
        # structure, both signatures, bound to this node's keys) BEFORE the existing
        # self card is replaced: a refused card writes nothing and names the reason
        # — before, a card with an empty agent name was persisted and the next start
        # refused the identity (round-19 gate, finding 13)
        try:
            cardmod.verify(c)
        except (VerifyError, TypeError, KeyError, AttributeError, ValueError) as e:
            raise ValueError(
                f"refusing to write a card its own loader would refuse ({e}); the existing "
                f"self card, if any, is untouched"
            ) from e
        for sect, kp in (("agent", self.agent), ("node", self.host), ("principal", self.principal)):
            if c[sect]["key"] != kp.public:
                raise ValueError(f"the built card's {sect} key is not this node's; nothing written")
        with self._locked():  # a state write, under the lock like every other
            self._write_state(self.state / "self.card.json", c)
            self.pin(self.principal.public, principal_name)  # our own principal is a root here
        return c

    # ---- trust store ----------------------------------------------------------------
    def _roots(self) -> dict[str, Any]:
        """pinned.json, typed: principal key -> {name, pinned_at}. The wrong shape is
        state.corrupt naming the path — a storage failure (a card is not imported,
        a grant not authenticated, the mail unseen), never an empty trust store."""
        return statemod.read(self.state / "pinned.json", {}, statemod.pinned)

    @property
    def pinned(self) -> set[str]:
        return set(self._roots().keys())

    def pin(self, principal_key: str, name: str) -> None:
        keys.public_from_str(principal_key, "pin")
        with self._locked():
            # the enforcing records are read FIRST: a feed or a denial store that
            # does not load (torn, or a record that no longer verifies as a
            # document) is a storage failure of the pin, by the file's name —
            # trust is never published over a restriction this node cannot read
            self.revocations.entries()
            self.denials.entries()
            self._refuse_if_repairing("ledger", "ledger.prose.txt")
            self.ledger.check_intact()  # the replay ledgers: the ledger in full first
            # Order: the revocations held for this principal land in the feed FIRST
            # (they verify against the key in hand), and only then is trust published.
            # A crash anywhere before the pinned.json write leaves the principal
            # unpinned, so nothing it revoked can be authorized in between; the
            # startup sweep covers a state where trust was published first.
            self._replay_pending_revocations(principal_key, why="principal pinned")
            p = self._roots()
            p[principal_key] = {"name": name, "pinned_at": self.ts()}
            self._write_state(self.state / "pinned.json", p)
            # a card that was waiting on this root becomes trusted (a card the replay
            # above revoked is never promoted); every held card is read through the
            # typed card loader (verified in full, bound to its name: card.corrupt)
            for f in list_dir(self.state / "cards-pending", ".json"):
                c = statemod.read_card(f)
                if c is not None and c["principal"]["key"] == principal_key:
                    try:
                        h = cardmod.verify(c, pinned=self.pinned)
                    except VerifyError:
                        continue
                    if self.card_revoked(c, h):
                        continue
                    self._write_state(self.state / "cards" / f.name, c)
                    f.unlink()

    def _held_revocations(self, principal_key: str) -> list[tuple[Path, dict[str, Any]]]:
        """Every candidate held under revocations-pending/ for this principal: a file
        per (rev_id, body hash), so two bodies claiming one rev_id are both kept."""
        # durable.list_dir: an unreadable directory is an OSError here, never "nothing
        # held" (Path.glob would swallow it, and the marker would be cleared with a
        # revocation still outstanding)
        out = []
        for f in list_dir(self.state / "revocations-pending", ".json"):
            r, pk = self._read_held_revocation(f)
            if pk == principal_key:
                out.append((f, r))
        return out

    def _read_held_revocation(self, f: Path) -> tuple[dict[str, Any], str]:
        """One held copy, verified in full — structure and signature against the
        principal key IT names, exactly as it was when it was held — and bound to
        its file name (rev_id and body hash): a copy that no longer is a revocation
        object, names a damaged or empty key, no longer verifies, or is not the
        document its name promises is LOCAL corruption of a file this node wrote
        after verifying it (IntegrityError revocation.held_corrupt naming the path),
        never a copy to skip and never one a hold stands on: it is kept in place
        and named. Returns (the document, its principal key)."""
        r = statemod.read(f, None, statemod.is_object, reason="revocation.held_corrupt")
        try:
            pk = r["principal"]["key"]
            if not isinstance(pk, str):
                raise VerifyError("revocation.principal.key", "not a string")
            revmod.verify(r, pinned={pk})
            if f.name != f"{r['rev_id']}-{hash_of(r)[7:19]}.json":
                raise VerifyError(
                    "revocation.held_name", "the copy is not the document its name promises"
                )
        except (VerifyError, TypeError, KeyError) as e:
            raise IntegrityError(
                "revocation.held_corrupt",
                f"{f}: the held copy no longer verifies ({e}); it is kept and nothing is "
                f"authorized until it is restored or removed by hand",
            ) from e
        return r, pk

    def _replay_pending_revocations(self, principal_key: str, *, why: str) -> None:
        """A revocation received while its principal was unpinned was kept under
        revocations-pending/ (its mail is long gone from the wire window). It is
        verified against the principal key it names — whether that key is pinned
        already (the startup sweep) or is being pinned right now (pin(), which calls
        this BEFORE it writes pinned.json) — applied, and the replay ledgered. Each
        held copy is deleted only after ITS OWN feed append returned (durable): a
        second body under the same rev_id is its own candidate, recorded as a
        variant, never dropped because another candidate landed first."""
        self._refuse_if_repairing("feed", "revocations.jsonl")
        trusted = self.pinned | {principal_key}
        held = self._held_revocations(principal_key)
        if held:
            # the ledger in full, with its anchors, BEFORE the first feed line lands
            # (every enforcing record is written only over a ledger that passes the
            # check — the pin, `revoke`, `deny` do the same): a failing check is a
            # storage failure by the ledger's name with the feed untouched — the
            # startup sweep's marker names it, the pin refuses, `feed repair` stops.
            # Before, the feed line landed and only the ledger entry's append refused,
            # so the replay recorded on the next start as a duplicate (round-14 Fable
            # read, section E)
            self.check_ledger()
        for f, r in held:
            try:
                added = self.revocations.add(r, pinned=trusted)
            except VerifyError as e:
                # the copy verified when it was held; a copy that no longer does is
                # local corruption (a damaged signature, a changed field): kept, and
                # the replay — and with it every authorization — stays blocked
                raise IntegrityError(
                    "revocation.held_corrupt",
                    f"{f}: the held copy no longer verifies ({e.reason}: {e.detail}); it is "
                    f"kept and nothing is authorized until it is restored or removed by hand",
                ) from e
            else:
                self.report(f"natively: held revocation {r['rev_id']} replayed: {why}")
                self.ledger_append(
                    ts=self.ts(),
                    actor=principal_key[:32],
                    grant_id=None,
                    action="revocation.replayed",
                    params_hash=hash_of(r["revokes"]),
                    outcome=added,
                    detail=f"{r['rev_id']} held while unpinned ({why}); "
                    f"cards={r['revokes']['cards']} grants={r['revokes']['grants']}",
                )
            f.unlink()

    def card_revoked(self, c: dict[str, Any], h: str | None = None) -> dict[str, Any] | None:
        """A card is revoked by ITS OWN principal (the key on the card), never by the
        root of whatever grant happens to be in hand."""
        return self.revocations.card_revoked_by(h or cardmod.card_hash(c), c["principal"]["key"])

    def import_card(self, c: dict[str, Any]) -> tuple[str, bool]:
        """Verify a card. Trusted iff its principal is pinned. Returns (hash, trusted).
        An unpinned card is kept aside and the fact is ledgered and printed."""
        h = cardmod.verify(c)  # structure + both signatures, whoever the principal is
        if self.card_revoked(c, h):
            raise VerifyError("card.revoked", f"card {h} was revoked by its principal")
        if c["principal"]["key"] in self.pinned:
            self._write_state(self.state / "cards" / f"{h[7:]}.json", c)
            return h, True
        self._write_state(self.state / "cards-pending" / f"{h[7:]}.json", c)
        return h, False

    def trusted_cards(self, *, include_revoked: bool = False) -> list[dict[str, Any]]:
        """Every card under cards/, each read through the typed card loader: verified
        in full and bound to its file name on every read, so a damaged card on file
        is card.corrupt (a storage failure: receive refuses, the mail stays unseen),
        never a sender identity, a recipient or a card silently skipped."""
        out = []
        for f in list_dir(self.state / "cards", ".json"):
            c = statemod.read_card(f)
            if c is None:
                continue
            if include_revoked or not self.card_revoked(c):
                out.append(c)
        return out

    def card_for_key(
        self, agent_key: str, *, include_revoked: bool = False
    ) -> dict[str, Any] | None:
        for c in self.trusted_cards(include_revoked=include_revoked):
            if c["agent"]["key"] == agent_key:
                return c
        return None

    def card_by_hash(self, h: str, *, include_revoked: bool = False) -> dict[str, Any] | None:
        for c in self.trusted_cards(include_revoked=include_revoked):
            if cardmod.card_hash(c) == h:
                return c
        return None

    def find_card(self, ref: str) -> dict[str, Any]:
        """Resolve a trusted, unrevoked card by agent name, card hash, or agent key
        ('self' works)."""
        if ref == "self":
            return self.card
        for c in self.trusted_cards():
            if ref in (c["agent"]["name"], cardmod.card_hash(c), c["agent"]["key"]):
                return c
        raise KeyError(f"no trusted card matches {ref!r}")

    def actor_name(self, agent_key: str) -> str:
        c = self.card_for_key(agent_key, include_revoked=True)
        return c["agent"]["name"] if c else f"unknown<{agent_key[:24]}>"

    def _sender_card(self, agent_key: str, what: str) -> dict[str, Any]:
        """The trusted, unrevoked card for an agent key. An agent whose old card was
        revoked and replaced is its replacement; only when no unrevoked card exists
        does a revoked one count, as a refusal."""
        c = self.card_for_key(agent_key)
        if c is not None:
            return c
        c = self.card_for_key(agent_key, include_revoked=True)
        if c is None:
            raise VerifyError(
                f"{what}.sender.untrusted", f"no trusted card for {agent_key}; pin its principal"
            )
        raise VerifyError(
            f"{what}.sender.revoked", f"card of {c['agent']['name']} revoked by its principal"
        )

    # ---- grants ---------------------------------------------------------------------
    def store_grant(self, g: dict[str, Any], *, embedded: bool = False) -> None:
        """A grant issued here or received top-level goes under grants/ (executable).
        A parent first met inside a delegated child goes under grants-embedded/: it
        is held to for identity and budget checks but a message may not name it."""
        check_id(g["grant_id"], "grant.grant_id", "grt_")
        # nothing lands on file that the typed loader would then refuse as corruption
        # (an issued grant is checked here for the first time — `grant --max-uses 0`
        # is refused at issue, never stored to poison every later load; a received
        # one was authenticated already): the document, whatever this node's flags
        try:
            grantmod.check_document(g, extensions=grantmod.ANY_EXTENSION)
        except VerifyError as e:
            raise ValueError(
                f"refusing to store grant {g['grant_id']}: not a sound document "
                f"({e.reason}: {e.detail})"
            ) from e
        d = "grants-embedded" if embedded else "grants"
        self._write_state(self.state / d / f"{g['grant_id']}.json", g)

    def load_grant(self, grant_id: str) -> dict[str, Any] | None:
        """The EXECUTABLE grant on file under this id: grants/ only, never a parent
        cached from a child."""
        check_id(grant_id, "grant_id", "grt_")
        return statemod.read_grant(self.state / "grants" / f"{grant_id}.json")

    def load_grant_any(self, grant_id: str) -> dict[str, Any] | None:
        """The grant this id names for VERIFICATION (identity, budgets): grants/
        first, then grants-embedded/. Both through the typed grant loader (the
        structure in full, bound to the file name): a grant file of the wrong shape
        is state.corrupt, a storage failure, never a refusal or a missing grant."""
        g = self.load_grant(grant_id)
        if g is None:
            g = statemod.read_grant(self.state / "grants-embedded" / f"{grant_id}.json")
        return g

    def grants_on_file(self) -> list[dict[str, Any]]:
        out = []
        for f in list_dir(self.state / "grants", ".json"):
            g = statemod.read_grant(f)
            if g is not None:
                out.append(g)
        return out

    def issue_grant(
        self,
        *,
        subject_card: dict[str, Any],
        scope: list[dict[str, Any]],
        principal_statement: str,
        expires_in_s: int = 3600,
        max_uses: int = 1,
        max_uses_per_window: dict[str, int] | None = None,
        audience: str | None = None,
        principal_name: str | None = None,
    ) -> dict[str, Any]:
        """The principal (stand-in) signs a root grant for `subject_card`'s agent."""
        if max_uses_per_window is not None and not self.extensions["max_uses_per_window"]:
            raise ValueError("max_uses_per_window is behind extensions.max_uses_per_window (off)")
        now = self.now()
        g = grantmod.build(
            issuer={
                "principal": principal_name or self.card["principal"]["name"],
                "key": self.principal.public,
            },
            subject={"agent": cardmod.card_hash(subject_card), "key": subject_card["agent"]["key"]},
            audience_executor=audience or subject_card["node"]["key"],
            scope=scope,
            principal_statement=principal_statement,
            issued_at=fmt(now),
            expires_at=fmt(plus(now, expires_in_s)),
            max_uses=max_uses,
            revocation_ledger=self.card["ledger_url"],
            max_check_interval_s=self.poll_s * 5,
            max_uses_per_window=max_uses_per_window,
        )
        g = grantmod.sign(g, self.principal)
        self.store_grant(g)
        return g

    def delegate_grant(
        self,
        *,
        parent: dict[str, Any],
        subject_card: dict[str, Any],
        scope: list[dict[str, Any]],
        principal_statement: str,
        expires_at: str | None = None,
        max_uses: int | None = None,
        max_uses_per_window: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """This agent (the parent's subject) delegates a strict subset, depth one. The
        child inherits the parent's max_check_interval_s and not_before. Each
        restriction asked for is applied when it is at least as tight as the
        parent's and refused by name (ValueError naming grant.delegation.<what>)
        when looser: `expires_at` never past the parent's (None: the parent's),
        `max_uses` never more than the parent's REMAINING budget across its family
        (None: that remaining budget; an explicit 0 issues nothing), the window
        never looser than the parent's — n no larger, window_s no shorter — (None:
        the parent's own). Nothing asked for is silently dropped — before, the
        expiry and the window were ignored and `max_uses or parent["max_uses"]`
        turned an explicit 0 into the parent's whole budget (round-19 gate,
        finding 5)."""
        if parent["subject"]["key"] != self.agent.public:
            raise ValueError("this agent is not the parent grant's subject")
        pid = parent["grant_id"]
        # the parent family's remaining budget is read and the child published under
        # ONE hold of the state lock (re-entrant: a widening of the store's own lock,
        # not a new one): a receive in another process that consumes the parent's
        # last use waits for the publication or runs before the read, so a child
        # never carries a use against zero remaining (round-19 gate R5)
        with self._locked():
            if max_uses is not None and max_uses < 1:
                raise ValueError(
                    f"grant.delegation.max_uses: {max_uses} uses requested; a delegation carries "
                    f"at least one use (an explicit 0 issues nothing)"
                )
            used, _in_window = self.grant_uses(parent, family=True)
            remaining = parent["max_uses"] - used
            if remaining < 1:
                raise ValueError(
                    f"grant.delegation.max_uses: parent {pid} has no remaining uses "
                    f"({used} of {parent['max_uses']} used across its family); nothing issued"
                )
            if max_uses is None:
                max_uses = remaining
            elif max_uses > remaining:
                raise ValueError(
                    f"grant.delegation.max_uses: {max_uses} uses requested but parent {pid} has "
                    f"{remaining} remaining ({used} of {parent['max_uses']} used); nothing issued"
                )
            if expires_at is None:
                expires_at = parent["expires_at"]
            elif parse(expires_at, "grant.expires_at") > parse(parent["expires_at"]):
                raise ValueError(
                    f"grant.delegation.expiry: requested expiry {expires_at} is past parent "
                    f"{pid}'s {parent['expires_at']}; nothing issued"
                )
            pw = parent.get("max_uses_per_window")
            if max_uses_per_window is None:
                window = pw
            else:
                if not self.extensions["max_uses_per_window"]:
                    raise ValueError(
                        "max_uses_per_window is behind extensions.max_uses_per_window (off)"
                    )
                w = max_uses_per_window
                window = {"n": int(w["n"]), "window_s": int(w["window_s"])}
                if window["n"] < 1 or window["window_s"] < 1:
                    raise ValueError(
                        f"grant.delegation.max_uses_per_window: a window is n>=1 uses over "
                        f"window_s>=1 seconds, not {window['n']} over {window['window_s']}"
                    )
                if pw is not None and (
                    window["n"] > pw["n"] or window["window_s"] < pw["window_s"]
                ):
                    raise ValueError(
                        f"grant.delegation.max_uses_per_window: requested {window['n']} uses per "
                        f"{window['window_s']}s is looser than parent {pid}'s {pw['n']} per "
                        f"{pw['window_s']}s; nothing issued"
                    )
            g = grantmod.build(
                issuer={"agent": self.card_hash, "key": self.agent.public},
                subject={
                    "agent": cardmod.card_hash(subject_card),
                    "key": subject_card["agent"]["key"],
                },
                audience_executor=parent["audience"]["executor"],
                scope=scope,
                principal_statement=principal_statement,
                issued_at=self.ts(),
                expires_at=expires_at,
                not_before=parent["not_before"],
                max_uses=max_uses,
                revocation_ledger=parent["revocation"]["ledger"],
                max_check_interval_s=parent["revocation"]["max_check_interval_s"],
                parent_grant=parent,
                max_uses_per_window=window,
            )
            g = grantmod.sign(g, self.agent)
            self.store_grant(g)
        return g

    # ---- use counting (ledger + reservations, direct + delegated children) ------------
    def _seen(self) -> dict[str, Any]:
        """seen.json, typed (state.seen): msg_id -> a stored ack (an object under
        `ack`) or a reservation (status in_progress, a grt_ grant id, a timestamp —
        the fields a consumed use is counted by, never defaulted). The wrong shape —
        a list, a string, an entry that is not an object, an ack that is not an
        object, an entry that is neither — is IntegrityError state.corrupt naming
        the path: a storage
        failure wherever it surfaces (receive: nothing ledgered, nothing acked, the
        mail unseen; `natively ack`: exit 2; `pending repair`: the copy left
        unresolved, refused by name). Never a verdict on the bundle in hand."""
        return statemod.read(self.state / "seen.json", {}, statemod.seen)

    def _stored_ack_anchors(self) -> list[tuple[str, str, str]]:
        """(msg_id, ledger_head, ledger_entry) of every ack stored in seen.json — the
        head of the chain this node signed over when it answered that message and
        the completion entry it named. The ledger's anchors (`Ledger._check_anchors`).
        Every stored ack is AUTHENTICATED here before its fields anchor anything: the
        structure and the signature (ack.verify), signed by this agent, answering the
        message it is stored under. A stored ack that no longer verifies is a signed
        record of ours that was damaged — IntegrityError seen.corrupt naming the path
        and the msg_id, a storage failure wherever the ledger is checked (never an
        anchor read from an unverified field, never a record skipped): the operator
        restores seen.json. Nothing rebuilds over it (`rebuild_from_completion`
        runs this check first), since the completion it anchored can no longer be
        told from an edited one."""
        out: list[tuple[str, str, str]] = []
        me = self.agent.public
        for msg_id, e in self._seen().items():
            if "ack" not in e:
                continue
            a = e["ack"]
            try:
                ackmod.verify(a)
                if a["from"] != me:
                    raise VerifyError("ack.signer", "not signed by this agent")
                if a["in_reply_to"] != msg_id:
                    raise VerifyError("ack.in_reply_to", f"answers {a['in_reply_to']}")
            except VerifyError as ex:
                raise IntegrityError(
                    "seen.corrupt",
                    f"{self.state / 'seen.json'}: the stored ack for {msg_id} is not this "
                    f"node's reply ({ex.reason}: {ex.detail}); a signed record of ours was "
                    f"damaged — nothing is authorized or rebuilt over it: restore "
                    f"state/seen.json from a backup",
                ) from ex
            out.append((msg_id, a["ledger_head"], a["ledger_entry"]))
        return out

    def check_ledger(self) -> None:
        """The ledger's full check — the repair guard (an unfinished mirror repair
        refuses, ledger.repair_pending) and `Ledger.check_intact` (the chain, every
        entry, the mirror through the head, the stored acks' anchors) — the first
        ledger read of EVERY path that appends to the ledger, marks a mail seen, or
        TRUSTS an existing pending-reply audit: the receive, the pin, the ack
        rebuild, the verbs that record (`revoke`, `deny`), the adapter's
        pending-reply lookups (`MailWire._find_pending_entry`: the poll's aside
        count, the pending list / repair / discard verbs — a discard on record is
        finished from it only after this passes), the poll's flush of held replies
        before any of them is sent or removed (`MailWire._flush_pending_replies`),
        the repair machine at step "truncated" before an audit found on record is
        trusted (barriered, its marker promoted: `_drive_repair`, every store)
        — and, through `ledger_append`,
        immediately before EVERY append in the package (the repair machine's
        audits included: the guard admits its own intent)."""
        self._refuse_if_repairing("ledger", "ledger.prose.txt")
        self.ledger.check_intact()

    def ledger_append(self, **entry: Any) -> dict[str, Any]:
        """The ONE way anything in the package appends to the ledger (a test pins
        the call sites to this method): `check_ledger` first — the repair guard
        and the full check with its anchors, in the same locked boundary as the
        append — then `Ledger.append` (whose own barrier re-reads what it stands
        on). So every path that appends runs the check immediately before the
        line lands, whether or not it ran it earlier: the receive first of all
        (before authorization), the verbs before their enforcing record, the
        repair audits under their own intent, the outbox's undelivered line, the
        replay of a held revocation, the adapter's lines. Nothing is appended over
        a ledger whose anchor check would fail (round-13 Fable read: five sites
        appended with only the guard, and a restore of the JSONL then lost them)."""
        self.check_ledger()
        return self.ledger.append(**entry)

    def _validate_mirror_resume(self, intent: dict[str, Any]) -> None:
        """What a RESUMED mirror repair checks before any cut, marker advance or
        marker removal: the JSONL in full with its anchors (`Ledger.check`), then
        the CURRENT mirror against it — the prose the intent retains, through its
        recorded cut point (`check_prose_prefix`: an equal-length whitespace
        replacement of the prefix is ledger.prose.mismatch naming the line,
        nothing cut, every marker standing) and, past step "intent" (the cut
        done), the whole mirror (`check_mirror`: the regenerated lines, a torn one
        a strict prefix the mend completes, more prose than entries refused)."""
        es = self.ledger.check()
        self.ledger.check_prose_prefix(intent["truncate_to"], es)
        if intent["step"] != "intent":
            self.ledger.check_mirror(es, excess_ok=False)

    def _validate_tail_resume(self, intent: dict[str, Any], *, nested: bool) -> None:
        """What a RESUMED JSONL-tail stage checks before any cut, marker advance or
        marker removal: the chain before the recorded cut point (`check_prefix`,
        anchored — an entry a stored ack names is never past the cut point), the
        chain as the file stands now (`chain_now`, anchored: that prefix plus this
        stage's own audit where it landed, whole or short of only its newline; a
        torn audit line is the tail the stage cuts again), and the CURRENT mirror
        against it (`check_mirror`: under the ledger's own marker a line beyond
        the entries is the excess the stage cuts; under the nested marker the
        mirror is the standing mirror intent's and nothing beyond the entries
        belongs to it). A termination intent (`bytes` 0, the ledger's own marker
        only) validates as `_validate_termination_resume`."""
        if intent["bytes"] == 0:
            if nested:
                raise IntegrityError(
                    "ledger.repair.intent_mismatch",
                    f"{LEDGER_TAIL_MARKER} records a termination intent (bytes 0), which "
                    f"the nested stage never writes; nothing written, the intent stays: "
                    f"inspect both markers before removing either",
                )
            self._validate_termination_resume(intent)
            return
        to = intent["truncate_to"]
        self.ledger.check_prefix(to)
        es, torn = self.ledger.chain_now()
        if intent["step"] == "truncated":
            # past the cut, what follows the cut point is this stage's own audit once
            # or nothing — the rule the termination intent has (round-17 self-gate,
            # finding 3: a whole foreign entry past the cut point was kept, its
            # prose regenerated and the audit appended after it); at step "audited"
            # `_audit_identity` names a displaced audit, read-only, first
            self._only_own_audit_past(
                intent, es[self.ledger.lines_before(to) :], torn, f"the intent's cut point {to}"
            )
        self.ledger.check_mirror(es, excess_ok=not nested)

    def _only_own_audit_past(
        self, intent: dict[str, Any], after: list[dict[str, Any]], torn: bytes, where: str
    ) -> None:
        """What may follow `where` in the JSONL while a tail-stage marker stands
        at step "truncated": nothing, or this stage's own audit ONCE — whole,
        short of only its newline, or torn (its append interrupted; the torn bytes
        are cut again). A whole entry that is not that audit, a second entry, or a
        torn tail AFTER the audit landed whole (the append ran once, so a tear
        after it is not this machine's) is ledger.repair.intent_mismatch by name
        with nothing written and the marker standing (round-16 Fable read, D3;
        round-17 self-gate, findings 2 and 3)."""
        if len(after) > 1 or (after and after[0].get("intent_id") != intent["intent_id"]):
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                f"ledger.jsonl holds {len(after)} whole entries past {where} that are not this "
                f"stage's one audit under intent {intent['intent_id']} (the first names intent "
                f"{after[0].get('intent_id')!r}); only that audit follows while the marker "
                f"stands; nothing written, the intent stays: inspect the file and the marker "
                f"before removing either",
            )
        if after and torn:
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                f"ledger.jsonl carries a torn tail ({len(torn)} bytes) past this stage's audit, "
                f"which landed whole past {where}; the audit's append ran once, so the tear is "
                f"not this machine's write; nothing written, nothing cut, the intent stays: "
                f"inspect the file and the marker before removing either",
            )

    def _validate_termination_resume(self, intent: dict[str, Any]) -> None:
        """What a TERMINATION intent (the fresh mend case: `_termination_intent`)
        checks before any step runs — on the fresh run before the marker is
        written, on a resume before the newline, the mend, the audit or the
        marker's removal: the chain as the file stands, anchored (`chain_now`:
        the entry past the cut point whole, terminated or short of only its
        newline; a torn tail there is this stage's own audit append, cut again at
        step "truncated" — at step "intent" nothing of ours wrote after the entry,
        so a torn tail there is not this machine's and refuses); the line at the
        cut point bound by hash to the entry the intent recorded (`line_at`), and
        the bytes past the cut point EXACTLY that line or that line plus its
        newline at step "intent" (`after_line`: a whole chained entry there,
        terminated or short of only its newline, is not this machine's write
        either and refuses — before, it passed the chain and the mirror check and
        the intent step terminated it under an intent whose hash names another
        entry: round-16 Fable read, D3), at step "truncated" additionally this
        stage's own audit — the one entry past the bound one carries this intent's
        id (whole or short of only its newline; a torn tail there is the audit's
        append, cut again), the same rule the cut intent applies to the bytes past
        its cut point; the CURRENT mirror against that chain with nothing beyond
        the entries (`check_mirror`: the partial line the mend completes, or the
        mended line, or the audit's line once it landed); and the recorded mirror
        cut point the end of the prose before that entry (`check_mirror_cut`).
        Anything else is refused by name with the marker standing and nothing
        written."""
        if "mirror_to" not in intent:
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                "the marker records a termination intent (bytes 0) without its mirror cut "
                "point (mirror_to); nothing written, the intent stays: inspect the marker "
                "before removing it",
            )
        to = intent["truncate_to"]
        es, torn = self.ledger.chain_now()
        if torn and intent["step"] == "intent":
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                f"ledger.jsonl carries a torn tail past the termination intent's entry at "
                f"{to} before any step of it ran; not this machine's write, nothing "
                f"written, the intent stays: inspect the file and the marker before "
                f"removing either",
            )
        if "sha256:" + sha256_hex(self.ledger.line_at(to)) != intent["tail_sha256"]:
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                f"the line of ledger.jsonl at the termination intent's cut point {to} is "
                f"not the entry the intent recorded ({intent['tail_sha256']}); nothing "
                f"written, the intent stays: inspect the file and the marker before "
                f"removing either",
            )
        # the bytes past the bound line: nothing, or its newline (the terminated
        # sibling) — at step "intent" nothing else of ours wrote there, so a whole
        # chained entry there (terminated or short of only its newline) is a hand
        # edit or a foreign tool and refuses by name, never terminated as "the last
        # entry" under an intent whose hash names another line; at step "truncated"
        # the one entry allowed past the bound one is this stage's own audit
        past = self.ledger.after_line(to)
        if intent["step"] == "intent" and past not in (b"", b"\n"):
            raise IntegrityError(
                "ledger.repair.intent_mismatch",
                f"ledger.jsonl carries {len(past) - 1} bytes past the termination intent's "
                f"entry at {to} and its newline before any step of it ran (a whole entry "
                f"there is not this machine's write: nothing of ours appends while the "
                f"marker stands); nothing written, nothing terminated, the intent stays: "
                f"inspect the file and the marker before removing either",
            )
        if intent["step"] == "truncated":
            self._only_own_audit_past(
                intent,
                es[self.ledger.lines_before(to) + 1 :],
                torn,
                f"the termination intent's entry at {to}",
            )
        self.ledger.check_mirror(es, excess_ok=False)
        self.ledger.check_mirror_cut(intent["mirror_to"], self.ledger.lines_before(to), es)

    def _reservations(self) -> list[dict[str, Any]]:
        """In-progress reservations whose message never reached the ledger: each is a
        consumed use (fail closed)."""
        out = []
        for msg_id, s in self._seen().items():
            if "ack" in s:
                continue
            if self.ledger.find_msg(msg_id) is None:
                out.append({"msg_id": msg_id, **s})
        return out

    def _uses_of(self, grant_id: str, since: datetime | None = None) -> int:
        n = self.ledger.uses(grant_id, since=since)
        for r in self._reservations():
            if r.get("grant_id") == grant_id and (since is None or parse(r["ts"]) >= since):
                n += 1
        return n

    def _family(self, grant_id: str) -> list[str]:
        """A grant and every delegated child of it on file."""
        ids = [grant_id]
        for g in self.grants_on_file():
            p = g.get("parent_grant")
            if isinstance(p, dict) and p.get("grant_id") == grant_id and g["grant_id"] != grant_id:
                ids.append(g["grant_id"])
        return ids

    def grant_uses(self, g: dict[str, Any], *, family: bool = False) -> tuple[int, int | None]:
        ids = self._family(g["grant_id"]) if family else [g["grant_id"]]
        uses = sum(self._uses_of(i) for i in ids)
        w = g.get("max_uses_per_window")
        in_window = None
        if w is not None:
            since = plus(self.now(), -w["window_s"])
            in_window = sum(self._uses_of(i, since=since) for i in ids)
        return uses, in_window

    def _check_uses(self, g: dict[str, Any]) -> None:
        uses, in_window = self.grant_uses(g, family=True)
        grantmod.uses_ok(g, uses, in_window)
        parent = g["parent_grant"]
        if parent is not None:
            # the parent's budget covers its direct uses plus every child's
            puses, pwin = self.grant_uses(parent, family=True)
            try:
                grantmod.uses_ok(parent, puses, pwin)
            except VerifyError as e:
                raise VerifyError(
                    "grant.parent." + e.reason.removeprefix("grant."), f"parent: {e.detail}"
                ) from e

    # ---- revocation / denial (issuing side) ----------------------------------------
    def build_revocation(
        self,
        *,
        cards: list[str] | None = None,
        grants: list[str] | None = None,
        principal_statement: str = "",
    ) -> dict[str, Any]:
        """The signed revocation object, recorded nowhere yet: the CLI composes and
        checks the outgoing bundle from it BEFORE `record_revocation` changes what
        this node enforces (and never records it on a dry run)."""
        return revmod.sign(
            revmod.build(
                principal_key=self.principal.public,
                ts=self.ts(),
                cards=cards,
                grants=grants,
                principal_statement=principal_statement,
            ),
            self.principal,
        )

    def revoke(
        self,
        *,
        cards: list[str] | None = None,
        grants: list[str] | None = None,
        principal_statement: str = "",
    ) -> dict[str, Any]:
        r = self.build_revocation(
            cards=cards, grants=grants, principal_statement=principal_statement
        )
        self.record_revocation(r)
        return r

    def record_revocation(self, r: dict[str, Any]) -> None:
        """The enforcing record: the feed line (durable), then the ledger entry."""
        cards, grants = r["revokes"]["cards"], r["revokes"]["grants"]
        with self._locked():
            # the ledger in full BEFORE the enforcing record lands: a ledger that
            # fails its check (its anchors included) refuses the verb by name with
            # nothing written, so the feed never holds a revocation the ledger has
            # no entry for; a damaged ledger already fails every receive closed, so
            # nothing a revocation would stop can run in the meantime
            self.check_ledger()
            self._refuse_if_repairing("feed", "revocations.jsonl")
            self.revocations.add(r, pinned=self.pinned)
            self.ledger_append(
                ts=self.ts(),
                actor=self.card["principal"]["name"],
                grant_id=None,
                action="revocation.issued",
                params_hash=hash_of(r["revokes"]),
                outcome="recorded",
                detail=f"{r['rev_id']} cards={cards} grants={grants}",
            )

    def deny(
        self,
        *,
        deny: list[dict[str, str]],
        principal_statement: str,
        subject_agent: str | None = None,
    ) -> dict[str, Any]:
        if not self.extensions["standing_denial"]:
            raise ValueError("standing_denial is behind extensions.standing_denial (off)")
        d = denialmod.sign(
            denialmod.build(
                principal_key=self.principal.public,
                ts=self.ts(),
                deny=deny,
                principal_statement=principal_statement,
                subject_agent=subject_agent,
            ),
            self.principal,
        )
        with self._locked():
            # order: the ledger in full first (a ledger that fails its check refuses
            # the verb by name with nothing written, as for `revoke`), then the
            # enforcing record durable (the store's line fsynced, then its
            # directory), then the ledger entry, then the report and the return; a
            # store failure leaves no ledger entry and is reported
            self.check_ledger()
            try:
                self._refuse_if_repairing("denial", "denials.jsonl")
                self.denials.add(d, pinned=self.pinned)
            except (OSError, StorageError) as e:
                self.report(
                    f"natively: standing denial {d['denial_id']} NOT recorded, the store "
                    f"write failed; nothing ledgered: {type(e).__name__}: {e}"
                )
                if isinstance(e, StorageError):
                    raise  # local corruption of the store (IntegrityError), as it is
                raise StorageError(f"{type(e).__name__}: {str(e)[:200]}", e) from e
            self.ledger_append(
                ts=self.ts(),
                actor=self.card["principal"]["name"],
                grant_id=None,
                action="denial.issued",
                params_hash=hash_of(d["deny"]),
                outcome="recorded",
                detail=f"{d['denial_id']} {d['principal_statement'][:80]}",
            )
        self.report(f"natively: standing denial {d['denial_id']} recorded")
        return d

    def mark_lookup_ok(self) -> None:
        """A COMPLETE revocation lookup succeeded (the poll pass fetched everything on
        the wire and applied its cards and revocations). Freshness clock resets."""
        with self._locked():
            self.revocations.mark_checked(self.now())

    # ---- compose --------------------------------------------------------------------
    def compose_card(self) -> dict[str, Any]:
        return bundlemod.make("card", self.card)

    def compose_info(
        self, to_card: dict[str, Any], text: str, in_reply_to: str | None = None
    ) -> dict[str, Any]:
        m = msgmod.sign(
            msgmod.info(
                from_key=self.agent.public,
                to_key=to_card["agent"]["key"],
                ts=self.ts(),
                text=text,
                in_reply_to=in_reply_to,
            ),
            self.agent,
        )
        return bundlemod.make("message", m, cards=[self.card])

    def compose_action(
        self,
        to_card: dict[str, Any],
        *,
        action: str,
        resource: str,
        params: dict[str, Any],
        grant_ids: list[str],
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        grants = []
        for gid in grant_ids:
            g = self.load_grant(gid)
            if g is None:
                raise KeyError(f"unknown grant {gid}")
            grants.append(g)
        m = msgmod.sign(
            msgmod.action(
                from_key=self.agent.public,
                to_key=to_card["agent"]["key"],
                ts=self.ts(),
                action=action,
                resource=resource,
                params=params,
                grant_ids=grant_ids,
                in_reply_to=in_reply_to,
            ),
            self.agent,
        )
        return bundlemod.make("message", m, cards=[self.card], grants=grants)

    def compose_revocation(self, r: dict[str, Any]) -> dict[str, Any]:
        return bundlemod.make("revocation", r, cards=[self.card])

    # ---- receive ------------------------------------------------------------------------
    def receive(self, b: dict[str, Any]) -> list[dict[str, Any]]:
        """Verify and apply one inbound bundle. Returns bundles to send back (acks).
        Every failure is printed and ledgered; nothing is dropped silently. Runs under
        the state lock; anything that is not a VerifyError/RefusedError is ledgered as
        verify_failed:malformed and the poll goes on — except a LOCAL storage failure
        (OSError from the feed, the ledger, a state file), which is not about the
        bundle at all: it is reported and raised as StorageError, nothing is ledgered
        (the ledger may be what failed), and the adapter keeps the mail unseen."""
        with self._locked():
            try:
                return self._receive(b)
            except StorageError as e:
                # local corruption (IntegrityError: a self card that fails, a stored ack
                # that no longer verifies): a storage failure, as it is — reported
                # here once, so the refusal and its path reach the operator, not only
                # the poll's count
                self.report(
                    f"natively: storage failure while applying a {b.get('kind')!r} bundle; "
                    f"nothing recorded, the mail is read again next poll: "
                    f"{type(e).__name__}: {e}"
                )
                raise
            except (VerifyError, RefusedError) as e:
                err: VerifyError | RefusedError = e
            except OSError as e:
                raise self._storage_failure(b, e) from e
            except Exception as e:  # noqa: BLE001 — hostile input never stops the poll
                err = VerifyError("malformed", f"{type(e).__name__}: {str(e)[:200]}")
            # ledgering the refusal is a write too: a failure THERE is the same storage
            # failure (nothing recorded, the mail stays unseen), never an escape —
            # an OSError of the write, or the ledger's own corruption met at the
            # read before it (IntegrityError: an unterminated tail, a torn line, a
            # mirror that does not verify) when the refusal is the FIRST ledger
            # read of this bundle (a bundle refused before anything else was read)
            try:
                self._fail("wire", _msg_id_of(b), err)
            except StorageError as e:
                self.report(
                    f"natively: storage failure ledgering the refusal of a {b.get('kind')!r} "
                    f"bundle; nothing recorded, the mail is read again next poll: "
                    f"{type(e).__name__}: {e}"
                )
                raise
            except OSError as e:
                raise self._storage_failure(b, e) from e
            return []

    def _storage_failure(self, b: dict[str, Any], e: OSError) -> StorageError:
        self.report(
            f"natively: storage failure while applying a {b.get('kind')!r} bundle; "
            f"nothing recorded, the mail is read again next poll: "
            f"{type(e).__name__}: {e}"
        )
        return StorageError(f"{type(e).__name__}: {str(e)[:200]}", e)

    def _receive(self, b: dict[str, Any]) -> list[dict[str, Any]]:
        # the ledger and its mirror in full, the FIRST ledger read of every receive
        # that may ledger (every kind does): the guard (a repair of the mirror
        # unfinished refuses every append, so nothing is authorized over it) and
        # the read-only check of both files — the chain, every entry, the mirror
        # compared through the head — BEFORE authorization counts uses, before a
        # reservation is written, before the executor runs. A ledger that fails
        # its own check or disagrees with its mirror is a storage failure by its
        # name (ledger.chain, ledger.corrupt, ledger.prose.mismatch, ...): nothing
        # reserved, nothing executed, nothing ledgered, the mail unseen. The same
        # check inside the append's barrier stays; no cache stands between the two
        self.check_ledger()
        # the enforcement configuration read — and so validated — before anything of
        # this bundle lands: a config the loader refuses is state.corrupt with no card
        # imported, no grant stored, nothing ledgered, the mail unseen (before, an
        # attached card was written to cards-pending and ledgered card.received
        # before the read refused; round-19 self-gate, second run)
        self._config_now()
        bundlemod.check(b)  # the envelope refused is ledgered too: after the check
        for c in b["cards"]:
            try:
                h, trusted = self.import_card(c)
                if not trusted:
                    self.report(
                        f"natively: card {h} from unpinned principal {c['principal']['key']} "
                        f"held in cards-pending; `natively pin <key> --name ...` to trust it"
                    )
                    self.ledger_append(
                        ts=self.ts(),
                        actor=c["agent"]["name"],
                        grant_id=None,
                        action="card.received",
                        params_hash=h,
                        outcome="unpinned",
                        detail="principal not pinned; held",
                    )
            except VerifyError as e:
                self._fail("card", None, e)
        refused_grants: set[str] = set()
        for g in b["grants"]:
            gid = g.get("grant_id") if isinstance(g, dict) else None
            try:
                # authenticate BEFORE anything touches the store: structure, signatures,
                # rooted in a pinned principal (or a delegation chain that is)
                grantmod.authenticate(g, pinned=self.pinned, extensions=self.extensions)
                self._check_grant_identity(g)
                parent = g["parent_grant"]
                if parent is not None and self.load_grant_any(parent["grant_id"]) is None:
                    # a parent first met inside a child is on file under its own id from
                    # now on (grants-embedded/: held to, never executable), so every
                    # later copy is compared with this one
                    self.store_grant(parent, embedded=True)
                # the attached grant itself arrived top-level, addressed to this node:
                # executable from now on (a parent that was only embedded before is
                # promoted by arriving like this, and it must equal the embedded copy)
                self.store_grant(g)
            except VerifyError as e:
                if is_id(gid, "grt_"):
                    refused_grants.add(gid)
                self._fail("grant", None, e)
        kind = b["kind"]
        if kind == "card":
            return self._receive_card(b["object"])
        if kind == "message":
            return self._receive_message(b["object"], refused_grants)
        if kind == "ack":
            return self._receive_ack(b["object"])
        if kind == "revocation":
            return self._receive_revocation(b["object"])
        return []

    def _check_grant_identity(self, g: dict[str, Any]) -> None:
        """A grant id names one object. Within the candidate chain first: the child
        and the parent it embeds may not share an id (two different objects would
        otherwise be written under one name, whichever lands last winning). Then
        against the store: the attached grant AND the parent it embeds must each equal
        the grant on file under that id (grants/ or grants-embedded/), or the whole
        attachment is refused. A different body under a known id is never written over
        the original (it could be one we issued, or the parent whose budget the child
        is spending: a re-signed parent variant with a larger limit would otherwise
        lift it). Nothing is written before every check here passed."""
        chain = [x for x in (g, g["parent_grant"]) if x is not None]
        ids = [x["grant_id"] for x in chain]
        if len(set(ids)) != len(ids):
            raise VerifyError(
                "grant.id_conflict",
                f"{ids[0]} names both the grant and its embedded parent; nothing stored",
            )
        for x in chain:
            on_file = self.load_grant_any(x["grant_id"])
            if on_file is not None and canonicalize(on_file) != canonicalize(x):
                raise VerifyError(
                    "grant.id_conflict",
                    f"{x['grant_id']} differs from the grant on file; the original is kept",
                )

    def _fail(
        self, what: str, msg_id: str | None, e: VerifyError | RefusedError, actor: str = "wire"
    ) -> None:
        self.report(f"natively: {what} rejected: {e.reason} — {e.detail}")
        self.ledger_append(
            ts=self.ts(),
            actor=actor,
            grant_id=None,
            action=f"{what}.verify",
            params_hash=None,
            outcome=f"verify_failed:{e.reason}",
            msg_id=msg_id,
            detail=e.detail,
        )

    def _receive_card(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            h, trusted = self.import_card(c)
        except VerifyError as e:
            self._fail("card", None, e)
            return []
        self.ledger_append(
            ts=self.ts(),
            actor=c["agent"]["name"],
            grant_id=None,
            action="card.received",
            params_hash=h,
            outcome="trusted" if trusted else "unpinned",
            detail=f"principal {c['principal']['name']} ({c['principal']['principal_kind']})",
        )
        if not trusted:
            self.report(f"natively: card {h} held; pin {c['principal']['key']} to trust it")
        return []

    def _receive_revocation(self, r: dict[str, Any]) -> list[dict[str, Any]]:
        self._refuse_if_repairing("feed", "revocations.jsonl")  # a storage failure: unseen
        try:
            added = self.revocations.add(r, pinned=self.pinned)
        except VerifyError as e:
            if e.reason == "revocation.principal.unpinned":
                self._hold_revocation(r)
            else:
                self._fail("revocation", None, e)
            return []
        self.ledger_append(
            ts=self.ts(),
            actor=r["principal"]["key"][:32],
            grant_id=None,
            action="revocation.received",
            params_hash=hash_of(r["revokes"]),
            outcome=added,
            detail=f"{r['rev_id']} cards={r['revokes']['cards']} grants={r['revokes']['grants']}",
        )
        return []

    def _hold_revocation(self, r: dict[str, Any]) -> None:
        """Structure passed and only the principal is not pinned (the feed checks that
        before the signature). Unpinned means untrusted, not unverifiable: the
        signature is checked NOW against the principal key the object names, and a
        failure is ledgered with nothing written — an unsigned variant can never
        displace a held original. What verifies is kept under revocations-pending/,
        keyed by rev_id AND body hash and never overwritten, so pin() and the startup
        sweep can replay every candidate (its mail is marked seen and will not be
        read again)."""
        pk = r["principal"]["key"]
        try:
            revmod.verify(r, pinned={pk})
        except VerifyError as e:
            self._fail("revocation", None, e)
            return
        d = self.state / "revocations-pending"
        d.mkdir(exist_ok=True)
        p = d / f"{r['rev_id']}-{hash_of(r)[7:19]}.json"
        if p.exists():
            # the same body again is the same file (a variant is another file): not a
            # short-circuit — the copy found is READ, verified and compared with the
            # authenticated document in hand first (a damaged copy under this name,
            # or another document, is revocation.held_corrupt: a storage failure,
            # the mail unseen, the copy kept and named; a hold never stands on a
            # file it did not check), then the file and its directory are fsynced
            # again, so a retry after a hold whose barrier failed stands on synced
            # bytes before its mail is marked seen
            held, _pk = self._read_held_revocation(p)
            if hash_of(held) != hash_of(r):
                raise IntegrityError(
                    "revocation.held_corrupt",
                    f"{p}: the held copy is not the revocation just received under its "
                    f"name; it is kept and nothing is authorized until it is restored or "
                    f"removed by hand",
                )
            fsync_existing(p)
        else:
            self._write_state(p, r)
        self.report(
            f"natively: revocation {r['rev_id']} from unpinned principal {pk} held in "
            f"revocations-pending; `natively pin {pk} --name ...` replays it"
        )
        self.ledger_append(
            ts=self.ts(),
            actor=pk[:32],
            grant_id=None,
            action="revocation.received",
            params_hash=hash_of(r["revokes"]),
            outcome="unpinned",
            detail=f"{r['rev_id']} held; principal not pinned",
        )

    def _receive_ack(self, a: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            ackmod.verify(a)
            if a["to"] != self.agent.public:
                raise VerifyError("ack.misaddressed", "ack.to is not this agent")
            sender = self._sender_card(a["from"], "ack")
            entry = self.outbox_entry(a["in_reply_to"])
            if entry is not None and entry["to"] != a["from"]:
                # only the recipient of the message may acknowledge it
                raise VerifyError(
                    "ack.signer",
                    f"ack for {a['in_reply_to']} signed by {self.actor_name(a['from'])}, "
                    f"which is not that message's recipient",
                )
        except VerifyError as e:
            self._fail("ack", a.get("in_reply_to") if isinstance(a, dict) else None, e)
            return []
        # Audit first, then the status — the order the undelivered transition keeps
        # (`outbox_mark_undelivered`): the peer-heads file is READ first (a heads
        # file of the wrong shape refuses with nothing written, as before), then the
        # out.ack line lands (and its mirror), then the outbox mark and the peer
        # head are written. Before, the mark and the head were written first, so a
        # failed append left the entry acked with no record and the retry's line
        # said "(no outbox entry)" for an entry that exists (round-19 Fable read,
        # finding 10). The detail is read from the entry as it stands; the mark is
        # idempotent, and the mail stays unseen until both landed. Every delivered
        # ack is ledgered (a re-delivered one too, naming the entry's state).
        msg_id = a["in_reply_to"]
        heads = self._peer_heads()
        if entry is None:
            suffix = " (no outbox entry)"
        elif entry["status"] in ("pending", "exported"):
            suffix = ""
        else:
            suffix = f" (outbox entry already {entry['status']})"
        self.ledger_append(
            ts=self.ts(),
            actor=sender["agent"]["name"],
            grant_id=None,
            action=OUT_ACK,  # outbound: never the completion of an inbound message
            params_hash=a["ledger_entry"],
            outcome=ackmod.outcome_kind(a),
            msg_id=msg_id,
            detail=f"{a['outcome']} peer head {a['ledger_head'][:19]}{suffix}",
            direction="out",
        )
        self.outbox_mark_acked(msg_id)
        heads[a["from"]] = {
            "head": a["ledger_head"],
            "entry": a["ledger_entry"],
            "ack_id": a["ack_id"],
            "ts": a["ts"],
            "in_reply_to": msg_id,
        }
        self._write_state(self.state / "peer-heads.json", heads)
        return []

    def _peer_heads(self) -> dict[str, Any]:
        """peer-heads.json, typed: agent key -> {head: <string>, ...}."""
        return statemod.read(self.state / "peer-heads.json", {}, statemod.peer_heads)

    def peer_head(self, agent_key: str) -> str | None:
        h = self._peer_heads().get(agent_key)
        return h["head"] if h else None

    def _receive_message(
        self, m: dict[str, Any], refused_grants: set[str] | None = None
    ) -> list[dict[str, Any]]:
        try:
            msgmod.verify(m)
        except VerifyError as e:
            mid = m.get("msg_id") if isinstance(m, dict) else None
            self._fail("message", mid if is_id(mid, "msg_") else None, e)
            return []
        msg_id = m["msg_id"]
        try:
            if m["to"] != self.agent.public:
                raise VerifyError("message.misaddressed", "message.to is not this agent")
            sender = self._sender_card(m["from"], "message")
        except VerifyError as e:
            self._fail("message", msg_id, e)
            return []
        actor = sender["agent"]["name"]
        # every message ends in an ack that carries this node's card: the self card
        # is verified here, before anything is ledgered for the message — a card
        # that fails (card.self_corrupt) is a storage failure: nothing acked, the
        # mail stays unseen
        self._self_card()
        seen = self._seen().get(msg_id)
        if isinstance(seen, dict) and "ack" in seen:
            # the stored ack is validated like a held reply before it is answered
            # with: one that no longer verifies is LOCAL corruption (seen.corrupt, a
            # storage failure: the mail stays unseen, nothing is sent, the poll is
            # incomplete) — never rebuilt here, never sent by any path
            r, why = self.stored_reply(msg_id)
            if r is None:
                raise IntegrityError(
                    "seen.corrupt",
                    f"{self.state / 'seen.json'}: the stored ack for {msg_id} is not this "
                    f"node's reply ({why}); `natively pending repair` rebuilds it from the "
                    f"ledger completion",
                )
            self.report(f"natively: duplicate {msg_id}; re-sending the stored ack")
            return [r]
        # No stored ack. A completion entry in the ledger (applied, information,
        # refused, failed) means the message was handled and only the ack was lost:
        # rebuild it, re-evaluate nothing. Only inbound completions count (never a
        # peer's ack naming this msg_id).
        led = self.ledger.find_msg(msg_id)
        if led is not None:
            return [self._rebuild_ack(m, led)]
        if seen is not None:
            return [self._resolve_interrupted(m, seen, actor)]
        try:
            body = msgmod.decode_body(m)
        except VerifyError as e:
            # refused and ledgered as a completion (the reason stays in detail so the
            # ack can be rebuilt from it), whatever grant_ids says
            entry = self._refuse(m, None, {}, e, actor)
            return [self._ack(m, "refused", e.reason, entry)]
        if msgmod.is_information(m):
            entry = self.ledger_append(
                ts=self.ts(),
                actor=actor,
                grant_id=None,
                action="info.received",
                params_hash=hash_of(body),
                outcome="information",
                msg_id=msg_id,
                detail=(body.get("text") or "")[:120],
            )
            return [self._ack(m, "information", "", entry)]
        return [self._apply_action(m, body, sender, refused_grants or set())]

    def _rebuild_ack(self, m: dict[str, Any], led: dict[str, Any]) -> dict[str, Any]:
        """The ack for a message the ledger says was completed: outcome kind from the
        entry's outcome, the reason from the entry (a `refused` / `failed` entry keeps
        `<reason>: <detail>` in detail; `failed:interrupted` carries it in the outcome)."""
        kind = outcome_kind(led["outcome"])
        if ":" in led["outcome"]:
            detail = led["outcome"].split(":", 1)[1]
        elif kind in ("refused", "failed"):
            detail = led.get("detail", "").split(":", 1)[0]
        else:
            detail = ""
        self.report(
            f"natively: {m['msg_id']} completed ({led['outcome']}) but its ack was lost; rebuilding"
        )
        # Promoting the recovered completion to a stored ack is a durability step:
        # the entry found may be an unsynced tail (its append failed AFTER the bytes
        # became visible), and saving the ack releases the reservation that is the
        # last durable record of the use. The ledger barrier is re-established first
        # (both files fsynced, the mirror made whole); an OSError here is a storage
        # failure and the reservation stays.
        self.ledger.barrier()
        return self._ack(m, kind, detail, led)

    def reply_problem(self, r: Any, msg_id: str | None, kind: str | None) -> str | None:
        """Why a reply bundle is NOT this node's reply to `msg_id` — the ONE
        validation every reply passes before it is HELD and again before it is
        SENT, on the same-poll path and the flush alike (and the stored ack a
        re-delivery or `natively ack` answers with, the source `natively pending
        repair` rebuilds from): the envelope, every card it carries (verified in
        full, one of them this agent's), the ack's structure and signature (ours),
        and its correspondence to the reply it is taken for — the kind and the
        message id. A reply whose signed fields were damaged would be accepted by
        the transport and rejected by the peer, the obligation lost. This node's
        own card is verified first (`card`): a self card that fails is
        card.self_corrupt, a storage failure raised through, never a verdict on the
        reply. None when sound."""
        self._self_card()  # card.self_corrupt (or an OSError) raises through: a storage failure
        try:
            bundlemod.check(r)
        except VerifyError as e:
            return f"{e.reason}: {e.detail}"
        except Exception as e:  # noqa: BLE001 — a shape the checker did not expect
            return f"{type(e).__name__}: {str(e)[:120]}"
        if kind != "ack" or r["kind"] != "ack":
            return f"kind {r['kind']!r} taken for a {kind!r} reply (replies are acks)"
        if r["grants"]:
            # a reply carries no grants (and no messages: one object, an ack); an
            # attachment here is nothing this node composed, and nothing the
            # reply validation would otherwise look at
            return (
                f"reply.grants_not_allowed: a reply carries no grants ({len(r['grants'])} attached)"
            )
        for i, c in enumerate(r["cards"]):
            try:
                cardmod.verify(c)
            except VerifyError as e:
                return f"cards[{i}]: {e.reason}: {e.detail}"
            except Exception as e:  # noqa: BLE001 — a shape the card checker did not expect
                return f"cards[{i}]: {type(e).__name__}: {str(e)[:120]}"
        if not any(c["agent"]["key"] == self.agent.public for c in r["cards"]):
            return "the envelope carries no card for this agent"
        o = r["object"]
        try:
            ackmod.verify(o)
        except VerifyError as e:
            return f"{e.reason}: {e.detail}"
        if o["from"] != self.agent.public:
            return "the ack is not signed by this agent"
        if o["in_reply_to"] != msg_id:
            return f"in_reply_to {o['in_reply_to']} is not {msg_id}"
        return None

    def stored_reply(self, msg_id: str) -> tuple[dict[str, Any] | None, str | None]:
        """The stored ack for `msg_id` (seen.json) as a bundle, validated in full
        (`reply_problem`): (bundle, None) when sound; (None, None) when nothing is
        stored; (None, why) when the stored ack is damaged — a re-delivery treats
        that as `seen.corrupt` (a storage failure), `natively pending repair` falls
        through to the ledger completion, and nothing sends it. A storage error on
        the way (the seen file unreadable or not parsing, the self card unreadable
        or card.self_corrupt) is raised through — a storage failure of the caller,
        never "absent" and never a fallthrough to another source."""
        seen = self._seen().get(msg_id)
        if not isinstance(seen, dict) or "ack" not in seen:
            return None, None
        try:
            r = bundlemod.make("ack", seen["ack"], cards=[self.card])
        except (OSError, StorageError):
            raise  # the self card: a storage failure, never a damaged-ack verdict
        except Exception as e:  # noqa: BLE001 — a stored ack of a shape make() rejects
            return None, f"{type(e).__name__}: {str(e)[:120]}"
        why = self.reply_problem(r, msg_id, "ack")
        return (r, None) if why is None else (None, why)

    def rebuild_from_completion(self, msg_id: str) -> dict[str, Any] | None:
        """The ack for an inbound message this node completed, rebuilt from the
        ledger's completion entry — the path a re-delivery takes (`_rebuild_ack`: the
        ledger barrier first, then the ack stored, replacing whatever seen.json held
        for the message) — addressed to the agent the entry names, resolved to
        exactly one card on file. None when there is no completion, or the actor
        resolves to no single card. Only `natively pending repair` calls it (after
        the stored ack failed validation or is absent); nothing here sends."""
        with self._locked():
            self._self_card()  # before anything is read, signed or stored: card.self_corrupt
            # the ledger in full, its stored acks authenticated and anchored, BEFORE a
            # completion is read from it and promoted: a damaged stored ack for this
            # very message is seen.corrupt here (a rebuild over it would sign a new
            # ack for an entry the damaged one can no longer vouch for), an edited
            # completion whose anchor still stands is ledger.head.mismatch
            self.check_ledger()
            led = self.ledger.find_msg(msg_id)
            if led is None:
                return None
            # the recipient is taken from a card ON FILE, so every card read here is
            # verified in full (structure, both signatures) and bound to its file name
            # (the hash) BEFORE a key from it is signed for — the typed card loader,
            # the same read every card on file gets: a card whose agent key was
            # damaged while its name survived would otherwise become a validly signed
            # ack to nobody. A damaged card is local corruption, a storage failure
            # (card.corrupt, the path named), never skipped
            named: list[dict[str, Any]] = []
            for f in list_dir(self.state / "cards", ".json"):
                c = statemod.read_card(f)
                if c is not None and c["agent"]["name"] == led["actor"]:
                    named.append(c)
            if len(named) != 1:  # none, or an ambiguous name: no single recipient
                return None
            (card,) = named
            return self._rebuild_ack({"msg_id": msg_id, "from": card["agent"]["key"]}, led)

    def _resolve_interrupted(
        self, m: dict[str, Any], reservation: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        """A re-delivery of a message whose use was reserved but which never reached
        the ledger: the outcome is unknown, the use stays consumed, and the message is
        acked failed:interrupted (ledgered once; the next re-delivery is answered from
        that entry)."""
        msg_id = m["msg_id"]
        self.report(f"natively: {msg_id} was interrupted mid-apply; use consumed, acking failed")
        try:
            body = msgmod.decode_body(m)
        except VerifyError:
            body = {}
        entry = self.ledger_append(
            ts=self.ts(),
            actor=actor,
            grant_id=reservation.get("grant_id"),
            action=body.get("action", "?"),
            params_hash=hash_of(body.get("params", {})),
            outcome="failed:interrupted",
            msg_id=msg_id,
            detail=f"reserved at {reservation.get('ts')}; no ledger entry; use consumed",
        )
        return self._ack(m, "failed", "interrupted", entry)

    def _apply_action(
        self,
        m: dict[str, Any],
        body: dict[str, Any],
        sender: dict[str, Any],
        refused_grants: set[str],
    ) -> dict[str, Any]:
        msg_id, actor = m["msg_id"], sender["agent"]["name"]
        if body["type"] != "action":
            e = RefusedError(
                "message.body.type", "a message with grant_ids must carry an action body"
            )
            entry = self._refuse(m, None, body, e, actor)
            return self._ack(m, "refused", e.reason, entry)
        action, resource, params = body["action"], body["resource"], body["params"]
        params_hash = hash_of(params)
        if action.startswith(OUTBOUND_PREFIX):
            # the outbound ledger names are reserved; a peer-chosen "out.*" action is
            # refused before any grant is read (its refusal entry is direction "in",
            # so a lost ack for it is still recovered from that entry)
            e = RefusedError(
                "executor.unsupported", f"action {action!r} is in the reserved out.* namespace"
            )
            entry = self._refuse(m, None, body, e, actor)
            return self._ack(m, "refused", e.reason, entry)
        # Held revocations a startup sweep could not replay (the feed was torn): no
        # authorization at all until they are in the feed. Attempted here first —
        # the feed may have been repaired by another process since. A replay that
        # fails is the storage failure it is — the feed still torn or a record of
        # it corrupt (IntegrityError), revocations-pending/ unreadable (OSError:
        # the enumeration is a storage failure, never "nothing held"), a held copy
        # corrupt, a replay write failed, a feed repair unfinished — raised
        # through: receive and the adapter count it, the mail stays unseen,
        # nothing is ledgered or acked, and the action is evaluated again after
        # `natively feed repair`. Never a verdict the peer keeps: every cause is a
        # fault in a file of ours, so no named refusal exists for this state.
        if self._replay_pending() is not None:
            for pk in self.pinned:
                self._replay_pending_revocations(pk, why="replay before authorizing")
            # cleared only once the enumeration AND every replay succeeded
            self._clear_replay_marker()
        # Standing denial (extension): checked before any scope, no grant overrides it.
        if self.extensions["standing_denial"]:
            d = self.denials.denied(
                action=action,
                resource=resource,
                card_hash=self.card_hash,
                principal_key=self.card["principal"]["key"],
            )
            if d is not None:
                e = RefusedError(
                    "denied", f"standing denial {d['denial_id']}: {d['principal_statement'][:80]}"
                )
                entry = self._refuse(m, None, body, e, actor)
                return self._ack(m, "refused", e.reason, entry)
        # Our own card revoked by our principal: nothing is authorized any more.
        if self.card_revoked(self.card):
            e = RefusedError("card.revoked", "this agent's card has been revoked")
            entry = self._refuse(m, None, body, e, actor)
            return self._ack(m, "refused", e.reason, entry)
        reasons: list[str] = []
        chosen: tuple[dict[str, Any], dict[str, Any]] | None = None
        for gid in m["grant_ids"]:
            if gid in refused_grants:
                reasons.append(f"{gid}: attached copy failed verification; not substituting")
                continue
            g = self.load_grant(gid)
            if g is None:
                reasons.append(f"{gid}: not attached and not on file")
                continue
            try:
                self._grant_valid_now(g)
                self._check_uses(g)
                s = grantmod.match_scope(g, action, resource, params)
                self.revocations.assert_fresh(g, s, self.now(), grace_s=self.poll_s)
                chosen = (g, s)
                break
            except RefusedError as e:
                if e.reason == "scope.regex_timeout":
                    entry = self._refuse(m, gid, body, e, actor)
                    return self._ack(m, "refused", e.reason, entry)
                reasons.append(f"{gid}: {e.reason} ({e.detail})")
            except VerifyError as e:
                reasons.append(f"{gid}: {e.reason} ({e.detail})")
        if chosen is None:
            e = RefusedError("no_authorizing_grant", "; ".join(reasons))
            entry = self._refuse(m, None, body, e, actor)
            return self._ack(m, "refused", e.reason, entry)
        g, s = chosen
        # Reserve the use durably BEFORE the executor runs (fail closed on a crash).
        self._reserve(msg_id, g["grant_id"])
        # Immediately before the executor, after every slow step (the use
        # accounting, the scope match, the reservation's durable write): the child
        # and its parent rechecked for the time window (expiry, not_before, the
        # parent's expiry) and for revocation and its freshness. A validity crossed
        # in between is refused by name, the refusal ledgered, and the reservation
        # released by that ledgered refusal (the stored ack replaces it): nothing
        # executed, and the record says so. Before, a grant verified at 12:00:00
        # and expired at 12:00:01 still ran the executor at 12:00:02 (round-19
        # gate, finding 7).
        try:
            # every read first — the grace period (config), the freshness sidecar, and
            # inside `_grant_valid_now` the card, the pins, the config and the feed —
            # then the two verdicts on clock readings taken after all of it: the time
            # window (`_grant_valid_now`'s last step) and the freshness (`check_fresh`,
            # pure). Before, the freshness verdict came first and could expire during
            # the reads that followed (round-19 self-gate, third run)
            grace = self.poll_s
            last = self.revocations.freshness_snapshot()
            self._grant_valid_now(g)
            self.revocations.check_fresh(last, g, s, self.now(), grace_s=grace)
        except VerifyError as e:
            crossed = VerifyError(
                e.reason,
                f"{e.detail}; crossed between verification and execution: nothing executed",
            )
            entry = self._refuse(m, g["grant_id"], body, crossed, actor)
            return self._ack(m, "refused", e.reason, entry)
        try:
            result = self.executor().apply(action, resource, params)
        except RefusedError as e:
            entry = self._refuse(m, g["grant_id"], body, e, actor)
            return self._ack(m, "refused", e.reason, entry)
        except PostCommitError as e:
            # the side effect exists (the rename landed; a later step failed): the
            # use is consumed like an applied action, and the ack says why it failed
            self.report(f"natively: executor failed AFTER committing {action}: {e.detail}")
            entry = self.ledger_append(
                ts=self.ts(),
                actor=actor,
                grant_id=g["grant_id"],
                action=action,
                params_hash=params_hash,
                outcome="failed:post_commit",
                msg_id=msg_id,
                detail=f"{resource} {e.detail}",
            )
            return self._ack(m, "failed", "post_commit", entry)
        except Exception as e:  # noqa: BLE001 — an executor failure is ledgered, never swallowed
            # nothing changed at the destination: an ordinary failure, no use consumed
            self.report(f"natively: executor failed on {action}: {e}")
            entry = self.ledger_append(
                ts=self.ts(),
                actor=actor,
                grant_id=g["grant_id"],
                action=action,
                params_hash=params_hash,
                outcome="failed",
                msg_id=msg_id,
                detail=f"{type(e).__name__}: {e}",
            )
            return self._ack(m, "failed", type(e).__name__, entry)
        entry = self.ledger_append(
            ts=self.ts(),
            actor=actor,
            grant_id=g["grant_id"],
            action=action,
            params_hash=params_hash,
            outcome="applied",
            msg_id=msg_id,
            detail=f"{resource} {result.get('note') or result.get('bytes', '')}".strip(),
        )
        return self._ack(m, "applied", "", entry)

    def _grant_valid_now(self, g: dict[str, Any]) -> None:
        """What is true of the grant at THIS moment, against this node: the full
        stateless verification (`grant.verify`: the document, the rooting, a
        delegation's chain and bounds — its parent not expired —, the binding, the
        time window: not_before and expiry) with the extension flags read from the
        config now, then revocation of the grant, its parent and the delegator's
        card (`_check_revoked`). Run when a grant is chosen and again immediately
        before the executor runs; use counting is not part of it (the reservation
        written in between is a consumed use and must not refuse its own message)."""
        grantmod.verify(
            g,
            now=self.now(),
            subject_card=self.card,
            executor_keys=self.executor_keys,
            pinned=self.pinned,
            extensions=self.extensions,
        )
        self._check_revoked(g)
        # LAST, on a clock read now: the time window again. `verify` read its `now`
        # before the card, the pins, the config and the feed were read, so a grant
        # that expired during those reads was judged at the earlier reading and ran
        # (round-19 self-gate, second run: T+3 with an expiry at T+2)
        grantmod.check_time(g, now=self.now())

    def _check_revoked(self, g: dict[str, Any]) -> None:
        root = g["parent_grant"]["issuer"]["key"] if g["parent_grant"] else g["issuer"]["key"]
        if self.revocations.grant_revoked_by(g["grant_id"], root):
            raise VerifyError("grant.revoked", f"{g['grant_id']} revoked by its principal")
        if g["parent_grant"]:
            p = g["parent_grant"]
            if self.revocations.grant_revoked_by(p["grant_id"], root):
                raise VerifyError("grant.parent_revoked", f"parent {p['grant_id']} revoked")
            # the delegator's card is checked against ITS OWN principal, which need not
            # be the root that issued the parent grant
            dc = self.card_by_hash(p["subject"]["agent"], include_revoked=True)
            if dc is None:
                raise VerifyError(
                    "grant.delegator_card.unknown",
                    f"no trusted card {p['subject']['agent']} for the delegating agent",
                )
            if dc["agent"]["key"] != p["subject"]["key"]:
                raise VerifyError(
                    "grant.delegator_card.mismatch", "parent.subject.key is not that card's key"
                )
            if self.card_revoked(dc):
                raise VerifyError(
                    "grant.delegator_revoked", "the delegating agent's card is revoked"
                )

    def _refuse(
        self,
        m: dict[str, Any],
        grant_id: str | None,
        body: dict[str, Any],
        e: RefusedError | VerifyError,
        actor: str,
    ) -> dict[str, Any]:
        self.report(
            f"natively: refused {body.get('action', '?')} from {actor}: {e.reason} — {e.detail}"
        )
        return self.ledger_append(
            ts=self.ts(),
            actor=actor,
            grant_id=grant_id,
            action=body.get("action", "?"),
            params_hash=hash_of(body.get("params", {})),
            outcome="refused",
            msg_id=m["msg_id"],
            detail=f"{e.reason}: {e.detail}",
        )

    def _reserve(self, msg_id: str, grant_id: str) -> None:
        seen = self._seen()
        seen[msg_id] = {"status": "in_progress", "grant_id": grant_id, "ts": self.ts()}
        self._write_state(self.state / "seen.json", seen)

    def _ack(
        self, m: dict[str, Any], outcome: str, detail: str, entry: dict[str, Any]
    ) -> dict[str, Any]:
        # this node's card FIRST (card.self_corrupt raises before anything is signed
        # or the seen file written): the stored ack never outruns the identity check
        card = self.card
        a = ackmod.sign(
            ackmod.build(
                from_key=self.agent.public,
                to_key=m["from"],
                ts=self.ts(),
                in_reply_to=m["msg_id"],
                outcome=outcome,
                detail=detail,
                ledger_head=self.ledger.head(),
                ledger_entry=entry_hash(entry),
            ),
            self.agent,
        )
        # the ack this node just signed is VERIFIED before it is stored: the stored
        # acks anchor the ledger's tail (`_stored_ack_anchors` authenticates every
        # one before its head is trusted), so an ack that does not verify is never
        # one of them — IntegrityError ack.self_invalid, a storage failure (nothing
        # stored, nothing sent, the mail unseen; the completion stands, and a
        # re-delivery rebuilds the ack from it once the signing is sound). A stored
        # ack that fails is therefore always one damaged on disk, never one made so
        try:
            ackmod.verify(a)
        except VerifyError as e:
            raise IntegrityError(
                "ack.self_invalid",
                f"the ack this node signed for {m['msg_id']} does not verify "
                f"({e.reason}: {e.detail}); nothing stored, nothing sent — the signing "
                f"key or the signer is faulty",
            ) from e
        seen = self._seen()
        seen[m["msg_id"]] = {"ack": a, "ts": self.ts()}
        self._write_state(self.state / "seen.json", seen)
        return bundlemod.make("ack", a, cards=[card])

    def check_reply(self, r: Any) -> dict[str, Any]:
        """The ONE validation at the boundary every outgoing reply crosses — the
        wire's send, a file export, the in-process transport: a reply that is not
        this node's reply to the message it names (`reply_problem`, against its own
        in_reply_to; the hold binds it to the request's id) is never transmitted:
        IntegrityError reply.invalid, a storage failure — nothing leaves, the copy
        it came from stays where it is. Returns the reply when sound."""
        answers = None
        if isinstance(r, dict) and isinstance(r.get("object"), dict):
            answers = r["object"].get("in_reply_to")
        problem = self.reply_problem(r, answers, "ack")
        if problem is not None:
            raise IntegrityError(
                "reply.invalid", f"not this node's reply to {answers} ({problem}); nothing sent"
            )
        return r

    def check_outgoing(self, b: Any) -> dict[str, Any]:
        """The ONE outgoing boundary for EVERY bundle this node writes to a file or
        hands to a transport (the CLI's send, ack, revoke and card exports in the
        --out and --dry-run --out forms alike, poll --file, the wire's send): a
        reply crosses `check_reply` (reply.invalid); a message, a card or a
        revocation crosses its own kind's check — the envelope, every card and grant
        it carries verified in full, the object's structure and signature, and that
        the object is THIS node's (the message from this agent, the card this
        node's own, the revocation by this node's principal). A failure is
        IntegrityError <kind>.invalid, a storage failure: nothing is written, nothing
        transmitted, nothing recorded, the copy it came from untouched. Every kind
        then crosses the wire's size bound HERE (`bundle.encode` over MAX_WIRE_BYTES
        is <kind>.invalid too): before, the encode raised ValueError at the send and
        the wire classed it as a transport failure — no storage failure counted, the
        stored entry due forever (round-15 self-gate, minor 2). Returns the bundle
        when sound."""
        kind = b.get("kind") if isinstance(b, dict) else None
        what = kind if kind in bundlemod.KINDS else "bundle"
        if kind == "ack":
            return self._check_wire_size(what, self.check_reply(b))
        try:
            bundlemod.check(b)
            for i, c in enumerate(b["cards"]):
                try:
                    cardmod.verify(c)
                except VerifyError as e:
                    raise VerifyError(f"cards[{i}].{e.reason}", e.detail) from e
            for i, g in enumerate(b["grants"]):
                try:
                    grantmod.check_document(g, extensions=grantmod.ANY_EXTENSION)
                except VerifyError as e:
                    raise VerifyError(f"grants[{i}].{e.reason}", e.detail) from e
            o = b["object"]
            if kind == "message":
                msgmod.verify(o)
                if o["from"] != self.agent.public:
                    raise VerifyError("message.from", "the message is not signed by this agent")
            elif kind == "card":
                if cardmod.verify(o) != self.card_hash:
                    raise VerifyError("card.hash", "the card is not this node's own card")
            else:
                revmod.verify(o, pinned={self.principal.public})
        except (OSError, StorageError):
            raise  # the self card, a key: a storage failure of its own, never a verdict
        except VerifyError as e:
            raise IntegrityError(
                f"{what}.invalid", f"not this node's {what} ({e.reason}: {e.detail}); nothing sent"
            ) from e
        except Exception as e:  # noqa: BLE001 — a shape a checker did not expect
            raise IntegrityError(
                f"{what}.invalid",
                f"not this node's {what} ({type(e).__name__}: {str(e)[:120]}); nothing sent",
            ) from e
        return self._check_wire_size(what, b)

    def _check_wire_size(self, what: str, b: dict[str, Any]) -> dict[str, Any]:
        """The bundle as the wire would carry it fits the wire's bound
        (`bundle.encode`, MAX_WIRE_BYTES on the JSON bytes); one that does not is
        <what>.invalid — a storage failure at the outgoing boundary, never a
        transport failure at the send."""
        try:
            bundlemod.encode(b)
        except ValueError as e:
            raise IntegrityError(
                f"{what}.invalid", f"not a {what} the wire carries ({e}); nothing sent"
            ) from e
        return b

    # ---- outbox / retry (adapter contract: retry timers sized to the poll) --------------
    def _outbox(self) -> list[dict[str, Any]]:
        """outbox.json, typed (state.outbox): the wrong shape is state.corrupt naming
        the path — a storage failure (an ack's receive refuses, the poll's outbox
        step is counted), never an empty box."""
        return statemod.read(self.state / "outbox.json", [], statemod.outbox)

    def outbox_record(
        self, b: dict[str, Any], transport_ref: str = "", *, status: str = "pending"
    ) -> dict[str, Any] | None:
        """Track a sent message for acks. Acks/cards/revocations are not retried; a
        file export is recorded as "exported" (delivered by hand, never re-sent)."""
        if b["kind"] != "message":
            return None
        if status not in ("pending", "exported"):
            raise ValueError(f"outbox status {status!r}")
        now = self.now()
        entry = {
            "msg_id": b["object"]["msg_id"],
            "to": b["object"]["to"],
            "bundle": b,
            "sent_at": fmt(now),
            "attempts": 1,
            "status": status,
            "due": fmt(plus(now, RETRY_MULTIPLIERS[0] * self.poll_s)),
            "transport_ref": transport_ref,
        }
        with self._locked():
            ob = [x for x in self._outbox() if x["msg_id"] != entry["msg_id"]]
            ob.append(entry)
            self._write_state(self.state / "outbox.json", ob)
        return entry

    def outbox_entry(self, msg_id: str) -> dict[str, Any] | None:
        for x in self._outbox():
            if x["msg_id"] == msg_id:
                return x
        return None

    def outbox_mark_acked(self, msg_id: str) -> bool:
        with self._locked():
            ob = self._outbox()
            hit = False
            for x in ob:
                if x["msg_id"] == msg_id and x["status"] in ("pending", "exported"):
                    x["status"] = "acked"
                    hit = True
            self._write_state(self.state / "outbox.json", ob)
        return hit

    def outbox_due(self) -> list[dict[str, Any]]:
        """Pending sends past their deadline, returned UNCHANGED. The adapter re-sends
        `bundle` (never recording it again) and calls outbox_advance() only once the
        transmission succeeded, so a failed send spends no attempt and moves no
        deadline; an entry whose attempts are used up goes to outbox_mark_undelivered()."""
        now = self.now()
        with self._locked():
            return [
                x for x in self._outbox() if x["status"] == "pending" and parse(x["due"]) <= now
            ]

    def outbox_advance(self, msg_id: str) -> dict[str, Any] | None:
        """A re-send of msg_id left the box: count the attempt and set the next deadline
        (2P, then 4P, 8P, 16P after each successful send)."""
        with self._locked():
            now = self.now()
            ob = self._outbox()
            hit = None
            for x in ob:
                if x["msg_id"] == msg_id and x["status"] == "pending":
                    x["attempts"] += 1
                    step = RETRY_MULTIPLIERS[min(x["attempts"], len(RETRY_MULTIPLIERS)) - 1]
                    x["due"] = fmt(plus(now, step * self.poll_s))
                    hit = x
            self._write_state(self.state / "outbox.json", ob)
        return hit

    def outbox_mark_undelivered(self, msg_id: str) -> bool:
        """The last deadline passed with no ack: terminal, ledgered. At most ONE
        audit per transition: the audit (`out.send` / `undelivered`) is keyed on the
        msg_id and the attempt count it names, and looked up — after the anchored
        check — before it is appended, so a retry after an outbox write that failed
        with the audit already on the ledger appends nothing (before, it appended a
        second line: round-14 Fable read, section E). The order stays audit first,
        outbox after: the terminal status never stands on disk without its record
        (the outbox write failing leaves the entry pending, and the retry finds the
        audit and writes the status; the other order would let a failed append leave
        a terminal status with no record and no retry to add one). A found audit is
        VISIBLE but may be an unsynced tail — its append failed after the bytes
        landed, before its barrier or its prose line — so the retry runs the ledger
        barrier (`Ledger.barrier`: both files fsynced, the mirror made whole) before
        the terminal status is written durably; the status must not outlive its
        record (round-15 self-gate, finding 4)."""
        with self._locked():
            ob = self._outbox()
            hit = False
            for x in ob:
                if x["msg_id"] == msg_id and x["status"] == "pending":
                    x["status"] = "undelivered"
                    hit = True
                    detail = f"no ack after {x['attempts']} attempts"
                    self.report(
                        f"natively: {x['msg_id']} undelivered after {x['attempts']} attempts"
                    )
                    if self._undelivered_audit(x["msg_id"], detail) is None:
                        self.ledger_append(
                            ts=self.ts(),
                            actor=self.card["agent"]["name"],
                            grant_id=None,
                            action=OUT_SEND,  # outbound, like out.ack
                            params_hash=None,
                            outcome="undelivered",
                            msg_id=x["msg_id"],
                            detail=detail,
                            direction="out",
                        )
                    else:
                        self.ledger.barrier()  # the found audit durable before the status
            self._write_state(self.state / "outbox.json", ob)
        return hit

    def _undelivered_audit(self, msg_id: str, detail: str) -> dict[str, Any] | None:
        """The undelivered audit of this transition, if it landed: `out.send` with
        outcome `undelivered` for this msg_id naming this attempt count — read
        only after the ledger's full check (`check_ledger`), like every record the
        package trusts."""
        self.check_ledger()
        for e in self.ledger.entries():
            if (
                e["action"] == OUT_SEND
                and e["outcome"] == "undelivered"
                and e.get("msg_id") == msg_id
                and e["detail"] == detail
            ):
                return e
        return None

    def outbox(self) -> list[dict[str, Any]]:
        return self._outbox()
