"""Revocation (spec 6): tombstones signed by a pinned root, read from the
node's local feed and from the feed a grant names, consulted before every
action and failing closed when the named feed cannot be read past grace.

A tombstone names one target - a grant id, an agent card hash, an agent
key, or a principal key (signed by the recovery key when the principal
key itself is compromised) - and revokes everything under it: the grant,
the card and every grant naming it, every card and grant the principal
issued. The verifier's root set (principal.pub, one key per line: the
principal and its recovery key) decides which tombstones count.

Feeds are JSONL, one tombstone per line. The local feed is
<home>/revocations.jsonl (the CLI's `revoke` appends to it; a principal
publishes the same lines at the URL its grants name). A grant's
revocation.ledger is fetched at most every max_check_interval_s
(file:// or http(s)://); when a fetch fails - unreachable, unreadable, or
holding a line that does not verify - the last good copy serves for one
more interval (grace), and beyond that only a scope entry with offline_ok
inside its max_offline_s may still run on the stale copy. A failed fetch
is not repeated inside the interval. A tombstone once read from a feed
is kept: a shorter feed later (rollback, truncation) never un-revokes.

Several processes share one home (the daemon, the CLI's `revoke` and its
feed check at issuance, a second daemon after a restart): the persisted
observations are one file, written under a lock after folding in whatever
another process wrote first, and re-read by every object whenever the
file is not as that object last left it. An observation lives in memory
from the moment it is verified; while the disk refuses to take it the
action is refused and the next check retries the write.
"""
import fcntl
import http.client
import json
import os
import tempfile
import time
import urllib.request

from . import envelope, jcs


class RevocationError(Exception):
    """The action does not run: a target is revoked, a feed cannot be read
    within policy, or an observation cannot be persisted."""


class Revoked(RevocationError):
    """A target named by the grant is tombstoned: no scope entry of the
    grant may run."""


class FeedUnavailable(RevocationError):
    """The feed cannot be read now and the last good copy is outside the
    grace and offline policy for THIS scope entry; another entry with an
    offline allowance may still run."""


def make_tombstone(signer_seed: bytes, target: str, reason: str = "") -> dict:
    from . import crypto
    t = {"kind": "tombstone", "signer": "ed25519:" + crypto.b64e(crypto.sign_pub(signer_seed)),
         "target": target, "ts": envelope.now_iso(), "reason": reason}
    return envelope.sign_obj(t, signer_seed)


def verify_tombstone(t, roots) -> bool:
    """A well-formed tombstone signed by one of `roots` (bare b64)."""
    try:
        if not isinstance(t, dict) or t.get("kind") != "tombstone":
            return False
        if not isinstance(t.get("target"), str) or not t["target"] or not isinstance(t.get("reason", ""), str):
            return False
        envelope.parse_iso(t.get("ts"))
        signer = t.get("signer")
        envelope.key_bytes(signer)
        if signer[len("ed25519:"):] not in set(roots or ()):
            return False
        return envelope.verify_obj(t, signer)
    except Exception:
        return False


def _loads(text):
    """The strict JSON reader (jcs.loads) for a file this node reads back
    or a feed line: a duplicate key or a non-finite number is an error,
    never a value silently normalized."""
    return jcs.loads(text)


class FeedUnreadable(RevocationError):
    """A feed with a line that is not a verified tombstone. `verified`
    holds the targets of the lines before it that did verify: they are
    kept, so a feed that goes bad after a tombstone never un-reads it."""

    def __init__(self, why, verified):
        RevocationError.__init__(self, why)
        self.verified = set(verified)


def parse_feed(data, roots) -> set:
    """Targets of the verified tombstones in a JSONL feed (bytes as
    fetched, or text). Lines are split on the JSONL delimiter only (a
    Unicode separator inside a JSON string is content) and decoded one at
    a time, so a line that is not UTF-8, not JSON or not a verified
    tombstone makes the feed unreadable (fail closed, FeedUnreadable)
    rather than silently shrinking the revoked set - and the tombstones
    verified before that line ride on the error, so the reader keeps
    them."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    targets = set()
    for raw in data.split(b"\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            t = _loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise FeedUnreadable("revocation feed holds a line that is not UTF-8", targets)
        except (ValueError, RecursionError):  # not JSON, or nested past what the parser takes
            raise FeedUnreadable("revocation feed holds a line that is not JSON", targets)
        if not verify_tombstone(t, roots):
            raise FeedUnreadable("revocation feed holds a tombstone that does not verify", targets)
        targets.add(t["target"])
    return targets


def check_feed_url(url: str) -> None:
    """A feed url this node can read: file:// or http(s)://. Raises
    RevocationError for any other scheme - checked at issuance (the CLI
    refuses to write a grant every execution would refuse) and before
    every fetch."""
    if not isinstance(url, str) or not (url.startswith("file://") or url.startswith("http://")
                                        or url.startswith("https://")):
        raise RevocationError("unsupported revocation feed url")


def _fetch(url: str, timeout=10) -> bytes:
    """The feed's bytes as served; parse_feed decodes them line by line."""
    check_feed_url(url)
    if url.startswith("file://"):
        with open(url[len("file://"):], "rb") as f:
            return f.read()
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


class Revocations:
    """What this node has learned about revocation, and never forgets.

    Every tombstone target read from the local feed or from a grant's
    feed is added to <home>/revocations.seen.json (the local set and,
    per feed url, the last good copy with its fetch time) and written
    back atomically under a cross-process lock, after folding in what
    another process persisted first. A feed that later shrinks, is
    truncated or deleted - by an operator error, a rollback, or an
    attacker who reached the file - un-revokes nothing, in this process
    or after a restart, and a restart carries the last good copy of every
    feed with it, so the grace and offline policy resumes from real fetch
    times rather than from a fresh, ignorant state."""

    def __init__(self, home: str, roots, fetch=_fetch):
        self.local_path = os.path.join(home, "revocations.jsonl")
        self.seen_path = os.path.join(home, "revocations.seen.json")
        self.lock_path = self.seen_path + ".lock"
        self.roots = set(roots)
        self._fetch = fetch
        self._local = set()  # every target ever read from the local feed
        self._feeds = {}  # url -> (fetched_at, targets): the last good copy, targets accumulated
        self._tried = {}  # url -> time of the last fetch that failed (this process)
        self._seen_key = None  # the seen file as this object last read or wrote it
        self._pending = False  # observations in memory the disk has not taken yet
        self._reload()

    # ---------- the persisted observations ----------

    def _stat_key(self):
        """The seen file's (mtime, size), None when there is no file. Any
        other failure to look at it is RevocationError: a store that
        cannot be read is not an empty store."""
        try:
            st = os.stat(self.seen_path)
            return (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise RevocationError("revocation observations cannot be read: %s" % e)

    @staticmethod
    def _targets_list(v):
        if not isinstance(v, list) or not all(isinstance(t, str) and t for t in v):
            raise RevocationError("revocations.seen.json is not the shape this node writes")
        return set(v)

    def _read_seen(self):
        """The persisted observations, checked field by field: the file is
        this node's own, and a value it would never write (a fetch time
        that is not a finite number, a target that is not a string) is
        refused rather than trusted - a fetch time of Infinity would make
        a feed forever fresh and never fetched again. (set(), {}) when
        there is no file yet."""
        bad = RevocationError("revocations.seen.json is not the shape this node writes")
        try:
            with open(self.seen_path) as f:
                d = _loads(f.read())
        except FileNotFoundError:
            return set(), {}
        except OSError as e:
            raise RevocationError("revocation observations cannot be read: %s" % e)
        except (ValueError, RecursionError):
            raise bad
        if not isinstance(d, dict) or set(d) != {"local", "feeds"} or not isinstance(d["feeds"], dict):
            raise bad
        local = self._targets_list(d["local"])
        feeds = {}
        for url, rec in d["feeds"].items():
            if (not isinstance(url, str) or not isinstance(rec, dict) or set(rec) != {"fetched_at", "targets"}
                    or isinstance(rec["fetched_at"], bool) or not isinstance(rec["fetched_at"], (int, float))
                    or not (0 <= rec["fetched_at"] < 1e12)):
                raise bad
            ts = float(rec["fetched_at"])
            if ts > time.time():
                # a fetch time in the future (a clock correction, a damaged
                # file) is not a fresh copy: the targets are kept, the copy
                # is due for a fetch now, and grace is measured from never
                ts = 0.0
            feeds[url] = (ts, self._targets_list(rec["targets"]))
        return local, feeds

    def _merge(self, local, feeds):
        """Fold an observation set into memory: targets only accumulate,
        and a feed's fetch time is the latest any process recorded."""
        self._local |= local
        for url, (ts, targets) in feeds.items():
            cur = self._feeds.get(url)
            self._feeds[url] = (ts, set(targets)) if cur is None else (max(cur[0], ts), cur[1] | targets)

    def _reload(self):
        """Take in what another process persisted since this object last
        looked (the CLI's feed check at issuance, a `revoke`, another
        daemon on the home): re-read whenever the file is not as this
        object last left it. A file this node would never write fails
        closed (RevocationError)."""
        key = self._stat_key()
        if key != self._seen_key:
            local, feeds = self._read_seen()
            self._merge(local, feeds)
            self._seen_key = key

    def _write_seen(self, local, feeds):
        """Write one observation set atomically (temp file, fsync, rename)."""
        d = {"local": sorted(local),
             "feeds": {url: {"fetched_at": ts, "targets": sorted(t)} for url, (ts, t) in feeds.items()}}
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.seen_path), prefix=".revocations.seen.")
            with os.fdopen(fd, "w") as f:
                json.dump(d, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.seen_path)
        except OSError as e:
            raise RevocationError("revocation observations could not be persisted: %s" % e)

    def _persist(self):
        """Put memory on disk under the cross-process lock: fold in what
        another process wrote first, write, remember the file as written.
        A write that fails leaves every observation in memory, keeps them
        pending, and raises: the action is refused and the next check
        tries the write again before trusting anything."""
        try:
            with open(self.lock_path, "w") as lk:
                fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
                try:
                    self._reload()
                    self._write_seen(self._local, self._feeds)
                    self._seen_key = self._stat_key()
                    self._pending = False
                finally:
                    fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
        except OSError as e:
            self._pending = True
            raise RevocationError("revocation observations could not be persisted: %s" % e)
        except RevocationError:
            self._pending = True
            raise

    def _settle(self):
        """Before any decision: a pending observation goes to disk first
        (or the decision is refused), and other processes' writes are
        taken in."""
        if self._pending:
            self._persist()
        else:
            self._reload()

    def _partial_targets(self, url, data: bytes):
        """A body cut short by the transport: its complete lines are parsed
        like a feed and what verifies is kept (never a fetch time - the copy
        is not a good one)."""
        complete = data[:data.rfind(b"\n") + 1] if isinstance(data, (bytes, bytearray)) else b""
        try:
            verified = parse_feed(complete, self.roots)
        except FeedUnreadable as e:
            verified = e.verified
        self._keep_targets(url, verified)

    def _keep_targets(self, url, targets):
        """Tombstones verified from a feed that could not be read to the
        end: kept under the feed, without advancing its fetch time (the
        copy was not good), and persisted before anything decides."""
        if not targets:
            return
        cur = self._feeds.get(url)
        self._feeds[url] = (0.0, set(targets)) if cur is None else (cur[0], cur[1] | set(targets))
        self._pending = True
        self._persist()

    def _adopt_feed(self, url, ts, targets):
        """A feed copy read now: adopted in memory first (targets
        accumulate, the fetch time is the latest - except that a recorded
        time ahead of the clock, from a clock rollback or a damaged file,
        yields to the time of this real fetch), then persisted."""
        cur = self._feeds.get(url)
        if cur is None:
            self._feeds[url] = (ts, set(targets))
        else:
            self._feeds[url] = (ts if cur[0] > time.time() else max(cur[0], ts), cur[1] | targets)
        self._tried.pop(url, None)
        self._pending = True
        self._persist()

    # ---------- the local feed ----------

    def local_targets(self) -> set:
        """Targets from the local feed, accumulated: a tombstone once read
        stays revoked when the feed is later truncated or removed. Only a
        feed that is absent is empty; one that is present but cannot be
        opened or read (a permission error, a symlink loop, an I/O error)
        fails closed, as does one holding a line that does not verify
        (parse_feed raises)."""
        self._settle()
        try:
            with open(self.local_path, "rb") as f:
                text = f.read()
        except FileNotFoundError:
            text = None
        except OSError as e:
            raise RevocationError("local revocation feed cannot be read: %s" % e)
        if text is not None:
            try:
                fresh = parse_feed(text, self.roots)
            except FeedUnreadable as e:
                if not e.verified <= self._local:
                    self._local |= e.verified
                    self._pending = True
                    self._persist()
                raise
            if not fresh <= self._local:
                self._local |= fresh
                self._pending = True
                self._persist()
        return set(self._local)

    def known_targets(self) -> set:
        """Every target this node has ever verified, from the local feed
        and from every feed it has read: a tombstone learned through one
        grant's feed revokes its target under every grant, whichever feed
        that grant names."""
        t = self.local_targets()
        for _, targets in self._feeds.values():
            t |= targets
        return t

    # ---------- the feeds grants name ----------

    def observe(self, url: str, now=None) -> set:
        """Fetch a feed now, verify it, and persist what it holds (used at
        issuance): a feed that cannot be read now refuses the grant, and
        what it held is kept for every later check. Raises RevocationError."""
        self._settle()
        check_feed_url(url)
        try:
            targets = parse_feed(self._fetch(url), self.roots)
        except FeedUnreadable as e:
            self._keep_targets(url, e.verified)
            raise
        except http.client.IncompleteRead as e:
            self._partial_targets(url, e.partial)
            raise RevocationError("revocation feed cannot be read: %s" % e)
        except RevocationError:
            raise
        except Exception as e:
            raise RevocationError("revocation feed cannot be read: %s" % e)
        self._adopt_feed(url, time.time() if now is None else now, targets)
        return set(self._feeds[url][1])

    def _stale(self, cached, interval_s: int, scope_entry: dict, now: float, why: str):
        """The policy for a feed that cannot be read now: the last good copy
        inside one further interval (grace); past that only when the scope
        entry allows running offline and the copy is inside its
        max_offline_s; otherwise FeedUnavailable."""
        if cached is None:
            raise FeedUnavailable("revocation feed unavailable and never read: %s" % why)
        age = now - cached[0]
        if age < 0:
            raise FeedUnavailable("revocation feed unavailable and its last copy is dated in the future: %s" % why)
        if age <= 2 * interval_s:
            return set(cached[1])
        if scope_entry.get("offline_ok") and age <= scope_entry.get("max_offline_s", 0):
            return set(cached[1])
        raise FeedUnavailable("revocation feed unavailable past grace (%ds old): %s" % (age, why))

    def feed_targets(self, url: str, interval_s: int, scope_entry: dict, now=None):
        """Targets from the feed at `url`, no older than interval_s when
        the feed can be read. When it cannot (unreachable, unreadable, or
        a line that does not verify): the last good copy under the grace
        and offline policy of `_stale`, judged by the clock AFTER the
        fetch returned - a fetch that runs to its timeout may cross the
        deadline, and the copy's age is what it is at the decision, not
        what it was when the fetch began. A failed fetch is not retried
        inside interval_s, so an outage costs one timeout per interval,
        not one per action. Targets only ever accumulate: a tombstone
        once read is kept when a later copy of the feed lacks it."""
        self._settle()
        clock = time.time if now is None else (lambda: now)
        check_feed_url(url)  # a url this node can never read is refused outright, grace or not
        cached = self._feeds.get(url)
        t = clock()
        if cached and 0 <= t - cached[0] <= interval_s:
            return set(cached[1])
        tried = self._tried.get(url)
        if tried is not None and 0 <= t - tried <= interval_s:
            return self._stale(cached, interval_s, scope_entry, t, "last fetch failed %ds ago" % (t - tried))
        try:
            targets = parse_feed(self._fetch(url), self.roots)
        except Exception as e:
            self._tried[url] = clock()
            if isinstance(e, FeedUnreadable):
                self._keep_targets(url, e.verified)  # what did verify is kept; the copy is not a good one
            elif isinstance(e, http.client.IncompleteRead):
                self._partial_targets(url, e.partial)  # the complete lines of a body cut short are kept too
            # the clock is read after the fetch AND after the persistence
            # above (a lock or a slow disk counts against grace too), so
            # the copy's age is what it is at the decision
            return self._stale(self._feeds.get(url), interval_s, scope_entry, clock(), str(e))
        fetched_at = clock()
        self._adopt_feed(url, fetched_at, targets)
        # persisting the copy may have waited on a lock or a slow disk: the
        # copy is judged by its age now, under the same policy as any other
        if clock() - fetched_at > interval_s:
            return self._stale(self._feeds.get(url), interval_s, scope_entry, clock(),
                               "persisting the copy outlived the check interval")
        return set(self._feeds[url][1])

    def check(self, grant: dict, card: dict, scope_entry: dict, parent: dict = None, now=None,
              parent_card: dict = None) -> None:
        """Raise Revoked when the grant, its parent, the parent's subject
        (card or key) and the principal that issued that card, the subject
        card, the subject key, or the issuing principal is tombstoned in
        any feed this node has ever read or in the feed the grant names
        (fetched fresh; and the parent's feed when it differs);
        FeedUnavailable when a feed cannot be read within the policy for
        `scope_entry`; RevocationError when an observation cannot be
        persisted. A tombstone already known is Revoked before any fetch,
        and the known set is rebuilt after the fetches: what they brought,
        and what another process persisted meanwhile (folded in under
        the lock as this one wrote)."""
        subjects = [grant["grant_id"], grant["issuer"]["key"], envelope.obj_hash(card), card["agent_key"],
                    card["principal_key_ref"]]
        if grant.get("parent_grant"):
            subjects.append(grant["parent_grant"])
        if parent is not None:
            # a tombstone on the delegating agent's card or key, on the
            # principal that issued the parent, or on the principal that
            # issued the delegating agent's card ends every delegation under it
            subjects += [parent["issuer"]["key"], parent["subject"]["agent"], parent["subject"]["key"]]
            if isinstance(parent_card, dict) and isinstance(parent_card.get("principal_key_ref"), str):
                subjects.append(parent_card["principal_key_ref"])
        self._hit(subjects, self.known_targets())
        feeds = [grant["revocation"]]
        if parent is not None and parent["revocation"] != grant["revocation"]:
            feeds.append(parent["revocation"])
        for rev in feeds:
            if rev["ledger"]:
                self.feed_targets(rev["ledger"], rev["max_check_interval_s"], scope_entry, now=now)
        self._hit(subjects, self.known_targets())

    @staticmethod
    def _hit(subjects, targets):
        for t in subjects:
            if t in targets:
                raise Revoked("revoked: %s" % t)
