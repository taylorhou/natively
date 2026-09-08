"""Ledger (spec 5): append-only JSONL, hash-chained via prev_hash, with a
prose mirror beside every entry. Content hashes, not content.
"""
import fcntl
import json
import os
import time
from . import jcs


class LedgerCorrupt(Exception):
    """A row that is not the last one does not parse, or the chain does not
    verify: the ledger is not something to build on. Only a torn LAST line
    (a crash mid-append) is recoverable, and is recovered."""


class Ledger:
    def __init__(self, path: str):
        self.path = path
        self.mirror_path = path + ".prose"
        self.torn_path = path + ".torn"
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            open(path, "w").close()
            self._fsync_dir(os.path.dirname(os.path.abspath(path)))  # the new file is linked durably: a first append never vanishes with it
        self._head_cache = None
        self._head_stat = None
        self._by_grant = None  # grant_id -> its rows, kept with the head cache
        with self._locked(self):
            self._recover_tail()

    class _locked:
        """The cross-process append lock (an flock beside the file)."""

        def __init__(self, ledger):
            self.ledger = ledger

        def __enter__(self):
            self.f = open(self.ledger.path + ".lock", "w")
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
            return self

        def __exit__(self, *a):
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()

    TAIL_CHUNK = 65536

    @staticmethod
    def _fsync_dir(d):
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def verify_at_start(self) -> bool:
        """Recover the tail and verify the chain in one step under the
        append lock: another writer's torn tail found between the
        constructor and start() is recovered before it is judged, and no
        unfinished concurrent append is inspected."""
        with self._locked(self):
            self._recover_tail()
            return self.verify_chain()

    def _unterminated_tail(self):
        """The bytes after the last newline (empty when the file ends with
        one), read backwards in bounded chunks: the whole ledger is never
        read to look at its tail."""
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            buf = b""
            pos = size
            while pos > 0:
                step = min(self.TAIL_CHUNK, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                nl = buf.rfind(b"\n")
                if nl >= 0:
                    return buf[nl + 1:]
            return buf

    @staticmethod
    def _is_row(fragment):
        """True when `fragment` is one complete, self-consistent row: an
        object whose entry hash is the hash of the rest of it."""
        try:
            e = json.loads(fragment)
            if not isinstance(e, dict) or not isinstance(e.get("prev_hash_chain"), str):
                return False
            body = {k: v for k, v in e.items() if k != "prev_hash_chain"}
            return jcs.sha256(jcs.canonicalize(body)) == e["prev_hash_chain"]
        except (ValueError, TypeError, RecursionError):
            return False

    def _recover_tail(self):
        """Under the lock: the one recoverable damage is a crash
        mid-append - bytes after the last newline. A tail that is a whole,
        self-consistent row lost only its delimiter: the newline is put
        back. Anything else after the last newline is moved to
        <ledger>.torn with the time it was found and cut off, so the chain
        resumes from the last delimited row. A complete line that does not
        parse is never touched here: it is corruption, and head() and
        verify_chain say so - recovery cannot make it disappear."""
        fragment = self._unterminated_tail()
        if not fragment:
            return
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if self._is_row(fragment):
            with open(self.path, "ab") as f:
                f.write(b"\n")
                f.flush()
                os.fsync(f.fileno())
            with open(self.mirror_path, "a") as m:
                m.write("[%s] node: ledger.torn-tail -> delimiter restored (whole row)\n" % stamp)
            return
        with open(self.torn_path, "ab") as t:
            t.write(("# torn tail found %s (%d bytes)\n" % (stamp, len(fragment))).encode())
            t.write(fragment + b"\n")
            t.flush()
            os.fsync(t.fileno())
        self._fsync_dir(os.path.dirname(os.path.abspath(self.torn_path)))  # the archive exists durably before the ledger loses the bytes
        with open(self.path, "r+b") as f:
            f.seek(0, os.SEEK_END)
            f.truncate(f.tell() - len(fragment))
            f.flush()
            os.fsync(f.fileno())
        with open(self.mirror_path, "a") as m:
            m.write("[%s] node: ledger.torn-tail -> recovered (%d bytes moved to %s)\n"
                    % (stamp, len(fragment), os.path.basename(self.torn_path)))
        self._head_cache = None

    def _stat_key(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _sync(self):
        """Read the file once when it is not as this Ledger last left it (a
        first look, another writer, a rewrite): the chain head and the
        per-grant row index come out of the same pass. Appends by this
        object keep both current without re-reading, so a node's budget
        checks cost the grant's own rows, never the lifetime ledger."""
        key = self._stat_key()
        if self._head_cache is not None and key == self._head_stat:
            return
        h, idx = "GENESIS", {}
        with open(self.path, "rb") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    line = raw.decode("utf-8")  # bytes that are not UTF-8 are corruption like any other
                    e = json.loads(line)
                    h = e["prev_hash_chain"]
                    if not isinstance(h, str):
                        raise TypeError("entry hash is not a string")
                except (ValueError, KeyError, TypeError, RecursionError) as ex:
                    raise LedgerCorrupt("ledger row does not parse: %s (%s)" % (raw[:60], ex))
                gid, parent = e.get("grant_id"), e.get("parent")
                for k in ((gid,) if gid == parent else (gid, parent)):
                    if isinstance(k, str):  # a row naming no grant, or a malformed one, is chained but not indexed
                        idx.setdefault(k, []).append(e)
        self._head_cache, self._head_stat, self._by_grant = h, key, idx

    def head(self) -> str:
        self._sync()
        return self._head_cache

    def rows_for_grant(self, grant_id) -> list:
        """Every entry ledgered under `grant_id` - as the grant it ran under
        or as the parent whose budget it spent - in chain order."""
        self._sync()
        return list(self._by_grant.get(grant_id, ()))

    def append(self, actor: str, grant_id, action: str, params, outcome: str,
               prose: str, scope=None, issuer_model=None, parent=None, parent_scope=None) -> dict:
        """One entry. `scope` (an integer, the index of the grant scope
        entry an execution ran under) is recorded when given so per-scope
        budgets can be counted back from the chain; `parent` and
        `parent_scope` name the parent grant and its scope entry when the
        execution ran under a delegation, so the parent's budget is
        counted back from the chain too; `issuer_model` (receiver-principal
        / sender-principal, spec 3) likewise on grant-scoped rows.
        `grant_id` and `parent` are strings or None, checked before
        anything is written: a row that cannot be indexed must never
        reach the file. Appends are serialized across the processes
        writing one ledger (an flock beside the file): the head is read,
        the row written and the file's new stat taken under the lock, so
        two writers never chain onto the same head and the index never
        adopts a stat that covers a row it did not see."""
        for v, what in ((grant_id, "grant_id"), (parent, "parent")):
            if v is not None and not isinstance(v, str):
                raise TypeError("%s must be a string or None" % what)
        for v, what in ((scope, "scope"), (parent_scope, "parent_scope")):
            if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
                raise TypeError("%s must be an integer or None" % what)
        with self._locked(self):
            if True:
                self._recover_tail()  # another writer may have died mid-line since this object last looked
                prev = self.head()
                entry = {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "actor": actor,
                    "grant_id": grant_id,
                    "action": action,
                    "params_hash": jcs.sha256(jcs.canonicalize(params or {})),
                    "outcome": outcome,
                    "prev_hash": prev,
                }
                if scope is not None:
                    entry["scope"] = scope
                if issuer_model is not None:
                    # SPEC 3 issuer models: receiver-principal vs sender-principal,
                    # recorded on grant-scoped rows so ledger comparisons can tell
                    # the models apart after the fact.
                    entry["issuer_model"] = issuer_model
                if parent is not None:
                    entry["parent"] = parent
                if parent_scope is not None:
                    entry["parent_scope"] = parent_scope
                chain = jcs.sha256(jcs.canonicalize(entry))
                entry["prev_hash_chain"] = chain
                # the row is on disk (flushed and fsynced) before the mirror
                # line that describes it is written: a crash between the two
                # leaves a chain that verifies and a mirror one line short,
                # never a mirror line for a row that does not exist
                with open(self.path, "a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                with open(self.mirror_path, "a") as f:
                    # each prose line carries the first 12 hex of its row's
                    # entry hash, so prose and rows pair up after a torn write
                    f.write("%s [%s] %s: %s -> %s (grant=%s)\n" % (chain[:12], entry["ts"], actor, action, outcome, grant_id or "-"))
                    if prose:
                        f.write("    " + prose.replace("\n", "\n    ") + "\n")
                self._head_stat = self._stat_key()
                self._head_cache = chain
                for gid in {grant_id, parent} - {None}:
                    self._by_grant.setdefault(gid, []).append(entry)
        return entry

    def entries(self):
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> bool:
        """Every row parses, hashes to its own entry hash and chains onto the
        previous one. False (never an exception) otherwise."""
        prev = "GENESIS"
        try:
            for e in self.entries():
                if not isinstance(e, dict) or e.get("prev_hash") != prev:
                    return False
                body = {k: v for k, v in e.items() if k != "prev_hash_chain"}
                if jcs.sha256(jcs.canonicalize(body)) != e.get("prev_hash_chain"):
                    return False
                prev = e["prev_hash_chain"]
        except (ValueError, TypeError, KeyError, RecursionError, OSError):
            return False
        return True
