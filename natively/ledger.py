"""Ledger (spec 5): append-only JSONL, hash-chained via prev_hash, with a
prose mirror beside every entry. Content hashes, not content.
"""
import fcntl
import json
import os
from . import jcs


class Ledger:
    def __init__(self, path: str):
        self.path = path
        self.mirror_path = path + ".prose"
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            open(path, "w").close()
        self._head_cache = None
        self._head_stat = None
        self._by_grant = None  # grant_id -> its rows, kept with the head cache

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
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                h = e["prev_hash_chain"]
                if isinstance(e.get("grant_id"), str):  # a row naming no grant, or a malformed one, is chained but not indexed
                    idx.setdefault(e["grant_id"], []).append(e)
        self._head_cache, self._head_stat, self._by_grant = h, key, idx

    def head(self) -> str:
        self._sync()
        return self._head_cache

    def rows_for_grant(self, grant_id) -> list:
        """Every entry ledgered under `grant_id`, in chain order."""
        self._sync()
        return list(self._by_grant.get(grant_id, ()))

    def append(self, actor: str, grant_id, action: str, params, outcome: str,
               prose: str, scope=None, issuer_model=None) -> dict:
        """One entry. `scope` (an integer, the index of the grant scope
        entry an execution ran under) is recorded when given so per-scope
        budgets can be counted back from the chain; `issuer_model`
        (receiver-principal / sender-principal, spec 3) likewise on
        grant-scoped rows. `grant_id` is a string
        or None, checked before anything is written: a row that cannot be
        indexed must never reach the file. Appends are serialized across
        the processes writing one ledger (an flock beside the file): the
        head is read, the row written and the file's new stat taken under
        the lock, so two writers never chain onto the same head and the
        index never adopts a stat that covers a row it did not see."""
        if grant_id is not None and not isinstance(grant_id, str):
            raise TypeError("grant_id must be a string or None")
        if scope is not None and (isinstance(scope, bool) or not isinstance(scope, int)):
            raise TypeError("scope must be an integer or None")
        with open(self.path + ".lock", "w") as lk:
            fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
            try:
                prev = self.head()
                entry = {
                    "ts": jcs and __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
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
                chain = jcs.sha256(jcs.canonicalize(entry))
                entry["prev_hash_chain"] = chain
                with open(self.path, "a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                with open(self.mirror_path, "a") as f:
                    f.write("[%s] %s: %s -> %s (grant=%s)\n" % (entry["ts"], actor, action, outcome, grant_id or "-"))
                    if prose:
                        f.write("    " + prose.replace("\n", "\n    ") + "\n")
                self._head_stat = self._stat_key()
                self._head_cache = chain
                if grant_id is not None:
                    self._by_grant.setdefault(grant_id, []).append(entry)
            finally:
                fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
        return entry

    def entries(self):
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> bool:
        prev = "GENESIS"
        for e in self.entries():
            if e["prev_hash"] != prev:
                return False
            body = {k: v for k, v in e.items() if k != "prev_hash_chain"}
            if jcs.sha256(jcs.canonicalize(body)) != e["prev_hash_chain"]:
                return False
            prev = e["prev_hash_chain"]
        return True
