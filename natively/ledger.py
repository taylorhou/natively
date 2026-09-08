"""Ledger (spec 5): append-only JSONL, hash-chained via prev_hash, with a
prose mirror beside every entry. Content hashes, not content.
"""
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

    def head(self) -> str:
        # Cached chain head: appends are per-envelope on a busy node, and a
        # full-file scan per append makes an N-envelope flush O(N x ledger).
        # The (mtime_ns, size) key catches any external appender.
        try:
            st = os.stat(self.path)
            key = (st.st_mtime_ns, st.st_size)
        except OSError:
            key = None
        if self._head_cache is not None and key == self._head_stat:
            return self._head_cache
        h = "GENESIS"
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    h = json.loads(line)["prev_hash_chain"]
        self._head_cache, self._head_stat = h, key
        return h

    def append(self, actor: str, grant_id, action: str, params, outcome: str,
               prose: str) -> dict:
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
        chain = jcs.sha256(jcs.canonicalize(entry))
        entry["prev_hash_chain"] = chain
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        with open(self.mirror_path, "a") as f:
            f.write("[%s] %s: %s -> %s (grant=%s)\n" % (entry["ts"], actor, action, outcome, grant_id or "-"))
            if prose:
                f.write("    " + prose.replace("\n", "\n    ") + "\n")
        try:
            st = os.stat(self.path)
            self._head_stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            self._head_stat = None
        self._head_cache = chain
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
