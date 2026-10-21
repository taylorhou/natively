"""Ledger (spec 5): append-only JSONL, hash-chained via prev_hash, with a
prose mirror beside every entry. Content hashes, not content.

Segments (spec 5.1): at a planned restart the live file can be sealed -
renamed to ledger.NNNNNN.jsonl (0400) beside a manifest - and a fresh live
file starts with a ledger.checkpoint row that chains onto the sealed head.
No row is ever removed: a seal is a rename plus a checkpoint row.
"""
import concurrent.futures
import fcntl
import hashlib
import json
import multiprocessing
import os
import re
import tempfile
import time
from . import jcs

CHECKPOINT = "ledger.checkpoint"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_READ = 1 << 20
PARALLEL_MIN = 64 << 20  # a segment smaller than this is verified in-process


def _row_hash(e):
    body = {k: v for k, v in e.items() if k != "prev_hash_chain"}
    return jcs.sha256(jcs.canonicalize(body))


def _grant_indexed(e):
    """A row the per-grant index files: one naming a grant it ran under or
    a parent whose budget it spent."""
    return isinstance(e.get("grant_id"), str) or isinstance(e.get("parent"), str)


def _file_sha256(path):
    """(sha256 hex, bytes) of a file, streamed: memory is one read buffer."""
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(_READ)
            if not b:
                return h.hexdigest(), n
            h.update(b)
            n += len(b)


def _scan_range(path, start, end, at_origin, digest=False):
    """Verify the rows in bytes [start, end) of a segment (both on line
    starts): each parses, hashes to its own entry hash and chains onto the
    row before it. The first row's prev_hash is returned for the caller to
    stitch onto the previous range. A ledger.checkpoint row may only be a
    segment's first row. Module-level so a spawned worker can run it."""
    r = {"rows": 0, "first_prev": None, "last": None, "first_ts": None, "last_ts": None,
         "grant_lines": [], "error": None, "error_row": 0, "sha256": None}
    h = hashlib.sha256() if digest else None
    prev = None
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw = f.readline(end - pos)
            if not raw:
                break
            pos += len(raw)
            if h:
                h.update(raw)
            s = raw.strip()
            if not s:
                continue
            r["rows"] += 1
            try:
                e = json.loads(s.decode("utf-8"))
                if not isinstance(e, dict):
                    raise ValueError("row is not an object")
                if r["rows"] == 1:
                    r["first_prev"] = e.get("prev_hash")
                elif e.get("prev_hash") != prev:
                    raise ValueError("prev_hash does not chain onto the row before")
                if _row_hash(e) != e.get("prev_hash_chain"):
                    raise ValueError("row does not hash to its entry hash")
                if e.get("action") == CHECKPOINT and not (at_origin and r["rows"] == 1):
                    raise ValueError("a checkpoint row that is not its segment's first row")
            except (ValueError, TypeError, KeyError, RecursionError) as ex:
                r["error"], r["error_row"] = str(ex), r["rows"]
                return r
            prev = e["prev_hash_chain"]
            if r["first_ts"] is None:
                r["first_ts"] = e.get("ts")
            r["last_ts"] = e.get("ts")
            if _grant_indexed(e):
                r["grant_lines"].append(s + b"\n")
    r["last"] = prev
    if h:
        r["sha256"] = h.hexdigest()
    return r


def _cuts(path, size, parts):
    """Byte ranges of `path` split at line starts, about `parts` of them."""
    cuts = [0]
    with open(path, "rb") as f:
        for i in range(1, parts):
            target = size * i // parts
            if target <= cuts[-1]:
                continue
            f.seek(target - 1)
            f.readline()
            p = f.tell()
            if p >= size:
                break
            if p > cuts[-1]:
                cuts.append(p)
    cuts.append(size)
    return list(zip(cuts, cuts[1:]))


def _scan_segment(path, origin, jobs=1, end=None, parallel_min=None):
    """Verify every row of one segment from `origin` (the hash its first row
    must chain onto) and take its sha256 in the same read. With jobs > 1 and
    a large file the rows are verified by spawned workers over line-aligned
    ranges while this process streams the sha256; the ranges are stitched
    hash to hash, so the result is the sequential one."""
    size = os.path.getsize(path) if end is None else end
    if jobs <= 1 or size < (PARALLEL_MIN if parallel_min is None else parallel_min):
        parts = [_scan_range(path, 0, size, True, digest=True)]
        sha = parts[0]["sha256"]
    else:
        ranges = _cuts(path, size, jobs * 4)
        ctx = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs, mp_context=ctx) as pool:
            futs = [pool.submit(_scan_range, path, a, b, a == 0) for a, b in ranges]
            h, left = hashlib.sha256(), size
            with open(path, "rb") as f:
                while left > 0:
                    b = f.read(min(_READ, left))
                    if not b:
                        break
                    h.update(b)
                    left -= len(b)
            sha = h.hexdigest()
            parts = [fu.result() for fu in futs]
    out = {"rows": 0, "bytes": size, "sha256": sha, "first_prev": origin, "head": origin,
           "first_ts": None, "last_ts": None, "grant_lines": [], "error": None}
    for p in parts:
        if p["error"]:
            out["error"] = "row %d: %s" % (out["rows"] + p["error_row"], p["error"])
            return out
        if not p["rows"]:
            continue
        if p["first_prev"] != out["head"]:
            out["error"] = "row %d: prev_hash does not chain onto %s" % (out["rows"] + 1, out["head"][:12])
            return out
        out["head"] = p["last"]
        out["rows"] += p["rows"]
        out["first_ts"] = out["first_ts"] or p["first_ts"]
        out["last_ts"] = p["last_ts"]
        out["grant_lines"] += p["grant_lines"]
    return out


def _open600(path, mode):
    """open(path, mode) for a file the node may be the one to create: a new
    file is owner-only whatever the process umask (96's state, prose mirror
    and locks came back 0644 under the default 022 on 2026-10-21; the home
    holds keys). A file that already exists keeps its mode."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if "a" in mode else os.O_TRUNC)
    return os.fdopen(os.open(path, flags, 0o600), mode)


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
            _open600(path, "w").close()
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
            self.f = _open600(self.ledger.path + ".lock", "w")
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

    def _unterminated_tail(self, path=None):
        """The bytes after the last newline (empty when the file ends with
        one), read backwards in bounded chunks: the whole ledger is never
        read to look at its tail."""
        with open(path or self.path, "rb") as f:
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
            with _open600(self.mirror_path, "a") as m:
                m.write("[%s] node: ledger.torn-tail -> delimiter restored (whole row)\n" % stamp)
            return
        with _open600(self.torn_path, "ab") as t:
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
        with _open600(self.mirror_path, "a") as m:
            m.write("[%s] node: ledger.torn-tail -> recovered (%d bytes moved to %s)\n"
                    % (stamp, len(fragment), os.path.basename(self.torn_path)))
        self._head_cache = None

    def _stat_key(self):
        try:
            st = os.stat(self.path)
            return (st.st_ino, st.st_mtime_ns, st.st_size)  # the inode: a seal replaces the file
        except OSError:
            return None

    def _sync(self):
        """Read the file once when it is not as this Ledger last left it (a
        first look, another writer, a rewrite): the chain head and the
        per-grant row index come out of the same pass. Appends by this
        object keep both current without re-reading, so a node's budget
        checks cost the grant's own rows, never the lifetime ledger. Rows
        sealed into earlier segments still spend budgets: the index starts
        from each segment's grant sidecar, so a seal never frees a use."""
        key = self._stat_key()
        if self._head_cache is not None and key == self._head_stat:
            return
        h, idx = "GENESIS", {}
        for seg in self._segment_chain():
            with open(seg["grants"], "rb") as f:
                for raw in f:
                    if raw.strip():
                        self._index(idx, json.loads(raw))
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
                self._index(idx, e)
        self._head_cache, self._head_stat, self._by_grant = h, key, idx

    @staticmethod
    def _index(idx, e):
        gid, parent = e.get("grant_id"), e.get("parent")
        for k in ((gid,) if gid == parent else (gid, parent)):
            if isinstance(k, str):  # a row naming no grant, or a malformed one, is chained but not indexed
                idx.setdefault(k, []).append(e)

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
        if action == CHECKPOINT:
            raise ValueError("%s rows are written only by a seal" % CHECKPOINT)
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
                with _open600(self.mirror_path, "a") as f:
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

    def repair_forks(self, apply=False):
        """Stream-repair self-consistent rows that forked under legacy writers.

        File order is the only durable ordering left after the old append race:
        every original row and field is retained, while `prev_hash` and the
        derived `prev_hash_chain` are recomputed from the first mismatch
        onward. Rows whose own hash is invalid are refused as corruption.
        Dry-run is the default. Apply archives the exact original beside the
        ledger and publishes the repaired file with an evidence manifest.
        """
        directory = os.path.dirname(os.path.abspath(self.path))
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        fd, candidate = tempfile.mkstemp(dir=directory, prefix=".ledger-repair-", suffix=".jsonl")
        original_sha, repaired_sha = hashlib.sha256(), hashlib.sha256()
        expected = new_prev = self._origin()  # a sealed ledger's live rows chain onto its checkpoint head
        rows = changed = first = 0
        first_evidence = None
        try:
            with os.fdopen(fd, "wb") as out, open(self.path, "rb") as source:
                for raw in source:
                    original_sha.update(raw)
                    stripped = raw.strip()
                    if not stripped:
                        continue
                    rows += 1
                    try:
                        row = json.loads(stripped.decode("utf-8"))
                        if not isinstance(row, dict):
                            raise ValueError("row is not an object")
                        old_hash = row.get("prev_hash_chain")
                        body = {k: v for k, v in row.items() if k != "prev_hash_chain"}
                        calculated = jcs.sha256(jcs.canonicalize(body))
                    except (UnicodeError, ValueError, TypeError, RecursionError) as e:
                        raise LedgerCorrupt("ledger row %d does not parse: %s" % (rows, e))
                    if not isinstance(old_hash, str) or calculated != old_hash:
                        raise LedgerCorrupt("ledger row %d is not internally self-consistent" % rows)
                    mismatch = row.get("prev_hash") != expected
                    if mismatch and not first:
                        first = rows
                        first_evidence = {"row": rows, "expected_prev_hash": expected,
                            "observed_prev_hash": row.get("prev_hash"),
                            "observed_row_hash": old_hash}
                    if first:
                        row["prev_hash"] = new_prev
                        body = {k: v for k, v in row.items() if k != "prev_hash_chain"}
                        row["prev_hash_chain"] = jcs.sha256(jcs.canonicalize(body))
                        changed += int(row["prev_hash_chain"] != old_hash or mismatch)
                    encoded = (json.dumps(row, separators=(",", ":")) + "\n").encode()
                    out.write(encoded); repaired_sha.update(encoded)
                    expected = old_hash
                    new_prev = row["prev_hash_chain"]
                out.flush(); os.fsync(out.fileno())
            evidence = {"schema": "natively.ledger-repair.v1", "rows": rows,
                "first_mismatch": first_evidence, "rows_rehashed": (rows - first + 1) if first else 0,
                "rows_with_changed_hash": changed, "original_head": expected,
                "repaired_head": new_prev, "original_sha256": original_sha.hexdigest(),
                "repaired_sha256": repaired_sha.hexdigest(), "content_policy": "all rows retained in file order"}
            if not first:
                os.unlink(candidate)
                evidence["applied"] = False
                evidence["status"] = "chain already valid"
                return evidence
            if not apply:
                os.unlink(candidate)
                evidence["applied"] = False
                evidence["status"] = "repair available; rerun with --apply"
                return evidence
            archive = self.path + ".pre-repair." + stamp
            manifest = self.path + ".repair." + stamp + ".json"
            if os.path.exists(archive) or os.path.exists(manifest):
                raise LedgerCorrupt("repair archive already exists for %s" % stamp)
            # Original is renamed, never rewritten. Candidate and manifest are
            # durable before the directory publishes their final names.
            os.replace(self.path, archive)
            os.replace(candidate, self.path)
            evidence.update({"applied": True, "status": "repaired",
                             "archive": archive, "manifest": manifest})
            with open(manifest + ".tmp", "w") as f:
                json.dump(evidence, f, indent=2, sort_keys=True); f.write("\n")
                f.flush(); os.fsync(f.fileno())
            os.replace(manifest + ".tmp", manifest)
            self._fsync_dir(directory)
            self._head_cache = self._head_stat = self._by_grant = None
            if not self.verify_chain():
                raise LedgerCorrupt("repaired ledger failed verification; original is at %s" % archive)
            return evidence
        except Exception:
            try:
                if os.path.exists(candidate): os.unlink(candidate)
            finally:
                raise

    # ---------- segments (spec 5.1) ----------
    def _stem(self):
        base = os.path.basename(self.path)
        return base[:-len(".jsonl")] if base.endswith(".jsonl") else base

    def _seg_paths(self, n):
        """The files of sealed segment `n`, beside the live one."""
        d = os.path.dirname(os.path.abspath(self.path))
        seg = os.path.join(d, "%s.%06d.jsonl" % (self._stem(), n))
        return {"segment": seg, "prose": seg + ".prose",
                "manifest": os.path.join(d, "%s.%06d.manifest.json" % (self._stem(), n)),
                "grants": os.path.join(d, "%s.%06d.grants.jsonl" % (self._stem(), n))}

    @staticmethod
    def _first_row(path):
        """The first row of a file, parsed, or None (empty, or not a row)."""
        with open(path, "rb") as f:
            while True:
                raw = f.readline(_READ)
                if not raw:
                    return None
                if raw.strip():
                    break
        try:
            e = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            return None
        return e if isinstance(e, dict) else None

    def _checkpoint_params(self, e):
        """The params of a well-formed checkpoint row and its segment number.
        Raises LedgerCorrupt otherwise: a malformed checkpoint is not a
        start the chain can be trusted from."""
        p = e.get("params")
        ok = (isinstance(p, dict) and e.get("outcome") == "sealed" and e.get("grant_id") is None
              and set(p) == {"segment", "rows", "sha256", "head", "grant_rows", "grants_sha256"}
              and all(isinstance(p[k], int) and not isinstance(p[k], bool) and p[k] >= 0 for k in ("rows", "grant_rows"))
              and all(isinstance(p[k], str) and _HEX64.match(p[k]) for k in ("sha256", "grants_sha256"))
              and isinstance(p["head"], str) and isinstance(p["segment"], str))
        m = re.match(r"^%s\.(\d{6})\.jsonl$" % re.escape(self._stem()), p["segment"]) if ok else None
        if not m or int(m.group(1)) < 1:
            raise LedgerCorrupt("checkpoint row is malformed")
        if e.get("params_hash") != jcs.sha256(jcs.canonicalize(p)):
            raise LedgerCorrupt("checkpoint params do not hash to its params_hash")
        if e.get("prev_hash") != p["head"]:
            raise LedgerCorrupt("checkpoint does not chain onto the head it names")
        if _row_hash(e) != e.get("prev_hash_chain"):
            raise LedgerCorrupt("checkpoint row does not hash to its entry hash")
        return p, int(m.group(1))

    def _segment_chain(self):
        """The sealed segments behind the live file, oldest first, found by
        walking checkpoint rows back from the live file's first row. Each
        carries its files, its manifest and the params of the checkpoint
        that names it (`man`). Reads first rows and manifests only."""
        chain, newer, below = [], self.path, None
        while True:
            first = self._first_row(newer)
            if first is None or first.get("action") != CHECKPOINT:
                break
            p, n = self._checkpoint_params(first)
            if below is not None and n >= below:
                raise LedgerCorrupt("checkpoint chain does not descend (segment %d)" % n)
            below = n
            seg = self._seg_paths(n)
            try:
                with open(seg["manifest"], "rb") as f:
                    man = jcs.loads(f.read())
            except (OSError, ValueError, RecursionError) as ex:
                raise LedgerCorrupt("segment %d manifest unreadable: %s" % (n, ex))
            g = man.get("grants") if isinstance(man, dict) else None
            if (not isinstance(g, dict) or [man.get(k) for k in ("segment", "rows", "sha256", "head")]
                    != [p[k] for k in ("segment", "rows", "sha256", "head")]
                    or [g.get("rows"), g.get("sha256")] != [p["grant_rows"], p["grants_sha256"]]):
                raise LedgerCorrupt("segment %d manifest does not match its checkpoint" % n)
            chain.append(dict(seg, n=n, man=man, params=p))
            newer = seg["segment"]
        chain.reverse()
        return chain

    def _origin(self):
        """The hash the live file's first row chains onto: its checkpoint's
        head when the ledger has been sealed, else GENESIS."""
        chain = self._segment_chain()
        return chain[-1]["params"]["head"] if chain else "GENESIS"

    def verify(self, full=False, jobs=1) -> dict:
        """The chain, as a report ({"ok": bool, "error": ...}). Fast (the
        default, and what a node runs at start): each sealed segment is
        checked by one streaming sha256 against the checkpoint that names it
        and its manifest, and the live rows are verified row by row from
        the last checkpoint. Full: every row of every segment, oldest first,
        across each checkpoint, with the grant sidecars rebuilt and the
        prose mirrors hashed. Never raises."""
        rep = {"ok": False, "mode": "full" if full else "fast", "segments": [], "error": None}
        try:
            chain = self._segment_chain()
            prev = "GENESIS"
            for s in chain:
                p, man = s["params"], s["man"]
                if man.get("first_prev_hash") != prev:
                    raise LedgerCorrupt("segment %d does not start on %s" % (s["n"], prev[:12]))
                if full:
                    r = _scan_segment(s["segment"], prev, jobs)
                    if r["error"]:
                        raise LedgerCorrupt("segment %d %s" % (s["n"], r["error"]))
                    got = [r["rows"], r["sha256"], r["head"], r["bytes"], r["first_ts"], r["last_ts"]]
                    if got != [p["rows"], p["sha256"], p["head"], man.get("bytes"), man.get("first_ts"), man.get("last_ts")]:
                        raise LedgerCorrupt("segment %d rows do not match its manifest" % s["n"])
                    glines = b"".join(r["grant_lines"])
                    if [len(r["grant_lines"]), hashlib.sha256(glines).hexdigest()] != [p["grant_rows"], p["grants_sha256"]]:
                        raise LedgerCorrupt("segment %d grant rows do not match its manifest" % s["n"])
                    with open(s["grants"], "rb") as f:
                        if f.read() != glines:
                            raise LedgerCorrupt("segment %d grant sidecar is not its grant rows" % s["n"])
                    pm = man.get("prose") or {}
                    if [*_file_sha256(s["prose"])] != [pm.get("sha256"), pm.get("bytes")]:
                        raise LedgerCorrupt("segment %d prose mirror does not match its manifest" % s["n"])
                else:
                    if [*_file_sha256(s["segment"])] != [p["sha256"], man.get("bytes")]:
                        raise LedgerCorrupt("segment %d bytes do not match its sha256" % s["n"])
                    if _file_sha256(s["grants"])[0] != p["grants_sha256"]:
                        raise LedgerCorrupt("segment %d grant sidecar does not match its sha256" % s["n"])
                rep["segments"].append({"segment": p["segment"], "rows": p["rows"], "head": p["head"]})
                prev = p["head"]
            end = None
            if full:  # a daemon may be appending: verify through the last whole row there is now
                end = os.path.getsize(self.path)
                end -= len(self._unterminated_tail())
            r = _scan_segment(self.path, prev, jobs if full else 1, end=end)
            if r["error"]:
                raise LedgerCorrupt("live %s" % r["error"])
            rep.update(ok=True, live_rows=r["rows"], live_bytes=r["bytes"], head=r["head"],
                       rows=r["rows"] + sum(s["params"]["rows"] for s in chain))
        except (LedgerCorrupt, OSError, ValueError, TypeError, KeyError, RecursionError) as ex:
            rep["error"] = str(ex)
        return rep

    def verify_chain(self) -> bool:
        """Every live row parses, hashes to its own entry hash and chains
        onto the previous one, from GENESIS or from a checkpoint whose
        sealed segments match their sha256. False (never an exception)
        otherwise."""
        return self.verify()["ok"]

    def entries(self, all_segments=False):
        """The live rows in chain order; with all_segments=True the sealed
        segments' rows first, oldest segment first."""
        paths = [s["segment"] for s in self._segment_chain()] if all_segments else []
        for path in paths + [self.path]:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        yield json.loads(line)

    def _lines_backwards(self, path):
        """The whole lines of a file, last first, read in bounded chunks;
        bytes after the last newline (a torn tail) are not a line."""
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell() - len(self._unterminated_tail(path))
            carry = b""
            while pos > 0:
                step = min(self.TAIL_CHUNK, pos)
                pos -= step
                f.seek(pos)
                parts = (f.read(step) + carry).split(b"\n")
                carry = parts[0]
                for raw in reversed(parts[1:]):
                    yield raw
            if carry:
                yield carry

    def tail(self, n) -> list:
        """The last `n` rows in chain order, read backwards from the end of
        the live file and on into the sealed segments when it holds fewer:
        memory is the n rows, never the ledger."""
        out = []
        if n <= 0:
            return out
        for path in self._newest_first():
            for raw in self._lines_backwards(path):
                if raw.strip():
                    out.append(json.loads(raw))
                    if len(out) >= n:
                        return out[::-1]
        return out[::-1]

    def _newest_first(self):
        yield self.path
        for s in reversed(self._segment_chain()):  # walked only when the live file runs out
            yield s["segment"]

    @staticmethod
    def _same_file(a, b):
        try:
            sa, sb = os.stat(a), os.stat(b)
        except OSError:
            return False
        return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)

    def _write_new(self, directory, data):
        """A new owner-only temp file in `directory` holding `data`, durable."""
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ledger-seal-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return tmp

    def seal(self, apply=False, actor="node", jobs=1) -> dict:
        """Seal the live file as the next segment (spec 5.1). The caller
        holds the home's node.lock (no daemon is running); this holds the
        append lock throughout. The live rows are verified row by row (on
        `jobs` processes) and hashed; dry-run (the default) reports what
        would be written and changes nothing. Apply writes the grant
        sidecar and the manifest, links the live file and its prose mirror
        under the segment's names, then replaces the live file with one
        holding only the checkpoint row (the commit point) and the mirror
        with its prose line, sets the sealed files 0400 and runs the fast
        verify. No byte of a row is rewritten and none is dropped. A seal
        interrupted before the commit is redone on the next run; one
        interrupted after it is finished."""
        directory = os.path.dirname(os.path.abspath(self.path))
        with self._locked(self):
            self._recover_tail()
            chain = self._segment_chain()
            if chain and self._same_file(self.mirror_path, chain[-1]["prose"]):
                # interrupted after the commit: the live file is sealed, the mirror not yet
                res = {"applied": False, "status": "interrupted seal of %s; rerun with --apply to finish it"
                       % chain[-1]["params"]["segment"]}
                if apply:
                    cp = self._first_row(self.path)
                    line = "%s [%s] %s: %s -> sealed (grant=-)\n    resumed: prose mirror sealed\n" % (
                        cp["prev_hash_chain"][:12], cp["ts"], cp["actor"], CHECKPOINT)
                    os.replace(self._write_new(directory, line.encode()), self.mirror_path)
                    self._finish_modes(chain[-1], directory)
                    res.update(applied=True, status="finished interrupted seal", verify=self.verify())
                return res
            if chain:
                for s in chain:
                    self._finish_modes(s, directory, check_only=not apply)
            n = (chain[-1]["n"] if chain else 0) + 1
            seg = self._seg_paths(n)
            for k, live in (("segment", self.path), ("prose", self.mirror_path)):
                if os.path.exists(seg[k]) and not self._same_file(seg[k], live):
                    raise LedgerCorrupt("%s exists and is not an interrupted seal of this ledger; inspect it" % seg[k])
            if not os.path.exists(seg["segment"]):
                for k in ("manifest", "grants"):
                    if os.path.exists(seg[k]):
                        raise LedgerCorrupt("%s exists without its segment; inspect it" % seg[k])
            prev = chain[-1]["params"]["head"] if chain else "GENESIS"
            st = os.stat(self.path)
            r = _scan_segment(self.path, prev, jobs)
            if r["error"]:
                raise LedgerCorrupt("live ledger does not verify, not sealing: %s" % r["error"])
            if not r["rows"]:
                raise LedgerCorrupt("the live ledger is empty: nothing to seal")
            glines = b"".join(r["grant_lines"])
            prose_sha, prose_bytes = (_file_sha256(self.mirror_path) if os.path.exists(self.mirror_path)
                                      else (hashlib.sha256().hexdigest(), 0))
            params = {"segment": os.path.basename(seg["segment"]), "rows": r["rows"], "sha256": r["sha256"],
                      "head": r["head"], "grant_rows": len(r["grant_lines"]),
                      "grants_sha256": hashlib.sha256(glines).hexdigest()}
            manifest = {"schema": "natively.ledger-segment.v1", "segment": params["segment"],
                        "rows": r["rows"], "bytes": r["bytes"], "sha256": r["sha256"],
                        "first_ts": r["first_ts"], "last_ts": r["last_ts"],
                        "first_prev_hash": prev, "head": r["head"],
                        "prose": {"file": os.path.basename(seg["prose"]), "bytes": prose_bytes, "sha256": prose_sha},
                        "grants": {"file": os.path.basename(seg["grants"]), "rows": params["grant_rows"],
                                   "sha256": params["grants_sha256"]},
                        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            cp = {"ts": manifest["sealed_at"], "actor": actor, "grant_id": None, "action": CHECKPOINT,
                  "params": params, "params_hash": jcs.sha256(jcs.canonicalize(params)),
                  "outcome": "sealed", "prev_hash": r["head"]}
            cp["prev_hash_chain"] = _row_hash(cp)
            res = {"applied": False, "status": "dry run; rerun with --apply to seal", "manifest": manifest,
                   "checkpoint": cp, "files": {k: os.path.basename(v) for k, v in seg.items()}}
            if not apply:
                return res
            for k, data in (("grants", glines),
                            ("manifest", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())):
                os.replace(self._write_new(directory, data), seg[k])
            if not os.path.exists(self.mirror_path):
                _open600(self.mirror_path, "a").close()
            for k, live in (("segment", self.path), ("prose", self.mirror_path)):
                if not os.path.exists(seg[k]):
                    os.link(live, seg[k])
            self._fsync_dir(directory)
            new_live = self._write_new(directory, (json.dumps(cp, separators=(",", ":")) + "\n").encode())
            new_prose = self._write_new(directory, ("%s [%s] %s: %s -> sealed (grant=-)\n    sealed %d rows as %s\n" % (
                cp["prev_hash_chain"][:12], cp["ts"], actor, CHECKPOINT, r["rows"], params["segment"])).encode())
            now = os.stat(self.path)
            if (now.st_ino, now.st_size, now.st_mtime_ns) != (st.st_ino, st.st_size, st.st_mtime_ns):
                os.unlink(new_live)
                os.unlink(new_prose)
                raise LedgerCorrupt("the live ledger changed while it was being sealed; nothing committed")
            os.replace(new_live, self.path)  # the commit point
            os.replace(new_prose, self.mirror_path)
            self._fsync_dir(directory)
            self._finish_modes(dict(seg), directory)
            self._head_cache = self._head_stat = self._by_grant = None
            res.update(applied=True, status="sealed", verify=self.verify())
            if not res["verify"]["ok"]:
                raise LedgerCorrupt("sealed ledger failed verification: %s" % res["verify"]["error"])
            return res

    def _finish_modes(self, seg, directory, check_only=False):
        """A sealed segment's files are read-only (0400)."""
        changed = False
        for k in ("segment", "prose", "grants", "manifest"):
            if os.stat(seg[k]).st_mode & 0o777 != 0o400 and not check_only:
                os.chmod(seg[k], 0o400)
                changed = True
        if changed:
            self._fsync_dir(directory)
