"""SQLite-backed shared task state machine for Natively v0.1.

Transport authenticates signed transition envelopes before calling this store.
This module owns transactional compare-and-swap, leases, idempotency, and an
append-only board event feed. Task bodies/results remain encrypted blob refs.
"""
import json
import sqlite3
import threading
import time
import uuid

TERMINAL = {"completed", "cancelled"}
VALID_STATES = {"ready", "claimed", "action", "submitted", "completed", "failed", "cancelled"}


class TaskConflict(Exception):
    def __init__(self, message, task=None):
        super().__init__(message)
        self.task = task


class TaskStore:
    def __init__(self, path, clock=time.time):
        self.path = str(path)
        self.clock = clock
        self._local = threading.local()
        self._init()

    def _db(self):
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            self._local.db = db
        return db

    def _init(self):
        db = self._db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS tasks (
          task_id TEXT PRIMARY KEY,
          board_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          state TEXT NOT NULL,
          document TEXT NOT NULL,
          updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS tasks_board_state ON tasks(board_id,state,updated_at);
        CREATE TABLE IF NOT EXISTS task_events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          board_id TEXT NOT NULL,
          task_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          action TEXT NOT NULL,
          actor TEXT NOT NULL,
          event TEXT NOT NULL,
          created_at REAL NOT NULL,
          UNIQUE(task_id,revision)
        );
        CREATE INDEX IF NOT EXISTS events_board_seq ON task_events(board_id,seq);
        CREATE TABLE IF NOT EXISTS task_idempotency (
          task_id TEXT NOT NULL,
          idempotency_key TEXT NOT NULL,
          request_hash TEXT NOT NULL,
          response TEXT NOT NULL,
          PRIMARY KEY(task_id,idempotency_key)
        );
        """)

    @staticmethod
    def _json(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _task(row):
        return json.loads(row["document"]) if row else None

    def get(self, task_id):
        return self._task(self._db().execute(
            "SELECT document FROM tasks WHERE task_id=?", (task_id,)).fetchone())

    def post(self, board_id, actor, task_id, title, body_ref, capabilities=(),
             depends_on=(), priority=50, extensions=None, idempotency_key=None,
             verifier=None, acceptance_ref=None):
        now = self.clock()
        task = {
            "task_id": task_id, "board_id": board_id, "revision": 1,
            "created_by": actor, "created_at": now, "title": title,
            "body_ref": body_ref, "verifier": verifier or actor,
            "acceptance_ref": acceptance_ref,
            "required_capabilities": sorted(set(capabilities)),
            "depends_on": list(depends_on), "priority": int(priority),
            "extensions": dict(extensions or {}), "state": "ready", "claim": None,
            "checkpoint_ref": None, "result_ref": None, "failure": None,
            "updated_at": now,
        }
        return self._create(task, actor, idempotency_key or "post:" + task_id)

    def _create(self, task, actor, key):
        db = self._db(); payload = self._json(task)
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT response,request_hash FROM task_idempotency WHERE task_id=? AND idempotency_key=?",
                               (task["task_id"], key)).fetchone()
            if prior:
                if prior["request_hash"] != payload: raise TaskConflict("idempotency key reused")
                db.execute("COMMIT"); return json.loads(prior["response"])
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?)", (task["task_id"], task["board_id"], 1, "ready", payload, task["updated_at"]))
            self._event(db, task, "task.post", actor)
            db.execute("INSERT INTO task_idempotency VALUES(?,?,?,?)", (task["task_id"], key, payload, payload))
            db.execute("COMMIT"); return task
        except sqlite3.IntegrityError:
            db.execute("ROLLBACK")
            existing = self.get(task["task_id"])
            raise TaskConflict("task already exists", existing)
        except Exception:
            db.execute("ROLLBACK"); raise

    def transition(self, task_id, expected_revision, action, actor, idempotency_key,
                   capabilities=(), lease_id=None, lease_seconds=None,
                   checkpoint_ref=None, result_ref=None, failure=None,
                   extensions=None, feedback_ref=None):
        request = self._json({"task_id": task_id, "expected_revision": expected_revision,
            "action": action, "actor": actor, "capabilities": sorted(set(capabilities)),
            "lease_id": lease_id, "lease_seconds": lease_seconds,
            "checkpoint_ref": checkpoint_ref, "result_ref": result_ref,
            "failure": failure, "extensions": extensions,
            "feedback_ref": feedback_ref})
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT response,request_hash FROM task_idempotency WHERE task_id=? AND idempotency_key=?",
                               (task_id, idempotency_key)).fetchone()
            if prior:
                if prior["request_hash"] != request: raise TaskConflict("idempotency key reused")
                db.execute("COMMIT"); return json.loads(prior["response"])
            row = db.execute("SELECT document FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row: raise TaskConflict("unknown task")
            task = json.loads(row["document"]); now = self.clock()
            if task["revision"] != expected_revision:
                raise TaskConflict("revision mismatch", task)
            self._apply(db, task, action, actor, now, set(capabilities), lease_id,
                        lease_seconds, checkpoint_ref, result_ref, failure, extensions,
                        feedback_ref)
            task["revision"] += 1; task["updated_at"] = now
            response = self._json(task)
            changed = db.execute("UPDATE tasks SET revision=?,state=?,document=?,updated_at=? WHERE task_id=? AND revision=?",
                (task["revision"], task["state"], response, now, task_id, expected_revision))
            if changed.rowcount != 1: raise TaskConflict("concurrent transition", self.get(task_id))
            self._event(db, task, action, actor)
            db.execute("INSERT INTO task_idempotency VALUES(?,?,?,?)", (task_id, idempotency_key, request, response))
            db.execute("COMMIT"); return task
        except Exception:
            if db.in_transaction: db.execute("ROLLBACK")
            raise


    def _apply(self, db, task, action, actor, now, caps, lease_id, lease_seconds,
               checkpoint_ref, result_ref, failure, extensions, feedback_ref):
        state, claim = task["state"], task.get("claim")
        if action == "task.claim":
            expired = state == "claimed" and claim and claim["lease_until"] <= now
            if state != "ready" and not expired: raise TaskConflict("task is not ready", task)
            if expired:
                task["state"], task["claim"] = "ready", None
                state, claim = "ready", None
            if not set(task["required_capabilities"]).issubset(caps): raise TaskConflict("capability mismatch", task)
            for dep in task["depends_on"]:
                row = db.execute("SELECT state FROM tasks WHERE task_id=?", (dep,)).fetchone()
                if not row or row["state"] != "completed": raise TaskConflict("dependency incomplete", task)
            if not lease_seconds or lease_seconds <= 0: raise TaskConflict("positive lease required", task)
            attempt = (task.get("last_attempt") or 0) + 1
            task["last_attempt"] = attempt; task["state"] = "claimed"
            task["claim"] = {"agent": actor, "lease_id": lease_id or "lease_" + uuid.uuid4().hex,
                             "lease_until": now + lease_seconds, "attempt": attempt}
        elif action == "task.renew":
            self._owner(task, actor, lease_id)
            if state not in {"claimed", "action"}: raise TaskConflict("task is not renewable", task)
            if not lease_seconds or lease_seconds <= 0: raise TaskConflict("positive lease required", task)
            claim["lease_until"] = now + lease_seconds
        elif action in {"task.checkpoint", "task.action_required", "task.resume", "task.submit", "task.fail"}:
            self._owner(task, actor, lease_id)
            if state not in {"claimed", "action"}: raise TaskConflict("task is not owned", task)
            if checkpoint_ref is not None: task["checkpoint_ref"] = checkpoint_ref
            if action == "task.action_required": task["state"] = "action"
            elif action == "task.resume": task["state"] = "claimed"
            elif action == "task.submit":
                if not result_ref: raise TaskConflict("result ref required", task)
                task["state"], task["result_ref"], task["claim"] = "submitted", result_ref, None
            elif action == "task.fail": task["state"], task["failure"] = "failed", failure
        elif action in {"task.accept", "task.reject"}:
            if state != "submitted": raise TaskConflict("task is not submitted", task)
            if actor != task["verifier"]: raise TaskConflict("verifier mismatch", task)
            if action == "task.accept":
                task["state"] = "completed"
            else:
                task["state"], task["result_ref"] = "ready", None
                task["feedback_ref"] = feedback_ref
        elif action == "task.cancel":
            if state in TERMINAL: raise TaskConflict("task is terminal", task)
            task["state"] = "cancelled"
        elif action == "task.extensions":
            task["extensions"].update(extensions or {})
        else:
            raise TaskConflict("unsupported action")

    @staticmethod
    def _owner(task, actor, lease_id):
        claim = task.get("claim")
        if not claim or claim["agent"] != actor or claim["lease_id"] != lease_id:
            raise TaskConflict("lease owner mismatch", task)

    def _event(self, db, task, action, actor):
        event = {"task": task, "action": action, "actor": actor}
        db.execute("INSERT INTO task_events(board_id,task_id,revision,action,actor,event,created_at) VALUES(?,?,?,?,?,?,?)",
            (task["board_id"], task["task_id"], task["revision"], action, actor, self._json(event), task["updated_at"]))

    def events(self, board_id, after=0, limit=1000):
        rows = self._db().execute("SELECT seq,event FROM task_events WHERE board_id=? AND seq>? ORDER BY seq LIMIT ?",
                                  (board_id, int(after), min(int(limit), 1000))).fetchall()
        return [{"seq": row["seq"], **json.loads(row["event"])} for row in rows]
