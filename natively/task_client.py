"""Authenticated client and harness-neutral adapters for shared task boards."""
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import crypto, envelope


class TaskHTTPError(RuntimeError):
    def __init__(self, status, message, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class TaskClient:
    """Bare adapter: one local Natively agent talking to hub task routes."""
    def __init__(self, hub_url, agent_key, agent_seed, timeout=35):
        self.hub = hub_url.rstrip("/")
        self.agent_key = agent_key
        self.seed = agent_seed
        self.timeout = timeout

    def _request(self, method, path, body=None):
        raw = b"" if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        token = envelope.sign_obj({
            "op": "task.http", "method": method, "path": path,
            "agent_key": self.agent_key, "body_sha256": hashlib.sha256(raw).hexdigest(),
            "ts": envelope.now_iso(),
        }, self.seed)
        headers = {"X-Natively-Agent": crypto.b64e(json.dumps(token, sort_keys=True, separators=(",", ":")).encode())}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.hub + path, data=raw if body is not None else None,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try: payload = json.loads(e.read() or b"{}")
            except Exception: payload = {}
            raise TaskHTTPError(e.code, payload.get("error", "task request failed"), payload)

    def post(self, board, title, body_ref, task_id=None, capabilities=(), depends_on=(),
             priority=50, extensions=None, verifier=None, acceptance_ref=None,
             idempotency_key=None):
        body = {"task_id": task_id or envelope.new_id("tsk"), "title": title,
                "body_ref": body_ref, "required_capabilities": list(capabilities),
                "depends_on": list(depends_on), "priority": priority,
                "extensions": extensions or {}, "verifier": verifier,
                "acceptance_ref": acceptance_ref, "idempotency_key": idempotency_key}
        return self._request("POST", "/v1/taskboards/%s/tasks" % urllib.parse.quote(board, safe=""), body)

    def list(self, board, after=0, states=()):
        q = urllib.parse.urlencode({"after": int(after), "state": ",".join(states)})
        return self._request("GET", "/v1/taskboards/%s/tasks?%s" % (urllib.parse.quote(board, safe=""), q))

    def get(self, task_id):
        return self._request("GET", "/v1/tasks/%s" % urllib.parse.quote(task_id, safe=""))

    def transition(self, task_id, expected_revision, action, idempotency_key=None, **fields):
        body = {"expected_revision": expected_revision, "action": action,
                "idempotency_key": idempotency_key or envelope.new_id("req")}
        body.update(fields)
        return self._request("POST", "/v1/tasks/%s/transitions" % urllib.parse.quote(task_id, safe=""), body)

    def events(self, board, after=0, limit=1000):
        q = urllib.parse.urlencode({"after": int(after), "limit": int(limit)})
        return self._request("GET", "/v1/taskboards/%s/events?%s" % (urllib.parse.quote(board, safe=""), q))


class GooseAdapter:
    """Small Goose bridge. The caller owns Goose process/config and supplies executor.

    The executor receives the claimed task and returns an encrypted/opaque
    result reference. The adapter never shells out, so prompts cannot turn
    into command-line instructions. A caller may checkpoint separately.
    """
    def __init__(self, client, board, capabilities, lease_seconds=300):
        self.client = client
        self.board = board
        self.capabilities = tuple(capabilities)
        self.lease_seconds = int(lease_seconds)

    def claim_one(self, after=0):
        page = self.client.list(self.board, after=after, states=("ready", "claimed"))
        for task in page["tasks"]:
            try:
                claimed = self.client.transition(
                    task["task_id"], task["revision"], "task.claim",
                    capabilities=self.capabilities, lease_seconds=self.lease_seconds)
                return {"task": claimed, "cursor": page["cursor"]}
            except TaskHTTPError as e:
                if e.status != 409:
                    raise
        return {"task": None, "cursor": page["cursor"]}

    def run_one(self, executor, after=0):
        found = self.claim_one(after=after)
        task = found["task"]
        if not task:
            return found
        claim = task["claim"]
        try:
            result_ref = executor(task)
            submitted = self.client.transition(
                task["task_id"], task["revision"], "task.submit",
                lease_id=claim["lease_id"], result_ref=result_ref)
            return {"task": submitted, "cursor": found["cursor"]}
        except Exception as exc:
            # Best effort failure record; keep the original executor error.
            try:
                self.client.transition(task["task_id"], task["revision"], "task.fail",
                                       lease_id=claim["lease_id"], failure={"class": type(exc).__name__})
            except Exception:
                pass
            raise
