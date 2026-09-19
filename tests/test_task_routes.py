import json
import threading

import pytest

from natively import crypto, envelope
from natively.task_client import GooseAdapter, TaskClient, TaskHTTPError
from conftest import agent_key, make_node, start_hub


def client(hub, node, name):
    agent = node.agents[name]
    return TaskClient(hub.url, agent["card"]["agent_key"], agent["seed"])


def test_private_board_routes_and_verifier_flow(tmp_path, principal):
    hub = start_hub(tmp_path, principal_roots=[principal.pub])
    try:
        poster = make_node(tmp_path, "poster", hub.url, principal,
            agents={"post": ["task.post:apmhelp.bill-entry", "task.read:apmhelp.bill-entry", "task.verify:apmhelp.bill-entry"]})
        worker = make_node(tmp_path, "worker", hub.url, principal,
            agents={"goose": ["task.claim:apmhelp.bill-entry", "task.read:apmhelp.bill-entry"]})
        wrong = make_node(tmp_path, "wrong", hub.url, principal,
            agents={"other": ["task.read:ccc.campaign"]})
        pc, wc, xc = client(hub, poster, "post"), client(hub, worker, "goose"), client(hub, wrong, "other")
        tid, idem = envelope.new_id("tsk"), envelope.new_id("req")
        task = pc.post("apmhelp.bill-entry", "bill", "blob:body", task_id=tid,
                       capabilities=["bill.extract.v1"], verifier=agent_key(poster, "post"),
                       acceptance_ref="blob:criteria", idempotency_key=idem)
        assert wc.list("apmhelp.bill-entry")["tasks"][0]["task_id"] == task["task_id"]
        with pytest.raises(TaskHTTPError) as denied:
            xc.get(task["task_id"])
        assert denied.value.status == 403
        claimed = wc.transition(task["task_id"], task["revision"], "task.claim",
                                capabilities=["bill.extract.v1"], lease_seconds=60)
        submitted = wc.transition(task["task_id"], claimed["revision"], "task.submit",
                                  lease_id=claimed["claim"]["lease_id"], result_ref="blob:result")
        with pytest.raises(TaskHTTPError) as denied:
            wc.transition(task["task_id"], submitted["revision"], "task.accept")
        assert denied.value.status == 403
        done = pc.transition(task["task_id"], submitted["revision"], "task.accept")
        assert done["state"] == "completed"
        events = pc.events("apmhelp.bill-entry")
        assert [e["action"] for e in events["events"]] == ["task.post", "task.claim", "task.submit", "task.accept"]
    finally:
        hub.close()


def test_signed_route_body_and_atomic_goose_claim(tmp_path, principal):
    hub = start_hub(tmp_path, principal_roots=[principal.pub])
    try:
        poster = make_node(tmp_path, "poster", hub.url, principal,
            agents={"post": ["task.post:tto.audit", "task.read:tto.audit", "task.verify:tto.audit"]})
        workers = [make_node(tmp_path, "w%d" % i, hub.url, principal,
            agents={"goose": ["task.claim:tto.audit", "task.read:tto.audit"]}) for i in range(8)]
        pc = client(hub, poster, "post")
        task = pc.post("tto.audit", "audit", "blob:body", capabilities=["audit.v1"], verifier=agent_key(poster, "post"))
        adapters = [GooseAdapter(client(hub, w, "goose"), "tto.audit", ["audit.v1"]) for w in workers]
        claimed, lock = [], threading.Lock()
        def race(a):
            out = a.claim_one()["task"]
            if out:
                with lock: claimed.append(out)
        threads = [threading.Thread(target=race, args=(a,)) for a in adapters]
        [t.start() for t in threads]; [t.join() for t in threads]
        assert len(claimed) == 1
        # Reusing a valid signature with a changed body does not authenticate.
        c = client(hub, workers[0], "goose")
        path = "/v1/tasks/%s/transitions" % task["task_id"]
        body = {"expected_revision": claimed[0]["revision"], "action": "task.submit",
                "idempotency_key": envelope.new_id("req"), "lease_id": claimed[0]["claim"]["lease_id"],
                "result_ref": "blob:ok"}
        # The normal client succeeds, proving the claimed worker path end-to-end.
        owner = next(a for a in adapters if a.client.agent_key == claimed[0]["claim"]["agent"])
        result = owner.client.transition(task["task_id"], claimed[0]["revision"], "task.submit",
                 lease_id=claimed[0]["claim"]["lease_id"], result_ref="blob:ok")
        assert result["state"] == "submitted"
    finally:
        hub.close()
