"""Bounded, durable hub storage (review 2026-09-07, point 7): quotas are
enforced by refusing the POST (429) before anything is accepted - by
message count, by bytes per recipient and by bytes for the whole hub;
what was accepted is never discarded by a limit, at enqueue or at load;
a save the throttle held back is written by a timer and on shutdown; a
state file that does not parse or is not the hub's shape refuses to
start rather than loading empty."""
import json
import os
import time

import pytest

from natively import envelope
from natively import hub as hubmod

from conftest import agent_key, http, inbox, make_node, outcomes, pump, start_hub


def _env(to, n=64):
    return {"msg_id": envelope.new_id("msg"), "type": "msg", "to": to, "body": "x" * n}


_ = (agent_key, inbox, outcomes, pump)  # conftest helpers used below


def test_byte_quotas_refuse_before_accepting_and_a_sender_keeps_the_envelope(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = agent_key(n2, "beta")
    hub.state.QUEUE_MAX_BYTES = 4096
    assert http("POST", hub.url + "/v1/msg", _env(to, 3000))[0] == 200
    st, resp = http("POST", hub.url + "/v1/msg", _env(to, 3000))
    assert st == 429 and "bytes" in resp["error"]
    assert len(hub.state.queues[n2.fp]) == 1  # nothing accepted was dropped to make room
    # a real sender: its flush sees the 429, keeps the file and retries later
    hub.state.QUEUE_MAX_BYTES = 3100  # the 3000 queued plus a real envelope does not fit
    n1.queue_send("alpha", to, {"kind": "text", "text": "waiting for room"})
    n1.step()
    assert "retry" in outcomes(n1, "msg.send") and len([f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]) == 1
    hub.state.QUEUE_MAX_BYTES = 16 * 1024 * 1024
    n1._backoff.clear()  # the Retry-After wait is over
    n1._rcpt_backoff.clear()  # and the per-recipient verdict the refusal set
    pump([n1, n2], 6)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["waiting for room"]
    # the hub-wide quota too
    hub.state.TOTAL_MAX_BYTES = 100
    st, resp = http("POST", hub.url + "/v1/msg", _env(to, 300))
    assert st == 429 and "hub storage" in resp["error"]


def test_fan_out_is_charged_for_every_copy_and_a_deferred_send_spends_no_budget(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    e = _env([agent_key(n2, "beta"), agent_key(n3, "gamma")], 200)
    hub.state.TOTAL_MAX_BYTES = len(json.dumps(e)) + 50  # one copy fits, two do not
    st, resp = http("POST", hub.url + "/v1/msg", e)
    assert st == 429 and "hub storage" in resp["error"]
    assert not hub.state.queues.get(n2.fp) and not hub.state.queues.get(n3.fp)  # nothing accepted for anyone
    # two recipients on ONE node are one copy: charged once, accepted
    n2b = make_node(tmp_path, "n2b", hub.url, principal, {"beta2": ["msg.send"], "gamma2": ["msg.send"]})
    e2 = _env([agent_key(n2b, "beta2"), agent_key(n2b, "gamma2")], 200)
    hub.state.TOTAL_MAX_BYTES = len(json.dumps(e2)) + 50
    assert http("POST", hub.url + "/v1/msg", e2)[0] == 200
    hub.state.TOTAL_MAX_BYTES = 256 * 1024 * 1024
    # a sender refused with 429 waits Retry-After before trying that file
    # again, and its other sends are not held behind it
    hub.state.QUEUE_MAX_MSGS = 0
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "no room at beta"})
    n1.step()
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    assert f in n1._backoff and n1._backoff[f][0] > time.time()
    hub.state.QUEUE_MAX_MSGS = 500
    n1.queue_send("alpha", agent_key(n3, "gamma"), {"kind": "text", "text": "gamma goes on"})
    pump([n1, n3], 3)
    assert [r["body"]["text"] for r in inbox(n3, "gamma")] == ["gamma goes on"]
    assert f in os.listdir(n1.outbox_dir)  # the deferred file was not attempted before its time
    n1._backoff[f] = (0.0, n1._backoff[f][1])
    n1._rcpt_backoff.clear()  # the per-recipient verdict the refusal set expires with the wait
    pump([n1, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["no room at beta"]


def test_a_relay_waits_behind_its_recipients_deferred_control_envelope(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = agent_key(n2, "beta")
    hub.state.QUEUE_MAX_MSGS = 0  # no room at beta: the control envelope is refused
    n1.queue_send("alpha", to, {"kind": "group_key", "text": "the key"}, control=True)
    n1.step()
    (ctl,) = [f for f in os.listdir(n1.outbox_dir) if f.startswith("ctl_")]
    assert ctl in n1._backoff
    hub.state.QUEUE_MAX_MSGS = 500  # room again, but the key still waits its Retry-After
    n1.queue_send("alpha", to, {"kind": "text", "text": "a relay after the key"})
    n1.step()
    assert not hub.state.queues.get(n2.fp)  # the relay did not overtake the key
    n1._backoff[ctl] = (0.0, n1._backoff[ctl][1])
    n1._rcpt_backoff.clear()  # the per-recipient verdict the refusal set expires with the wait
    n1.step()
    kinds = [m["env"] for m in hub.state.queues[n2.fp]]
    assert len(kinds) == 2 and kinds[0].get("class") == "control"  # the key first, then the relay


def test_a_relay_queued_in_the_same_pass_as_its_refused_key_waits_too(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = agent_key(n2, "beta")
    hub.state.QUEUE_MAX_BYTES = 20000
    assert http("POST", hub.url + "/v1/msg", _env(to, 19070))[0] == 200  # ~800 bytes of room left
    n1.queue_send("alpha", to, {"kind": "group_key", "text": "k" * 600}, control=True)  # the key (bigger) does not fit; a small relay would
    n1.queue_send("alpha", to, {"kind": "text", "text": "r"})
    n1.step()  # one pass: the key is refused first (control goes first), then the relay must not slip through
    assert len(hub.state.queues.get(n2.fp, [])) == 1  # only the filler: neither the key nor the relay
    assert len([f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]) == 2
    # and on the next pass the held relay is neither in the windows nor an attempt
    n1.LIVE_WINDOW, n1.DRAIN_SLICE, n1.FLUSH_BATCH = 1, 0, 1
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n3, "gamma"), {"kind": "text", "text": "gamma goes on"})
    n1.step()
    pump([n3], 2)
    assert [r["body"]["text"] for r in inbox(n3, "gamma")] == ["gamma goes on"]


def test_the_hub_refuses_at_accept_what_it_would_refuse_at_load(tmp_path, hub, principal):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    e = _env(agent_key(n2, "beta"))
    e["msg_id"] = 12345
    assert http("POST", hub.url + "/v1/msg", e)[0] == 400
    # what is on disk always loads again
    with hub.state.lock:
        hub.state.save(force=True)
    hubmod.State(hub.state.path)


def test_what_can_never_fit_or_never_serialize_is_refused_at_accept(tmp_path, hub, principal):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    hub.state.QUEUE_MAX_BYTES = 2048
    assert http("POST", hub.url + "/v1/msg", _env(agent_key(n2, "beta"), 4000))[0] == 413  # terminal, not 429
    hub.state.QUEUE_MAX_BYTES = 16 * 1024 * 1024
    deep = ('{"msg_id": "%s", "type": "msg", "to": "%s", "body": "x", "n": ' % (envelope.new_id("msg"), agent_key(n2, "beta"))
            + "[" * 200000 + "]" * 200000 + "}")  # built as text: nesting no encoder or decoder can walk
    st, _ = http("POST", hub.url + "/v1/msg", deep.encode())
    assert st == 400  # refused at the door, whether the reader or the snapshot would choke on it
    # nested past the bound but shallow enough for this thread's json.dumps:
    # the saver thread's stack is smaller than the request thread's, so the
    # accept-time encode proves nothing about the snapshot - the bound does
    deepish = ('{"msg_id": "%s", "type": "msg", "to": "%s", "body": "y", "n": ' % (envelope.new_id("msg"), agent_key(n2, "beta"))
               + "[" * 900 + "]" * 900 + "}")
    st, b = http("POST", hub.url + "/v1/msg", deepish.encode())
    assert st == 400 and "deep" in b["error"]
    with hub.state.lock:  # and the file still writes
        hub.state.save(force=True)
    assert not [m for q in hub.state.queues.values() for m in q if m["env"].get("body") in ("x", "y")]
    assert not hub.state._dirty


def test_a_control_hold_matches_either_key_form(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = agent_key(n2, "beta")
    hub.state.QUEUE_MAX_MSGS = 0
    n1.queue_send("alpha", to, {"kind": "group_key", "text": "the key"}, control=True)  # prefixed form
    n1.step()
    hub.state.QUEUE_MAX_MSGS = 500
    n1.queue_send("alpha", to.split(":", 1)[1], {"kind": "text", "text": "bare form"})  # the same recipient, bare
    n1.step()
    assert not hub.state.queues.get(n2.fp)  # held behind the key, whatever the form


def test_a_registration_time_that_does_not_parse_is_corrupt_state(tmp_path):
    path = str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path))
    open(path, "w").write('{"nodes": {"fp": {"name": "n", "node_key": "k", "reg_ts": "not-a-date"}}}')
    with pytest.raises(hubmod.StateCorrupt):
        hubmod.State(path)


def test_a_shutdown_refusal_leaves_the_connection_usable(tmp_path, hub, principal):
    import http.client
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    with hub.state.lock:
        hub.state.closing = True
    try:
        c = http.client.HTTPConnection("127.0.0.1", hub.server.server_address[1], timeout=5)
        body = json.dumps(_env(agent_key(n2, "beta"), 2000)).encode()
        c.request("POST", "/v1/msg", body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        assert r.status == 503 and r.read()
        c.request("GET", "/v1/healthz")  # the same keep-alive connection: the next request is parsed cleanly
        r2 = c.getresponse()
        assert r2.status == 200 and r2.read()
    finally:
        with hub.state.lock:
            hub.state.closing = False


def test_eligibility_is_decided_before_the_windows_are_cut(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    n1.LIVE_WINDOW, n1.DRAIN_SLICE = 2, 1
    files = [n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "deferred %d" % i}) for i in range(4)]
    eligible = n1.queue_send("alpha", agent_key(n3, "gamma"), {"kind": "text", "text": "eligible"})
    files += [n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "deferred %d" % i}) for i in range(4, 7)]
    for f in files:
        n1._backoff[os.path.basename(f)] = (time.time() + 600, 60.0)  # every beta file waits; gamma's sits in the middle
    n1.step()
    pump([n3], 2)
    assert [r["body"]["text"] for r in inbox(n3, "gamma")] == ["eligible"]
    assert not os.path.exists(eligible)


def test_a_forced_save_that_fails_is_a_retryable_failure_for_the_caller(tmp_path, monkeypatch):
    path = str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path))
    st = hubmod.State(path)
    real_replace = os.replace

    def broken(a, b):
        if a.endswith("hub.json.tmp"):
            raise OSError("volume away")
        return real_replace(a, b)
    monkeypatch.setattr(os, "replace", broken)
    with st.lock:
        st.seq["a"] = 1
        with pytest.raises(OSError):
            st.save(force=True)  # the caller learns; the retry is armed all the same
        assert st._dirty and st._saver is not None
        st.save()  # an ordinary mutation meanwhile does not hammer the disk: the armed retry takes it along
    monkeypatch.setattr(os, "replace", real_replace)
    st.close()
    assert json.load(open(path))["seq"] == {"a": 1}


def test_nothing_is_accepted_past_the_final_flush(tmp_path, hub, principal):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    with hub.state.lock:
        hub.state.closing = True
    st, resp = http("POST", hub.url + "/v1/msg", _env(agent_key(n2, "beta")))
    assert st == 503 and "shutting down" in resp["error"]
    with hub.state.lock:
        hub.state.closing = False


def test_a_failed_save_is_retried_until_it_lands(tmp_path, monkeypatch):
    path = str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path))
    st = hubmod.State(path)
    st.SAVE_INTERVAL = 0.2
    real_replace = os.replace
    broken = {"on": True}

    def flaky(a, b):
        if broken["on"] and a.endswith("hub.json.tmp"):
            raise OSError("volume away")
        return real_replace(a, b)
    monkeypatch.setattr(os, "replace", flaky)
    with st.lock:
        st.seq["a"] = 7
        st.save()  # the write fails: the state stays dirty, a retry is armed
    assert st._dirty and st._saver is not None and not os.path.exists(path)
    broken["on"] = False
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(path):
        time.sleep(0.05)
    assert json.load(open(path))["seq"] == {"a": 7}
    st.close()


def test_a_duplicate_takes_no_room(tmp_path, hub, principal):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = agent_key(n2, "beta")
    hub.state.QUEUE_MAX_MSGS = 1
    e = _env(to)
    assert http("POST", hub.url + "/v1/msg", e)[0] == 200
    assert http("POST", hub.url + "/v1/msg", e) == (200, {"queued": 0, "deduped": 1})
    assert http("POST", hub.url + "/v1/msg", _env(to))[0] == 429


def test_a_save_the_throttle_held_back_is_written_by_the_timer_and_on_close(tmp_path):
    path = str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path))
    st = hubmod.State(path)
    st.SAVE_INTERVAL = 0.3
    with st.lock:
        st.seq["a"] = 1
        st.save()  # first save: written now
    assert json.load(open(path))["seq"] == {"a": 1}
    with st.lock:
        st.seq["a"] = 2
        st.save()  # inside the interval: held back, but not lost
    assert json.load(open(path))["seq"] == {"a": 1}
    deadline = time.time() + 3
    while time.time() < deadline and json.load(open(path))["seq"] != {"a": 2}:
        time.sleep(0.05)
    assert json.load(open(path))["seq"] == {"a": 2}
    with st.lock:
        st.seq["a"] = 3
        st.save()
    st.close()  # shutdown writes what the throttle held
    assert json.load(open(path))["seq"] == {"a": 3} and not os.path.exists(path + ".tmp")


def test_corrupt_state_refuses_to_start_instead_of_loading_empty(tmp_path):
    path = str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path))
    for bad in ("{not json", "[]", '{"queues": []}', '{"queues": {"fp": [1]}}', '{"seq": {"fp": -1}}',
                '{"queues": {"fp": [{"env": {}, "_seq": "1"}]}}',
                '{"queues": {"fp": [{"env": {}, "_seq": 5}]}, "seq": {"fp": 0}}',  # a counter behind its queue
                '{"queues": {"fp": [{"env": {}, "_seq": 1, "_bytes": "x"}]}, "seq": {"fp": 1}}',
                '{"queues": {"fp": [{"env": {}, "_seq": 1, "_bytes": -5}]}, "seq": {"fp": 1}}',
                '{"nodes": {"fp": "not a record"}}', '{"agent_owner": {"k": 5}}',
                '{"nodes": {"fp": {"reg_ts": ["not", "a", "stamp"]}}}',
                '{"agent_dir": {"a@fp": {"node_fp": "fp", "agent_key": "k", "card": "not a card"}}}',
                '{"queues": {"fp": [{"env": {"msg_id": ["x"]}, "_seq": 1}]}, "seq": {"fp": 1}}',
                '{"queues": {}, "queues": {"fp": [{"env": {"msg_id": "m"}, "_seq": 1}]}, "seq": {"fp": 1}}',  # a duplicate key: last-wins is not what this hub wrote
                '{"queues": {"fp": [{"env": {"msg_id": "m", "n": NaN}, "_seq": 1}]}, "seq": {"fp": 1}}',  # NaN: a poll the node cannot parse
                '{"queues": {"fp": [{"env": {"msg_id": "a"}, "_seq": 2}, {"env": {"msg_id": "b"}, "_seq": 1}]}, "seq": {"fp": 2}}'):  # out of order: b would be pruned unread
        open(path, "w").write(bad)
        with pytest.raises(hubmod.StateCorrupt):
            hubmod.State(path)
    # a valid file with a deep backlog loads whole: nothing accepted is discarded at load
    q = [{"env": {"msg_id": envelope.new_id("msg"), "to": "x"}, "_seq": i + 1} for i in range(700)]
    open(path, "w").write(json.dumps({"queues": {"fp": q}, "seq": {"fp": 700}}))  # a counter that covers its queue
    st = hubmod.State(path)
    assert len(st.queues["fp"]) == 700 and all("_bytes" in m for m in st.queues["fp"])


def test_a_refused_send_goes_again_as_the_envelope_it_built(tmp_path, hub, principal):
    """One ratchet step per message, however many passes the hub refuses
    it: the envelope built for a 429'd send is kept in the request file
    and sent as the same bytes when there is room."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    hub.state.QUEUE_MAX_MSGS = 1
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "first"})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "second"})
    n1.step()  # one accepted, one refused for room
    assert "retry" in outcomes(n1, "msg.send")
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    req = json.load(open(os.path.join(n1.outbox_dir, f)))
    assert isinstance(req.get("env"), dict) and req["env"]["to_node"] == n2.fp  # the envelope it built, kept
    mid = req["env"]["msg_id"]
    pump([n2], 2)  # beta's node polls: room again
    n1._backoff = {}  # the wait the hub asked for is over
    n1._rcpt_backoff.clear()  # and the per-recipient verdict the refusal set
    n1.step()
    assert [m["env"]["msg_id"] for m in hub.state.queues.get(n2.fp, [])] == [mid]  # the same envelope, not a re-encryption
    pump([n2], 2)
    assert sorted(r["body"]["text"] for r in inbox(n2, "beta")) == ["first", "second"]  # both delivered (inbox order is by id, not arrival)


def test_a_poll_cursor_past_the_readable_range_is_refused_and_moves_nothing(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    before = hub.state.seq.get(n1.fp, 0)
    for after in (2 ** 53, 2 ** 52 + 1, -1):
        st, b = http("GET", hub.url + "/v1/poll/%s?after=%d" % (n1.fp, after),
                     headers={"X-Natively-Auth": n1._auth_token("poll", after=after)})
        assert st == 400 and "cursor" in b["error"]
    assert hub.state.seq.get(n1.fp, 0) == before  # the skew self-heal never ran on it
    st, b = http("GET", hub.url + "/v1/poll/%s?after=x" % n1.fp, headers={"X-Natively-Auth": n1._auth_token("poll", after=0)})
    assert st == 400
    st, b = http("GET", hub.url + "/v1/poll/%s?after=%d" % (n1.fp, 2 ** 52),
                 headers={"X-Natively-Auth": n1._auth_token("poll", after=2 ** 52)})
    assert st == 200  # the bound itself is a cursor the hub can still write and read back
    with hub.state.lock:
        hub.state.save(force=True)
    assert hubmod.State(hub.state.path).seq[n1.fp] == 2 ** 52


def test_an_envelope_that_can_never_fit_is_refused_before_it_is_parsed(tmp_path, hub, principal, monkeypatch):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    hub.state.QUEUE_MAX_BYTES = 4096
    parsed = []
    real = hubmod.jcs.loads
    monkeypatch.setattr(hubmod.jcs, "loads", lambda b: parsed.append(len(b)) or real(b))
    flat = ('{"msg_id": "%s", "type": "msg", "to": "%s", "n": [' % (envelope.new_id("msg"), agent_key(n2, "beta"))
            + ",".join(["1"] * 4000) + "]}")  # a flat array: many elements, no depth
    st, _ = http("POST", hub.url + "/v1/msg", flat.encode())
    assert st == 413 and parsed == []  # refused on its length; the reader never built an object from it


def test_shutdown_answers_an_oversized_request_before_dropping_it(tmp_path, hub, principal):
    import socket
    hub.state.closing = True
    try:
        host, port = hub.server.server_address
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(("POST /v1/msg HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n"
                   % (hubmod.MAX_BODY + 1)).encode() + b"{")
        head = s.recv(4096)
        s.close()
        assert head.startswith(b"HTTP/1.1 413")  # answered, not left hanging
    finally:
        hub.state.closing = False


def test_the_hubs_handlers_are_joined_before_the_final_flush(tmp_path):
    st = hubmod.State(str(tmp_path / "hub.json"))
    srv = hubmod.make_server(0, st)
    try:
        assert srv.daemon_threads is False  # server_close joins them: no handler outlives State.close
    finally:
        srv.server_close()
