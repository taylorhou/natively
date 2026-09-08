"""Retry-sweep bounds: an unacked backlog must not starve flush/poll.
96's daemon went dark ~20 min behind a ~27k unacked sweep in the
plane-test-1 soak - no cap, and every dead-letter rewrote the whole
state file."""
from conftest import make_node


def _plant_unacked(node, count, attempts=1):
    for i in range(count):
        node.state["unacked"]["m%04d" % i] = {
            "env": {"msg_id": "m%04d" % i}, "attempts": attempts,
            "next": 0, "peer_fp": "peer"}


def test_retry_sweep_processes_at_most_100_due(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    _plant_unacked(n1, 150)
    posts = []
    n1._hub_req = lambda *a, **k: (posts.append(a), (200, b"{}"))[1]
    n1._retries()
    assert len(posts) == 100
    left = [r for r in n1.state["unacked"].values() if r["attempts"] == 1]
    assert len(left) == 50
    # the next sweep picks up the remainder
    n1._retries()
    assert len(posts) == 150


def test_dead_letters_pop_and_save_state_once(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    _plant_unacked(n1, 50, attempts=3)
    saves = []
    orig = n1._save_state
    n1._save_state = lambda: (saves.append(1), orig())[1]
    n1._retries()
    assert n1.state["unacked"] == {}
    assert saves == [1]
    from conftest import outcomes
    assert outcomes(n1, "msg.undelivered") == ["dead"] * 50


def test_sweep_timebox_stops_mid_batch(tmp_path, hub, principal):
    # a slow hub must not hold the sweep past the budget: remaining due
    # entries wait for the next step so polling (ack intake) is never
    # more than ~budget behind
    import time as _time
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    _plant_unacked(n1, 60)
    posts = []

    def slow(*a, **k):
        _time.sleep(0.15)
        posts.append(a)
        return (200, b"{}")

    n1._hub_req = slow
    t0 = _time.time()
    n1._retries()
    elapsed = _time.time() - t0
    assert elapsed < 10  # 60 * 0.15s unboxed would be 9s; the box must cut it well short
    assert len(posts) < 60


def test_deep_backlog_stretches_backoff(tmp_path, hub, principal):
    # depth above BACKOFF_SCALE_DEPTH multiplies the next-retry delay so a
    # deep table re-POSTs each entry proportionally less often
    from natively.node import P
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    _plant_unacked(n1, 10001)  # scale = 2
    n1._hub_req = lambda *a, **k: (200, b"{}")
    n1._retries()
    rec = n1.state["unacked"]["m0000"]
    assert rec["attempts"] == 2
    import time as _time
    assert rec["next"] > _time.time() + (2 ** 2) * P  # strictly beyond the unscaled backoff


def test_shallow_backlog_backoff_unchanged(tmp_path, hub, principal):
    from natively.node import P
    import time as _time
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    _plant_unacked(n1, 10)  # scale = 1
    n1._hub_req = lambda *a, **k: (200, b"{}")
    n1._retries()
    rec = n1.state["unacked"]["m0000"]
    assert rec["next"] <= _time.time() + (2 ** 2) * P + 1
