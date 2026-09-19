import concurrent.futures
from natively.tasks import TaskConflict, TaskStore


def test_one_atomic_claim_wins_and_event_feed_is_ordered(tmp_path):
    store = TaskStore(tmp_path / "tasks.db")
    store.post("board", "producer", "tsk_1", "work", "blob:x", ["bill.extract.v1"])
    def claim(i):
        try:
            return store.transition("tsk_1", 1, "task.claim", "agent-%d" % i, "claim-%d" % i,
                                    ["bill.extract.v1"], lease_id="lease-%d" % i, lease_seconds=60)
        except TaskConflict:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(claim, range(50)))
    winners = [r for r in results if r]
    assert len(winners) == 1
    task = store.get("tsk_1")
    assert task["claim"]["agent"] == winners[0]["claim"]["agent"]
    events = store.events("board")
    assert [e["action"] for e in events] == ["task.post", "task.claim"]
    assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)


def test_idempotent_completion_and_owner_enforcement(tmp_path):
    store = TaskStore(tmp_path / "tasks.db")
    store.post("board", "producer", "tsk_1", "work", "blob:x")
    claimed = store.transition("tsk_1", 1, "task.claim", "worker", "claim", lease_id="lease", lease_seconds=60)
    try:
        store.transition("tsk_1", 2, "task.complete", "other", "bad", lease_id="lease", result_ref="blob:r")
        assert False
    except TaskConflict:
        pass
    done = store.transition("tsk_1", claimed["revision"], "task.complete", "worker", "done", lease_id="lease", result_ref="blob:r")
    replay = store.transition("tsk_1", claimed["revision"], "task.complete", "worker", "done", lease_id="lease", result_ref="blob:r")
    assert done == replay and done["state"] == "completed"
    assert len(store.events("board")) == 3


def test_expired_claim_reopens_with_incremented_attempt(tmp_path):
    now = [100.0]
    store = TaskStore(tmp_path / "tasks.db", clock=lambda: now[0])
    store.post("board", "producer", "tsk_1", "work", "blob:x")
    store.transition("tsk_1", 1, "task.claim", "one", "c1", lease_id="l1", lease_seconds=5)
    now[0] = 106
    # Expiry is materialized by the next CAS; its expected revision remains 2.
    second = store.transition("tsk_1", 2, "task.claim", "two", "c2", lease_id="l2", lease_seconds=5)
    assert second["claim"]["agent"] == "two" and second["claim"]["attempt"] == 2


def test_dependencies_capabilities_and_extensions(tmp_path):
    store = TaskStore(tmp_path / "tasks.db")
    store.post("board", "p", "dep", "dep", "blob:d")
    store.post("board", "p", "job", "job", "blob:j", ["bill.extract.v1"], ["dep"], extensions={"teale.market.v1": {"bid_ref": None}})
    for caps in ([], ["bill.extract.v1"]):
        try:
            store.transition("job", 1, "task.claim", "w", "try-" + str(len(caps)), caps, lease_id="l", lease_seconds=5)
            assert False
        except TaskConflict:
            pass
    dep = store.transition("dep", 1, "task.claim", "w", "dc", lease_id="dl", lease_seconds=5)
    store.transition("dep", dep["revision"], "task.complete", "w", "dd", lease_id="dl", result_ref="blob:r")
    job = store.transition("job", 1, "task.claim", "w", "jc", ["bill.extract.v1"], lease_id="jl", lease_seconds=5)
    assert job["extensions"]["teale.market.v1"] == {"bid_ref": None}

def test_repeated_claim_races_never_double_win(tmp_path):
    store = TaskStore(tmp_path / "tasks.db")
    for round_no in range(100):
        task_id = "tsk_%d" % round_no
        store.post("board", "p", task_id, "work", "blob:x")
        def race(i):
            try:
                store.transition(task_id, 1, "task.claim", "a%d" % i,
                                 "r%d-%d" % (round_no, i), lease_id="l%d" % i,
                                 lease_seconds=60)
                return 1
            except TaskConflict:
                return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            assert sum(pool.map(race, range(20))) == 1
