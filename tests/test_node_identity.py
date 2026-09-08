"""Node-side identity binding (review 2026-09-07, point 1): the hub is a
lookup, never an authority. Sender and recipient nodes come from
principal-signed cards under the pinned root set; prekey bundles must be
signed by the node the card names."""
import os
import time

from natively import crypto, envelope, jcs

import json

from natively import node as nodemod

from conftest import Principal, agent_key, inbox, make_node, outcomes, pump


def test_two_nodes_exchange_a_message_and_an_ack(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["test.ping", "msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hello from alpha"})
    pump([n1, n2], 4)
    recs = inbox(n2, "beta")
    assert [r["body"]["text"] for r in recs] == ["hello from alpha"]
    assert recs[0]["from"] == agent_key(n1, "alpha")
    assert outcomes(n1, "msg.ack") == ["ok"]
    assert n1.state["unacked"] == {}


def test_sender_card_from_an_unknown_principal_is_rejected(tmp_path, hub, principal):
    stranger = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, stranger, {"alpha": ["msg.send"]}, roots=[stranger.pub, principal.pub])
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    # n1 trusts both principals; n2 pins only its own; the hub accepted
    # n1 (no allowlist), so the refusal is n2's own
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hi"})
    pump([n1, n2], 3)
    assert inbox(n2, "beta") == []
    assert "rejected-bad-card" in outcomes(n2, "msg.recv")
    # and n2 will not open a session toward n1 either
    n2.queue_send("beta", agent_key(n1, "alpha"), {"kind": "text", "text": "back"})
    pump([n2], 1)
    assert "error" in outcomes(n2, "msg.send")
    assert not os.path.exists(os.path.join(n2.home, "sessions", "to_" + n1.fp + ".json"))


def test_sender_card_from_a_pinned_second_root_is_accepted(tmp_path, hub, principal):
    other = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, other, {"alpha": ["msg.send"]}, roots=[other.pub, principal.pub])
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]}, roots=[principal.pub, other.pub])
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hi"})
    pump([n1, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["hi"]


def test_hub_directory_tampering_does_not_redirect_a_message(tmp_path, hub, principal):
    """A malicious hub points beta's directory entry at the attacker's node.
    The sender derives the node from beta's card, so the envelope still
    routes (by agent key) to beta's node; and a swapped card is refused."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"mallory": ["msg.send"]})
    beta = agent_key(n2, "beta")
    with hub.state.lock:
        entry = hub.state.agent_dir["beta@" + n2.fp]
        entry["node_fp"] = n3.fp  # routing field lies
    n1.queue_send("alpha", beta, {"kind": "text", "text": "for beta"})
    pump([n1], 1)
    assert n1.state["unacked"] and list(n1.state["unacked"].values())[0]["peer_fp"] == n2.fp
    # now swap the card for one that names mallory's node: refused, no session
    with hub.state.lock:
        entry["card"] = envelope.make_card(n3.agents["mallory"]["seed"], n3.node_pub, principal.seed, ["msg.send"], "")
    n1._dir_cache = (0.0, None)
    n1.queue_send("alpha", beta, {"kind": "text", "text": "again"})
    pump([n1], 1)
    assert "error" in outcomes(n1, "msg.send")
    assert not os.path.exists(os.path.join(n1.home, "sessions", "to_" + n3.fp + ".json"))


def test_substituted_prekey_bundle_is_refused(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    attacker = crypto.gen_signing_key()
    spk = crypto.x_gen()
    b = {"node_key": "ed25519:" + crypto.b64e(crypto.sign_pub(attacker)), "name": "n2",
         "spk_x": crypto.b64e(crypto.x_pub(spk)), "ts": envelope.now_iso()}
    b["spk_sig"] = crypto.b64e(crypto.sign(attacker, crypto.b64d(b["spk_x"])))
    with hub.state.lock:
        hub.state.prekeys[n2.fp] = envelope.sign_obj(b, attacker)  # the hub (or its operator) swaps it
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "secret"})
    pump([n1], 1)
    assert n1.state["unacked"] == {}
    assert "error" in outcomes(n1, "msg.send")
    assert not os.path.exists(os.path.join(n1.home, "sessions", "to_" + n2.fp + ".json"))


def test_empty_principal_pin_refuses_to_start(tmp_path, hub, principal):
    from natively import node as nodemod
    home = str(tmp_path / "n0")
    nodemod.init_node(home, "n0", hub.url, principal.pub)
    open(os.path.join(home, "principal.pub"), "w").close()
    try:
        nodemod.Node(home)
    except ValueError as e:
        assert "pinned principal root" in str(e)
    else:
        raise AssertionError("node started without a principal root")


def test_peer_that_registered_after_the_directory_was_cached_is_not_rejected(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    d = n1._directory()
    n1._dir_cache = (time.time() + 100, d)  # a copy that looks fresh: n3 is not in it
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    n3.queue_send("gamma", agent_key(n1, "alpha"), {"kind": "text", "text": "new here"})
    pump([n3, n1], 3)
    assert [r["body"]["text"] for r in inbox(n1, "alpha")] == ["new here"]
    assert "rejected-bad-card" not in outcomes(n1, "msg.recv")


def test_send_to_an_agent_not_yet_registered_waits_in_the_outbox(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]}, start=False)
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "early"})
    pump([n1], 2)
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]  # still queued, not .err
    assert not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    assert "error" not in outcomes(n1, "msg.send")
    n2.start()
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["early"]
    assert os.listdir(n1.outbox_dir) == []


def test_fast_restart_registers_again_without_dying(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n2.stop()
    n2b = nodemod.Node(n2.home)
    n2b.start()  # same second as the previous registration: no exception
    # until the wall clock passes the last ts the node waits (never runs ahead of the clock)
    while int(time.time()) <= n2.state["reg_ts"]:
        n2b.step()
        time.sleep(0.05)
    n2b.step()
    assert n2b.state["reg_ts"] > n2.state["reg_ts"]
    assert hub.state.nodes[n2b.fp]["reg_ts"] == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(n2b.state["reg_ts"]))
    n1.queue_send("alpha", agent_key(n2b, "beta"), {"kind": "text", "text": "after restart"})
    pump([n1, n2b], 4)
    assert [r["body"]["text"] for r in inbox(n2b, "beta")] == ["after restart"]


def test_unregistered_node_neither_sends_nor_polls(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    hub.state.principal_roots = {Principal().pub}  # the hub now refuses our principal's cards
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    assert n2._last_reg_time == 0 and "retry" in outcomes(n2, "node.register")
    calls = []
    real_http = nodemod._http

    def logged(method, url, *a, **kw):
        calls.append((method, url))
        return real_http(method, url, *a, **kw)

    monkeypatch.setattr(nodemod, "_http", logged)
    n2.queue_send("beta", agent_key(n1, "alpha"), {"kind": "text", "text": "too early"})
    pump([n2], 2)
    assert [f for f in os.listdir(n2.outbox_dir) if f.endswith(".json")]  # held, not sent
    assert hub.state.queues.get(n1.fp, []) == []
    assert not [u for m, u in calls if "/v1/poll/" in u or u.endswith("/v1/msg")]  # neither polled nor posted
    hub.state.principal_roots = set()
    while int(time.time()) <= n2.state["reg_ts"]:
        time.sleep(0.05)
    pump([n2, n1], 4)
    assert [r["body"]["text"] for r in inbox(n1, "alpha")] == ["too early"]


def test_unknown_recipient_at_the_hub_waits_in_the_outbox(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    d = n1._directory()
    n1._dir_cache = (time.time() + 100, d)
    beta = agent_key(n2, "beta")
    with hub.state.lock:  # the hub forgot beta (a registration gap)
        hub.state.agent_owner.pop(beta.split(":", 1)[1])
    n1.queue_send("alpha", beta, {"kind": "text", "text": "gap"})
    pump([n1], 1)
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")] and not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    with hub.state.lock:
        hub.state.agent_owner[beta.split(":", 1)[1]] = n2.fp
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["gap"]


def test_issuers_installed_under_principals_dir_are_pinned(tmp_path, hub, principal):
    other = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, other, {"alpha": ["msg.send"]}, roots=[other.pub, principal.pub])
    home2 = str(tmp_path / "n2")
    nodemod.init_node(home2, "n2", hub.url, principal.pub)
    os.makedirs(os.path.join(home2, "principals"))
    with open(os.path.join(home2, "principals", "other.pub"), "w") as f:
        f.write(other.pub + "\n")
    nodemod.add_agent(home2, "beta", principal.seed, ["msg.send"])
    n2 = nodemod.Node(home2)
    n2.start()
    assert n2.principal_roots == {principal.pub, other.pub} and n2.principal_pub == principal.pub
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "from other's agent"})
    pump([n1, n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["from other's agent"]


def test_agent_move_between_nodes_is_delivered_after_the_move(tmp_path, hub, principal):
    """beta moves from nA to nB (same agent key, a superseding card). A
    sender whose directory copy still says nA gets 409 from the hub,
    refreshes, re-encrypts for nB and the message arrives there."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    na = make_node(tmp_path, "na", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(na, "beta"), {"kind": "text", "text": "before"})
    pump([n1, na], 3)
    assert [r["body"]["text"] for r in inbox(na, "beta")] == ["before"]
    d = n1._directory()
    n1._dir_cache = (time.time() + 100, d)  # n1 keeps believing beta is on na
    # beta's key and a superseding card land on nb; na is gone
    home_b = str(tmp_path / "nb")
    nodemod.init_node(home_b, "nb", hub.url, principal.pub)
    nb0 = nodemod.Node(home_b)
    seed = na.agents["beta"]["seed"]
    card_b = envelope.make_card(seed, nb0.node_pub, principal.seed, ["msg.send"], "", supersedes=envelope.obj_hash(na.agents["beta"]["card"]))
    adir = os.path.join(home_b, "agents")
    os.makedirs(adir, exist_ok=True)
    open(os.path.join(adir, "beta.key"), "w").write(seed.hex())
    json.dump(card_b, open(os.path.join(adir, "beta.card.json"), "w"))
    na.stop()
    nb = nodemod.Node(home_b)
    nb.start()
    assert hub.state.agent_owner[card_b["agent_key"].split(":", 1)[1]] == nb.fp
    n1.queue_send("alpha", card_b["agent_key"], {"kind": "text", "text": "after"})
    pump([n1], 1)  # encrypted for na, refused 409, cache dropped, still queued
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")] and not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    pump([n1, nb], 4)
    assert [r["body"]["text"] for r in inbox(nb, "beta")] == ["after"]
    assert n1.state["unacked"] == {}


def test_failed_provisional_session_does_not_block_the_real_handshake(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    # a ciphertext n3 made for n2, wrapped in an envelope signed by n1's alpha:
    # n2 opens a provisional session with n1 from it and the decryption fails
    ct = n3._enc_pairwise(n2.fp, {"kind": "text", "text": "wrong"})
    a = n1.agents["alpha"]
    env = envelope.make_message(a["card"]["agent_key"].split(":", 1)[1], agent_key(n2, "beta").split(":", 1)[1], ct, a["seed"],
                                extra={"to": agent_key(n2, "beta"), "to_node": n2.fp})
    from conftest import http
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200
    pump([n2], 2)
    assert "error" in outcomes(n2, "msg.recv")
    assert "from:" + n1.fp not in n2.sessions and not os.path.exists(os.path.join(n2.home, "sessions", "from_" + n1.fp + ".json"))
    # the real handshake from n1 now works
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "real"})
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["real"]


class _Clock:
    """time.time under test control; everything else on the module is real."""
    def __init__(self, t):
        self.t = t

    def time(self):
        return self.t

    def __getattr__(self, name):
        return getattr(time, name)


def test_agent_added_inside_the_registration_second_waits_for_its_registration(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    clock = _Clock(int(time.time()) + 0.5)
    monkeypatch.setattr(nodemod, "time", clock)  # the node's clock is frozen mid-second; the hub keeps the real one
    n2.state["reg_ts"] = int(clock.time())  # the last registration was this very second: the next must wait for the clock
    nodemod.add_agent(n2.home, "delta", principal.seed, ["msg.send"])
    n2.step()  # picks delta up; re-registration waits; delta is not in the hub's directory yet
    assert "delta" in n2.agents and "delta" not in n2._last_registered
    n2.queue_send("delta", agent_key(n1, "alpha"), {"kind": "text", "text": "from delta"})
    n2.queue_send("beta", agent_key(n1, "alpha"), {"kind": "text", "text": "from beta"})
    pump([n2], 1)
    held = [json.load(open(os.path.join(n2.outbox_dir, f)))["from_agent"] for f in os.listdir(n2.outbox_dir) if f.endswith(".json")]
    assert held == ["delta"]  # beta's went out, delta's waits for the registration that carries delta
    pump([n2], 2)
    assert "delta" not in n2._last_registered  # still the same second: nothing has moved
    clock.t += 1  # the next whole second: the registration carrying delta goes out
    pump([n2, n1], 4)
    assert "delta" in n2._last_registered
    assert sorted(r["body"]["text"] for r in inbox(n1, "alpha")) == ["from beta", "from delta"]
    assert not [f for f in os.listdir(n2.outbox_dir) if f.endswith(".err")]


def test_sender_moved_inside_the_cache_lifetime_is_re_resolved_and_read(tmp_path, hub, principal):
    """The receiver holds an established session from node A. The sender
    agent moves to node B and B's first ciphertext arrives while the
    receiver's directory cache still says A: A's session must not be
    advanced by the failed attempt, and the envelope is read from B."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"], "omega": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"], "gamma": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "one"})
    n1.queue_send("alpha", agent_key(n2, "gamma"), {"kind": "text", "text": "to gamma"})
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["one"]
    before = n2._session("from", n1.fp).to_state()
    # alpha moves to a third node under a superseding card from the same principal
    n3 = make_node(tmp_path, "n3", hub.url, principal, start=False)
    seed = n1.agents["alpha"]["seed"]
    card = envelope.make_card(seed, n3.node_pub, principal.seed, ["msg.send"], "file:///dev/null",
                              supersedes=envelope.obj_hash(n1.agents["alpha"]["card"]))
    nodemod._w600(os.path.join(n3.home, "agents", "alpha.key"), seed.hex().encode())
    nodemod._w600(os.path.join(n3.home, "agents", "alpha.card.json"), json.dumps(card).encode())
    n3 = nodemod.Node(n3.home)
    n3.start()
    assert hub.state.agent_owner[card["agent_key"].split(":", 1)[1]] == n3.fp
    n2._dir_cache = (time.time() + 100, n2._dir_cache[1] or n2._directory())  # n2 still believes alpha lives on n1
    n3.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "from n3"})
    pump([n3, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["one", "from n3"]
    # n1's session was not advanced by the failed attempt: it is the last
    # saved state, and a message from n1's other agent still reads
    assert n2._session("from", n1.fp).to_state() == before
    n1.queue_send("omega", agent_key(n2, "gamma"), {"kind": "text", "text": "still n1"})
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "gamma")] == ["to gamma", "still n1"]


def _move_agent(tmp_path, hub, principal, src, agent, new_name, caps=("msg.send",)):
    """Move `agent` from node `src` to a fresh node under a card that
    supersedes the one on file (the same principal signs both); the
    agent's files leave `src`. Returns the started new node."""
    n3 = make_node(tmp_path, new_name, hub.url, principal, start=False)
    seed = src.agents[agent]["seed"]
    card = envelope.make_card(seed, n3.node_pub, principal.seed, list(caps), "file:///dev/null",
                              supersedes=envelope.obj_hash(src.agents[agent]["card"]))
    nodemod._w600(os.path.join(n3.home, "agents", agent + ".key"), seed.hex().encode())
    nodemod._w600(os.path.join(n3.home, "agents", agent + ".card.json"), json.dumps(card).encode())
    n3 = nodemod.Node(n3.home)
    n3.start()
    assert hub.state.agent_owner[card["agent_key"].split(":", 1)[1]] == n3.fp
    for f in (agent + ".key", agent + ".card.json"):
        os.unlink(os.path.join(src.home, "agents", f))
    return n3


def test_a_send_to_an_agent_that_left_this_node_is_not_delivered_in_place(tmp_path, hub, principal, monkeypatch):
    """The loopback shortcut trusts the directory cache. After the
    recipient moved, a cached card still names this node: the send must
    wait for a fresh answer, never be consumed by a local delivery to
    nobody or dropped."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"], "omega": ["msg.send"]})
    omega = agent_key(n1, "omega")
    stale = n1._directory()
    n3 = _move_agent(tmp_path, hub, principal, n1, "omega", "n3")
    n1._dir_cache = (time.time() + 100, stale)  # n1 still believes omega is here
    n1.queue_send("alpha", omega, {"kind": "text", "text": "after the move"})
    pump([n1], 1)
    assert [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]  # held, not consumed
    assert not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".err")]
    assert not os.path.isdir(os.path.join(n1.home, "inbox", "omega"))
    pump([n1, n3], 4)  # the cache was dropped: the next pass resolves omega on n3
    assert [r["body"]["text"] for r in inbox(n3, "omega")] == ["after the move"]
    assert not [f for f in os.listdir(n1.outbox_dir) if f.endswith(".json") or f.endswith(".err")]


def test_an_ack_read_after_re_resolving_the_sender_clears_its_message(tmp_path, hub, principal):
    """The ack for a message to a moved agent arrives while the sender's
    directory cache still names the old node: the preview fails, the
    envelope is re-resolved and read from the new node, and it is an ack -
    it clears the outstanding message and is never filed as a message."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n2.queue_send("beta", agent_key(n1, "alpha"), {"kind": "text", "text": "one"})
    pump([n2, n1], 4)
    assert n2.state["unacked"] == {}
    stale = n2._directory()
    alpha = agent_key(n1, "alpha")
    n3 = _move_agent(tmp_path, hub, principal, n1, "alpha", "n3")
    n2._dir_cache = (0.0, None)  # the cache filled a moment ago still names n1: read the directory again
    n2.queue_send("beta", alpha, {"kind": "text", "text": "two"})
    n2.step()  # fresh directory: encrypted to n3, sent
    assert len(n2.state["unacked"]) == 1
    pump([n3], 2)  # read, then the ack goes out to the hub for n2
    n2._dir_cache = (time.time() + 100, stale)  # n2's cache says alpha is still on n1
    pump([n2], 2)
    assert n2.state["unacked"] == {}
    assert outcomes(n2, "msg.ack")[-1] == "ok"
    assert [r["body"].get("kind") for r in inbox(n2, "beta")] == []  # no ack filed as a message
    assert not [f for f in os.listdir(n2.outbox_dir) if f.endswith(".json")]  # and no ack of the ack


def test_an_agent_whose_files_are_gone_leaves_the_next_registration(tmp_path, hub, principal, monkeypatch):
    """An agent that moved away is removed from this node's agents
    directory. The daemon's snapshot must drop it, or every later
    registration claims a key another node owns and is refused (409)."""
    clock = _Clock(time.time())
    monkeypatch.setattr(nodemod, "time", clock)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"], "omega": ["msg.send"]})
    n3 = _move_agent(tmp_path, hub, principal, n1, "omega", "n3")
    nodemod.add_agent(n1.home, "delta", principal.seed, ["msg.send"])
    clock.t += 2  # past the registration second
    n1.step()
    assert set(n1.agents) == {"alpha", "delta"}
    assert n1._last_registered == {"alpha", "delta"}
    assert outcomes(n1, "node.register")[-1:] != ["retry"]
    d = hub.state.agent_dir
    assert {k.split("@")[0] for k, v in d.items() if v["node_fp"] == n1.fp} == {"alpha", "delta"}
    assert hub.state.agent_owner[agent_key(n3, "omega").split(":", 1)[1]] == n3.fp


def _install_grant(node, grant):
    d = os.path.join(node.home, "grants")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, grant["grant_id"] + ".json"), "w") as f:
        json.dump(grant, f)


def test_grant_from_a_pinned_second_root_executes(tmp_path, hub, principal):
    other = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, other, {"alpha": ["msg.send"]}, roots=[other.pub, principal.pub])
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]},
                   roots=[principal.pub, other.pub])
    g = envelope.make_grant(other.seed, "other", n2.agents["beta"]["card"],
                            n2.agents["beta"]["card"]["node_key"].split(":", 1)[1],
                            [{"action": "test.ping", "resource": ""}], "cross-principal ping", max_uses=1)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "", "params": {}},
                  grant_ids=[g["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == ["ok"]
    recs = inbox(n2, "beta")
    assert recs and outcomes(n2, "msg.recv")[-1] == "acted:test.ping"


def test_grant_from_an_unpinned_issuer_is_refused(tmp_path, hub, principal):
    stranger = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]})
    g = envelope.make_grant(stranger.seed, "stranger", n2.agents["beta"]["card"],
                            n2.agents["beta"]["card"]["node_key"].split(":", 1)[1],
                            [{"action": "test.ping", "resource": ""}], "forged ping", max_uses=1)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "", "params": {}},
                  grant_ids=[g["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == []
    assert "invalid" in outcomes(n2, "grant.check")
