"""Hub authentication (review 2026-09-07, point 1): prekey bundles are
bound to the key that signed them, registration carries verified cards,
polls are node-signed."""
import json
import time

from natively import crypto, envelope, hub as hubmod, jcs

from conftest import http, make_node, signed, start_hub


def _bundle(seed, name="n"):
    spk = crypto.x_gen()
    b = {"node_key": "ed25519:" + crypto.b64e(crypto.sign_pub(seed)), "name": name,
         "spk_x": crypto.b64e(crypto.x_pub(spk)), "ts": envelope.now_iso()}
    b["spk_sig"] = crypto.b64e(crypto.sign(seed, crypto.b64d(b["spk_x"])))
    return signed(b, seed)


def _fp(seed):
    return jcs.sha256(crypto.sign_pub(seed))[:32]


def _card(agent_seed, node_seed, principal, caps=("test.ping",)):
    return envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, list(caps), "")


def _register(node_seed, agents, name="n", ts=None):
    reg = {"node_key": "ed25519:" + crypto.b64e(crypto.sign_pub(node_seed)), "name": name,
           "ts": ts or envelope.now_iso(), "agents": agents}
    return signed(reg, node_seed)


def _poll_token(node_seed, fp, after, op="poll", ts=None):
    tok = signed({"op": op, "fp": fp, "after": after, "ts": ts or envelope.now_iso()}, node_seed)
    return {"X-Natively-Auth": crypto.b64e(json.dumps(tok).encode())}


# ---------- prekeys ----------

def test_prekey_bundle_is_stored_only_under_its_signers_fingerprint(hub):
    victim, attacker = crypto.gen_signing_key(), crypto.gen_signing_key()
    st, b = http("PUT", hub.url + "/v1/prekey/" + _fp(victim), _bundle(victim))
    assert st == 200
    # a bundle signed by the attacker, PUT under the victim's fingerprint
    st, b = http("PUT", hub.url + "/v1/prekey/" + _fp(victim), _bundle(attacker))
    assert st == 400 and "does not match" in b["error"]
    st, got = http("GET", hub.url + "/v1/prekey/" + _fp(victim))
    assert got["node_key"] == "ed25519:" + crypto.b64e(crypto.sign_pub(victim))
    # the attacker's own fingerprint is fine
    st, _ = http("PUT", hub.url + "/v1/prekey/" + _fp(attacker), _bundle(attacker))
    assert st == 200


def test_prekey_bundle_with_bad_signature_is_refused(hub):
    seed = crypto.gen_signing_key()
    b = _bundle(seed)
    b["spk_x"] = crypto.b64e(crypto.x_pub(crypto.x_gen()))  # tampered after signing
    st, r = http("PUT", hub.url + "/v1/prekey/" + _fp(seed), b)
    assert st == 400
    st, _ = http("PUT", hub.url + "/v1/prekey/" + _fp(seed), {"node_key": 5, "sig": []})
    assert st == 400


# ---------- registration ----------

def test_register_requires_cards_that_name_this_node_and_agent(hub, principal):
    node, other, agent = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    good = _card(agent, node, principal)
    st, r = http("POST", hub.url + "/v1/register", _register(node, [{"name": "a", "agent_key": good["agent_key"], "card": good}]))
    assert st == 200 and r["node_fp"] == _fp(node)
    # card issued for a different node
    wrong_node = _card(agent, other, principal)
    st, r = http("POST", hub.url + "/v1/register", _register(node, [{"name": "a", "agent_key": wrong_node["agent_key"], "card": wrong_node}]))
    assert st == 400 and "node_key" in r["error"]
    # registered agent key differs from the card's
    st, r = http("POST", hub.url + "/v1/register", _register(node, [{"name": "a", "agent_key": "ed25519:" + crypto.b64e(crypto.sign_pub(other)), "card": good}]))
    assert st == 400 and "agent_key" in r["error"]
    # card whose signature does not verify
    forged = dict(good, capabilities=["node.config.set"])
    st, r = http("POST", hub.url + "/v1/register", _register(node, [{"name": "a", "agent_key": forged["agent_key"], "card": forged}]))
    assert st == 400 and "not verified" in r["error"]
    # the directory still holds the one good registration
    st, d = http("GET", hub.url + "/v1/directory")
    assert list(d["agents"]) == ["a@" + _fp(node)]


def test_register_rejects_stale_timestamp_and_missing_ts(hub, principal):
    node, agent = crypto.gen_signing_key(), crypto.gen_signing_key()
    card = _card(agent, node, principal)
    agents = [{"name": "a", "agent_key": card["agent_key"], "card": card}]
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    st, r = http("POST", hub.url + "/v1/register", _register(node, agents, ts=old))
    assert st == 400 and "ts" in r["error"]
    reg = _register(node, agents)
    del reg["ts"]
    reg = signed(reg, node)
    st, r = http("POST", hub.url + "/v1/register", reg)
    assert st == 400


def test_register_principal_allowlist(tmp_path, principal):
    other = type(principal)()
    h = start_hub(tmp_path, principal_roots=[principal.pub])
    try:
        node, agent = crypto.gen_signing_key(), crypto.gen_signing_key()
        card = _card(agent, node, other)
        st, r = http("POST", h.url + "/v1/register", _register(node, [{"name": "a", "agent_key": card["agent_key"], "card": card}]))
        assert st == 400 and "root set" in r["error"]
        card = _card(agent, node, principal)
        st, r = http("POST", h.url + "/v1/register", _register(node, [{"name": "a", "agent_key": card["agent_key"], "card": card}]))
        assert st == 200
    finally:
        h.close()


def test_agent_key_moves_between_nodes_only_with_a_superseding_card(hub, principal):
    node_a, node_b, agent = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    card_a = _card(agent, node_a, principal)
    st, _ = http("POST", hub.url + "/v1/register", _register(node_a, [{"name": "a", "agent_key": card_a["agent_key"], "card": card_a}], name="A"))
    assert st == 200
    # node B claims the same agent key with a fresh card: refused
    card_b = _card(agent, node_b, principal)
    st, r = http("POST", hub.url + "/v1/register", _register(node_b, [{"name": "a", "agent_key": card_b["agent_key"], "card": card_b}], name="B"))
    assert st == 409
    assert hub.state.agent_owner[card_a["agent_key"].split(":", 1)[1]] == _fp(node_a)
    # a superseding card signed by ANOTHER principal: refused - the move
    # needs the word of the principal whose card is on file
    other = type(principal)()
    card_x = envelope.make_card(agent, crypto.sign_pub(node_b), other.seed, ["test.ping"], "",
                                supersedes=envelope.obj_hash(card_a))
    st, r = http("POST", hub.url + "/v1/register", _register(node_b, [{"name": "a", "agent_key": card_x["agent_key"], "card": card_x}], name="B"))
    assert st == 409
    assert hub.state.agent_owner[card_a["agent_key"].split(":", 1)[1]] == _fp(node_a)
    # with a card that supersedes the one on file, same principal: allowed,
    # and the old node's directory entry for that key is gone with it
    card_b2 = envelope.make_card(agent, crypto.sign_pub(node_b), principal.seed, ["test.ping"], "",
                                 supersedes=envelope.obj_hash(card_a))
    st, r = http("POST", hub.url + "/v1/register", _register(node_b, [{"name": "a", "agent_key": card_b2["agent_key"], "card": card_b2}], name="B"))
    assert st == 200
    assert hub.state.agent_owner[card_a["agent_key"].split(":", 1)[1]] == _fp(node_b)
    _, d = http("GET", hub.url + "/v1/directory")
    holders = [n for n, v in d["agents"].items() if v["agent_key"] == card_a["agent_key"]]
    assert holders == ["a@" + _fp(node_b)]
    assert d["agents"]["a@" + _fp(node_b)]["card"] == card_b2


def test_registration_replay_cannot_roll_the_agent_set_back(hub, principal):
    node, a1, a2 = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    c1, c2 = _card(a1, node, principal), _card(a2, node, principal)
    one = [{"name": "one", "agent_key": c1["agent_key"], "card": c1}]
    both = one + [{"name": "two", "agent_key": c2["agent_key"], "card": c2}]
    t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10))
    t1 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
    earlier = _register(node, one, ts=t0)   # captured: one agent
    later = _register(node, both, ts=t1)    # the current set: two agents
    assert http("POST", hub.url + "/v1/register", earlier)[0] == 200
    assert http("POST", hub.url + "/v1/register", later)[0] == 200
    # replaying the earlier registration (still inside the window) is refused
    st, r = http("POST", hub.url + "/v1/register", earlier)
    assert st == 409 and "newer" in r["error"]
    # so is the same registration twice
    assert http("POST", hub.url + "/v1/register", later)[0] == 409
    _, d = http("GET", hub.url + "/v1/directory")
    assert sorted(d["agents"]) == ["one@" + _fp(node), "two@" + _fp(node)]


def test_reregistration_replaces_the_agent_set(hub, principal):
    node, a1, a2 = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    c1, c2 = _card(a1, node, principal), _card(a2, node, principal)
    both = [{"name": "one", "agent_key": c1["agent_key"], "card": c1}, {"name": "two", "agent_key": c2["agent_key"], "card": c2}]
    assert http("POST", hub.url + "/v1/register", _register(node, both))[0] == 200
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1))  # registrations apply in ts order
    assert http("POST", hub.url + "/v1/register", _register(node, both[:1], ts=later))[0] == 200
    _, d = http("GET", hub.url + "/v1/directory")
    assert list(d["agents"]) == ["one@" + _fp(node)]
    assert c2["agent_key"].split(":", 1)[1] not in hub.state.agent_owner


# ---------- polling ----------

def _enqueue(hub, fp, n):
    with hub.state.lock:
        for i in range(n):
            hub.state.seq[fp] = hub.state.seq.get(fp, 0) + 1
            hub.state.queues.setdefault(fp, []).append({"env": {"msg_id": "msg_%d" % i}, "_seq": hub.state.seq[fp]})
            hub.state.qids.setdefault(fp, set()).add("msg_%d" % i)


def test_poll_requires_a_token_signed_by_the_registered_node(hub, principal):
    victim, attacker, agent = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    for seed, name in ((victim, "V"), (attacker, "A")):
        card = _card(agent if seed is victim else crypto.gen_signing_key(), seed, principal)
        assert http("POST", hub.url + "/v1/register", _register(seed, [{"name": "a", "agent_key": card["agent_key"], "card": card}], name=name))[0] == 200
    vfp = _fp(victim)
    _enqueue(hub, vfp, 3)
    # no token
    st, r = http("GET", hub.url + "/v1/poll/%s?after=0" % vfp)
    assert st == 401
    # attacker's token over the victim's fingerprint, with a high cursor
    st, r = http("GET", hub.url + "/v1/poll/%s?after=999" % vfp, headers=_poll_token(attacker, vfp, 999))
    assert st == 401
    st, r = http("GET", hub.url + "/v1/poll/%s?after=999" % vfp, headers=_poll_token(attacker, _fp(attacker), 999))
    assert st == 401
    assert len(hub.state.queues[vfp]) == 3  # nothing pruned
    # token over a different cursor than the request
    st, r = http("GET", hub.url + "/v1/poll/%s?after=999" % vfp, headers=_poll_token(victim, vfp, 1))
    assert st == 401
    # stale token
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    st, r = http("GET", hub.url + "/v1/poll/%s?after=0" % vfp, headers=_poll_token(victim, vfp, 0, ts=old))
    assert st == 401
    # the victim itself reads, then prunes with its own cursor
    st, r = http("GET", hub.url + "/v1/poll/%s?after=0" % vfp, headers=_poll_token(victim, vfp, 0))
    assert st == 200 and [m["env"]["msg_id"] for m in r["messages"]] == ["msg_0", "msg_1", "msg_2"]
    st, r = http("GET", hub.url + "/v1/poll/%s?after=2" % vfp, headers=_poll_token(victim, vfp, 2))
    assert st == 200 and [m["env"]["msg_id"] for m in r["messages"]] == ["msg_2"]
    assert len(hub.state.queues[vfp]) == 1


def test_poll_of_an_unregistered_node_is_refused(hub):
    seed = crypto.gen_signing_key()
    st, r = http("GET", hub.url + "/v1/poll/%s?after=0" % _fp(seed), headers=_poll_token(seed, _fp(seed), 0))
    assert st == 401 and r["error"] == "unknown node"


def test_registration_order_survives_a_hub_restart(tmp_path, principal):
    h = start_hub(tmp_path)
    try:
        node, a1, a2 = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
        c1, c2 = _card(a1, node, principal), _card(a2, node, principal)
        one = [{"name": "one", "agent_key": c1["agent_key"], "card": c1}]
        both = one + [{"name": "two", "agent_key": c2["agent_key"], "card": c2}]
        t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10))
        t1 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
        earlier, later = _register(node, one, ts=t0), _register(node, both, ts=t1)
        assert http("POST", h.url + "/v1/register", earlier)[0] == 200
        assert http("POST", h.url + "/v1/register", later)[0] == 200  # inside the save throttle window
        state_path = h.state.path
    finally:
        h.close()
    assert json.load(open(state_path))["nodes"][_fp(node)]["reg_ts"] == t1  # on disk before the 200
    h = start_hub(tmp_path, state_path=state_path)
    try:
        assert http("POST", h.url + "/v1/register", earlier)[0] == 409
        _, d = http("GET", h.url + "/v1/directory")
        assert sorted(d["agents"]) == ["one@" + _fp(node), "two@" + _fp(node)]
    finally:
        h.close()


def test_envelope_for_a_node_the_recipient_left_is_refused(hub, principal):
    node_a, node_b, agent, sender = (crypto.gen_signing_key() for _ in range(4))
    card_a = _card(agent, node_a, principal)
    assert http("POST", hub.url + "/v1/register", _register(node_a, [{"name": "a", "agent_key": card_a["agent_key"], "card": card_a}], name="A"))[0] == 200
    env = {"msg_id": envelope.new_id("msg"), "to": card_a["agent_key"], "to_node": _fp(node_a), "body": ""}
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200
    card_b = envelope.make_card(agent, crypto.sign_pub(node_b), principal.seed, ["test.ping"], "", supersedes=envelope.obj_hash(card_a))
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1))
    assert http("POST", hub.url + "/v1/register", _register(node_b, [{"name": "a", "agent_key": card_b["agent_key"], "card": card_b}], name="B", ts=later))[0] == 200
    st, r = http("POST", hub.url + "/v1/msg", dict(env, msg_id=envelope.new_id("msg")))
    assert st == 409 and r["node_fp"] == _fp(node_b)
    assert http("POST", hub.url + "/v1/msg", dict(env, msg_id=envelope.new_id("msg"), to_node=_fp(node_b)))[0] == 200
    assert len(hub.state.queues.get(_fp(node_b), [])) == 1
