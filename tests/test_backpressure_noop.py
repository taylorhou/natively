import json
from natively.node import IdentityError
from conftest import make_node


def test_prepared_relay_invalid_member_does_not_rewrite_or_log(tmp_path, hub, principal):
    n = make_node(tmp_path, 'n', hub.url, principal, {'alpha': ['msg.send']})
    req = {'from_agent': 'alpha', 'to': 'ed25519:primary',
           'body_obj': {'kind': 'group_relay', 'recipients': ['ed25519:primary', 'ed25519:old']},
           'env': {'msg_id': 'msg_saved', 'ciphertext': 'same-bytes'}}
    path = tmp_path / 'out_test.json'
    path.write_text(json.dumps(req))
    original = path.read_bytes()
    def invalid(k):
        raise IdentityError('card no longer verified')
    n._peer_card = invalid
    calls = []
    n.ledger.append = lambda *a, **kw: calls.append(a)
    for _ in range(3):
        assert n._split_relay(path.name, str(path), req, 'fp') is False
    assert path.read_bytes() == original
    assert calls == []


def test_prepared_relay_still_splits_a_new_moved_recipient(tmp_path, hub, principal):
    n = make_node(tmp_path, 'n', hub.url, principal, {'alpha': ['msg.send']})
    req = {'from_agent': 'alpha', 'to': 'ed25519:primary',
           'body_obj': {'kind': 'group_relay', 'recipients': ['ed25519:primary', 'ed25519:moved']},
           'env': {'msg_id': 'msg_saved', 'ciphertext': 'same-bytes'}}
    path = tmp_path / 'out_moved.json'
    path.write_text(json.dumps(req))
    n._peer_card = lambda k: (None, 'other-node')
    queued = []
    n.queue_send = lambda *a, **kw: queued.append((a, kw))
    assert n._split_relay(path.name, str(path), req, 'original-node') is True
    assert len(queued) == 1
    saved = json.loads(path.read_text())
    assert saved['env'] == {'msg_id': 'msg_saved', 'ciphertext': 'same-bytes'}
    assert saved['split'] == ['ed25519:moved']
    assert n._split_relay(path.name, str(path), saved, 'original-node') is False
    assert len(queued) == 1


def test_400_file_full_recipient_shard_spends_one_post(tmp_path, hub, principal):
    import urllib.error
    n = make_node(tmp_path, 'n', hub.url, principal, {'alpha': ['msg.send']})
    posts = []
    def full(*args, **kwargs):
        posts.append(args)
        raise urllib.error.HTTPError(hub.url + '/v1/msg', 429, 'full', {}, None)
    n._hub_req = full
    items = [(f'out_{i}.json', '/unused', {'to': 'ed25519:rcpt'},
              {'msg_id': f'msg_{i}'}, 'fp', None) for i in range(400)]
    result = n._flush_post_shard(items)
    assert len(posts) == 1
    assert len(result) == 400
    assert sum(deferred for _, _, deferred in result) == 399
