"""Ratchet state commits only after the AEAD verifies (review 2026-09-07,
point 5 / header point 8), for the pairwise Double Ratchet and the group
sender key; the X3DH handshake is the standard triple, so both identity
keys enter the root."""
import copy

import pytest

from natively import crypto, jcs


def _pair():
    a_seed, b_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    b_spk_sk = crypto.x_gen()
    root_a, ek = crypto.x3dh_initiator(a_seed, crypto.sign_pub(b_seed), crypto.x_pub(b_spk_sk))
    root_b = crypto.x3dh_responder(b_seed, b_spk_sk, crypto.ed_pk_to_x(crypto.sign_pub(a_seed)), ek)
    assert root_a == root_b
    a = crypto.DRSession.init_initiator(root_a, crypto.x_pub(b_spk_sk))
    b = crypto.DRSession.init_responder(root_b, b_spk_sk)
    return a, b


def test_x3dh_is_the_standard_triple_and_binds_both_identities():
    a_seed, b_seed, other = crypto.gen_signing_key(), crypto.gen_signing_key(), crypto.gen_signing_key()
    b_spk_sk = crypto.x_gen()
    root, ek = crypto.x3dh_initiator(a_seed, crypto.sign_pub(b_seed), crypto.x_pub(b_spk_sk))
    assert root == crypto.x3dh_responder(b_seed, b_spk_sk, crypto.ed_pk_to_x(crypto.sign_pub(a_seed)), ek)
    # the responder's signed prekey alone is not enough: its identity key enters the root
    assert root != crypto.x3dh_responder(other, b_spk_sk, crypto.ed_pk_to_x(crypto.sign_pub(a_seed)), ek)
    # and the initiator's identity enters it too
    assert root != crypto.x3dh_responder(b_seed, b_spk_sk, crypto.ed_pk_to_x(crypto.sign_pub(other)), ek)


def test_pairwise_decrypt_failure_leaves_the_session_untouched():
    a, b = _pair()
    hdr, ct = a.encrypt(b"first", aad=b"nv1-msg")
    before = b.to_state()
    with pytest.raises(crypto.CryptoError):
        b.decrypt(hdr, ct[:-1] + bytes([ct[-1] ^ 1]), aad=b"nv1-msg")
    assert b.to_state() == before  # nothing advanced, no key stored
    with pytest.raises(crypto.CryptoError):
        b.decrypt(hdr, ct, aad=b"wrong-aad")
    assert b.to_state() == before
    assert b.decrypt(hdr, ct, aad=b"nv1-msg") == b"first"
    # a forged message far ahead does not move the receive counter either
    hdr2, ct2 = a.encrypt(b"second", aad=b"nv1-msg")
    hdr3, ct3 = a.encrypt(b"third", aad=b"nv1-msg")
    after_first = b.to_state()
    with pytest.raises(crypto.CryptoError):
        b.decrypt(hdr3, ct3[:-1] + bytes([ct3[-1] ^ 1]), aad=b"nv1-msg")
    assert b.to_state() == after_first
    assert b.decrypt(hdr3, ct3, aad=b"nv1-msg") == b"third"
    assert b.decrypt(hdr2, ct2, aad=b"nv1-msg") == b"second"  # the skipped key was stored on success only


def test_pairwise_gap_beyond_the_skip_window_fast_forwards_and_beyond_ffwd_is_refused():
    """A gap wider than MAX_SKIP (a hub that dropped deep backlog) heals:
    the chain fast-forwards, keeping only the newest MAX_SKIP keys, so the
    later messages still decrypt and the store stays bounded; a gap beyond
    MAX_FFWD is refused before anything moves."""
    a, b = _pair()
    n = crypto.DRSession.MAX_SKIP + 300
    msgs = [a.encrypt(b"m%d" % i, aad=b"") for i in range(n + 1)]
    assert b.decrypt(msgs[n][0], msgs[n][1], aad=b"") == b"m%d" % n
    assert len(b.skipped) == crypto.DRSession.MAX_SKIP
    assert b.decrypt(msgs[n - 1][0], msgs[n - 1][1], aad=b"") == b"m%d" % (n - 1)  # inside the kept window
    with pytest.raises(crypto.CryptoError):
        b.decrypt(msgs[0][0], msgs[0][1], aad=b"")  # gone with the backlog
    for i in range(3):
        hdr, ct = a.encrypt(b"later%d" % i, aad=b"")
        assert b.decrypt(hdr, ct, aad=b"") == b"later%d" % i  # the channel goes on
    far = a.encrypt(b"far", aad=b"")
    a2, b2 = _pair()
    fake_hdr = dict(far[0], n=crypto.DRSession.MAX_FFWD + 10)
    before = b2.to_state()
    with pytest.raises(crypto.CryptoError, match="skip window"):
        b2.decrypt(fake_hdr, far[1], aad=b"")
    assert b2.to_state() == before


def test_ratchet_header_is_bound_as_its_jcs_form():
    hdr = {"dh": "AAAA", "n": 3, "pn": 0}
    assert crypto.DRSession._header_bytes(hdr) == jcs.canonicalize(hdr) == b'{"dh":"AAAA","n":3,"pn":0}'


def test_sender_key_decrypt_failure_leaves_the_key_untouched():
    s = crypto.SenderKey()
    r = crypto.SenderKey.from_state(s.state())
    msgs = [s.encrypt(b"g%d" % i) for i in range(5)]
    before = r.state()
    n, ct = msgs[3]
    with pytest.raises(crypto.CryptoError):
        r.decrypt_at(n, ct[:-1] + bytes([ct[-1] ^ 1]))
    assert r.state() == before  # counter and skipped store unchanged
    assert r.decrypt_at(n, ct) == b"g3"
    assert set(r.skipped) == {0, 1, 2}
    assert r.decrypt_at(msgs[1][0], msgs[1][1]) == b"g1"
