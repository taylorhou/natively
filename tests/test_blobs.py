"""Blobs are durable and repeatably readable (review 2026-09-07, point 8):
a GET never consumes the only copy, every recipient of a group blob can
fetch it, a hub started without a state path still keeps blobs, writes
are atomic, and the store is bounded by the cap with the oldest retired
first - never the blob just written."""
import hashlib
import json
import os

import pytest

from natively import hub as hubmod

from conftest import http, start_hub


def _put(h, data):
    status, resp = http("POST", h.url + "/v1/blob", body=data, raw=True)
    assert status == 200, resp
    return json.loads(resp)["blob_id"]


def test_a_blob_can_be_fetched_again_and_again(tmp_path, hub):
    data = os.urandom(4096)
    bid = _put(hub, data)
    assert bid == hashlib.sha256(data).hexdigest()[:32]
    for _ in range(3):  # a group of three recipients, or one whose first download died
        status, body = http("GET", hub.url + "/v1/blob/" + bid, raw=True)
        assert (status, body) == (200, data)
    assert not [f for f in os.listdir(hub.state.blob_dir) if f.startswith(".blob.")]  # no temp files


def test_a_hub_without_a_state_path_still_keeps_blobs_in_a_private_store(tmp_path, monkeypatch):
    import stat
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    st = hubmod.State(None)
    other = hubmod.State(None)
    assert st.blob_dir.startswith(str(tmp_path)) and st.blob_dir != other.blob_dir  # its own, never shared
    assert stat.S_IMODE(os.stat(st.blob_dir).st_mode) == 0o700
    data = b"kept by default"
    assert st.blob_put(hashlib.sha256(data).hexdigest()[:32], data) == ""
    assert st.blob_get(hashlib.sha256(data).hexdigest()[:32]) == data


def test_the_store_is_bounded_oldest_out_and_never_the_new_blob(tmp_path, monkeypatch):
    st = hubmod.State(str(tmp_path / "hub.json"))
    st.BLOB_CAP = 10 * 1024
    ids = []
    for i in range(4):
        data = bytes([i]) * 3 * 1024
        bid = hashlib.sha256(data).hexdigest()[:32]
        assert st.blob_put(bid, data) == ""
        ids.append(bid)
        os.utime(os.path.join(st.blob_dir, bid), (1000 + i, 1000 + i))
    assert st.blob_get(ids[0]) is None  # the oldest went when the fourth arrived
    assert all(st.blob_get(b) is not None for b in ids[1:])
    assert st.blob_put("f" * 32, b"x" * (st.BLOB_CAP + 1)) == "blob larger than the store"
    # a clock that puts the new blob FIRST (equal or earlier mtimes): the
    # others are still retired until the store is within the cap
    st2 = hubmod.State(str(tmp_path / "hub2.json"))
    st2.BLOB_CAP = 10 * 1024
    real_utime = os.utime
    stamp = [2000]

    def older_each_time(path, times=None, **kw):
        stamp[0] -= 1
        return real_utime(path, (stamp[0], stamp[0]))  # the blob being written sorts FIRST when eviction runs
    monkeypatch.setattr(os, "utime", older_each_time)
    for i in range(4):
        data = bytes([10 + i]) * 3 * 1024
        bid = hashlib.sha256(data).hexdigest()[:32]
        assert st2.blob_put(bid, data) == ""
    kept = [x for x in os.listdir(st2.blob_dir) if not x.startswith(".blob.")]
    assert sum(os.path.getsize(os.path.join(st2.blob_dir, x)) for x in kept) <= st2.BLOB_CAP
    assert st2.blob_get(hashlib.sha256(bytes([13]) * 3 * 1024).hexdigest()[:32]) is not None  # the newest survives
    assert st2.blob_get(hashlib.sha256(bytes([12]) * 3 * 1024).hexdigest()[:32]) is None  # the one that sorted right after it went


def test_two_stores_on_one_directory_serialize_and_a_private_store_goes_with_its_hub(tmp_path, monkeypatch):
    import tempfile
    a = hubmod.State(str(tmp_path / "a.json"))
    b = hubmod.State(str(tmp_path / "b.json"))  # the same parent: the same blobs/ directory, created by whichever came first
    assert a.blob_dir == b.blob_dir and os.path.isdir(a.blob_dir)
    data = b"shared store"
    bid = hashlib.sha256(data).hexdigest()[:32]
    assert a.blob_put(bid, data) == ""
    # b's first use reclaims temp files and reconciles the cap under the
    # store lock: a's published blob is untouched, and a lock file exists
    assert b.blob_get(bid) == data and os.path.exists(os.path.join(b.blob_dir, ".lock"))
    assert b.blob_put(hashlib.sha256(b"from b").hexdigest()[:32], b"from b") == ""
    assert a.blob_get(hashlib.sha256(b"from b").hexdigest()[:32]) == b"from b"
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    st = hubmod.State(None)
    d = st.blob_dir
    assert st.blob_put(bid, data) == "" and os.path.isdir(d)
    st.close()
    assert not os.path.exists(d)  # a private store does not outlive its hub
    a.close()
    assert os.path.isdir(a.blob_dir)  # a volume-backed store does


def test_the_cap_is_enforced_even_when_the_final_fsync_fails_and_reconciled_on_reopen(tmp_path, monkeypatch):
    st = hubmod.State(str(tmp_path / "hub.json"))
    st.BLOB_CAP = 10 * 1024
    real_fsync_dir = st._fsync_dir
    fail = {"on": False}

    def flaky(d):
        if fail["on"]:
            raise OSError("fsync failed")
        return real_fsync_dir(d)
    monkeypatch.setattr(st, "_fsync_dir", flaky)
    for i in range(3):
        data = bytes([i]) * 3 * 1024
        assert st.blob_put(hashlib.sha256(data).hexdigest()[:32], data) == ""
    fail["on"] = True
    data = bytes([9]) * 3 * 1024
    with pytest.raises(OSError):
        st.blob_put(hashlib.sha256(data).hexdigest()[:32], data)  # published, then the failure is reported
    fail["on"] = False
    kept = [x for x in os.listdir(st.blob_dir) if not x.startswith(".")]
    assert sum(os.path.getsize(os.path.join(st.blob_dir, x)) for x in kept) <= st.BLOB_CAP  # the cap held anyway
    assert st.blob_get(hashlib.sha256(data).hexdigest()[:32]) == data
    # a store left over the cap (a crash between publish and eviction) is
    # brought within it when the hub starts, before any request - and a
    # stale temp file goes then too, without waiting for an upload
    extra = bytes([7]) * 3 * 1024
    open(os.path.join(st.blob_dir, hashlib.sha256(extra).hexdigest()[:32]), "wb").write(extra)
    open(os.path.join(st.blob_dir, ".blob.stale"), "wb").write(b"x")
    hubmod.State.BLOB_CAP, cap = 10 * 1024, hubmod.State.BLOB_CAP
    try:
        st2 = hubmod.State(str(tmp_path / "hub.json"))
    finally:
        hubmod.State.BLOB_CAP = cap
    kept = [x for x in os.listdir(st2.blob_dir) if not x.startswith(".")]
    assert sum(os.path.getsize(os.path.join(st2.blob_dir, x)) for x in kept) <= 10 * 1024
    assert not [x for x in os.listdir(st2.blob_dir) if x.startswith(".blob.")]


def test_a_failed_upload_leaves_no_temp_file_and_a_short_write_is_not_published(tmp_path, monkeypatch):
    st = hubmod.State(str(tmp_path / "hub.json"))
    data = b"never published"
    bid = hashlib.sha256(data).hexdigest()[:32]
    real_replace = os.replace

    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        st.blob_put(bid, data)
    monkeypatch.setattr(os, "replace", real_replace)
    assert st.blob_get(bid) is None
    assert not [x for x in os.listdir(st.blob_dir) if x.startswith(".blob.")]
    # a leftover temp file from a hub that died mid-write is reclaimed on first use
    open(os.path.join(st.blob_dir, ".blob.stale"), "wb").write(b"x")
    st._blob_dir_ready = False
    assert st.blob_put(bid, data) == "" and st.blob_get(bid) == data
    assert not [x for x in os.listdir(st.blob_dir) if x.startswith(".blob.")]


def test_an_oversized_upload_is_refused_with_413(tmp_path):
    h = start_hub(tmp_path)
    try:
        h.state.BLOB_CAP = 1024
        status, resp = http("POST", h.url + "/v1/blob", body=b"x" * 2048, raw=True)
        assert status == 413
        status, _ = http("GET", h.url + "/v1/blob/" + "0" * 32, raw=True)
        assert status == 404
    finally:
        h.close()
