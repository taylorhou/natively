import json
from datetime import UTC, datetime

import pytest

from natively.errors import IntegrityError, VerifyError
from natively.ledger import GENESIS, Ledger, entry_hash


def test_chain_head_prose_and_verify(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    assert led.head() == GENESIS and len(led) == 0
    e1 = led.append(
        ts="2026-09-07T07:00:00Z",
        actor="a",
        grant_id=None,
        action="info.received",
        params_hash=None,
        outcome="information",
        msg_id="msg_1",
        detail="hi",
    )
    e2 = led.append(
        ts="2026-09-07T07:00:01Z",
        actor="a",
        grant_id="grt_1",
        action="fs.write",
        params_hash="sha256:" + "0" * 64,
        outcome="applied",
        msg_id="msg_2",
    )
    assert e1["prev_hash"] == GENESIS and e2["prev_hash"] == entry_hash(e1)
    assert led.head() == entry_hash(e2)
    assert led.verify() == led.head()
    prose = led.prose_path.read_text().splitlines()
    assert len(prose) == 2 and "fs.write under grt_1" in prose[1] and prose[1].endswith("]")
    # a fresh handle reads the same chain
    assert Ledger(tmp_path / "l.jsonl").verify() == led.head()
    assert (
        led.uses("grt_1") == 1
        and led.uses("grt_1", since=datetime(2026, 9, 7, 7, 0, 2, tzinfo=UTC)) == 0
    )
    assert led.find_msg("msg_2")["outcome"] == "applied" and led.find_msg("msg_9") is None


def test_tamper_detected(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.append(
        ts="2026-09-07T07:00:00Z",
        actor="a",
        grant_id=None,
        action="x",
        params_hash=None,
        outcome="information",
    )
    led.append(
        ts="2026-09-07T07:00:01Z",
        actor="a",
        grant_id=None,
        action="y",
        params_hash=None,
        outcome="information",
    )
    lines = led.path.read_text().splitlines()
    e = json.loads(lines[0])
    e["outcome"] = "applied"
    lines[0] = json.dumps(e, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError) as ex:
        Ledger(tmp_path / "l.jsonl").verify()
    assert ex.value.reason == "ledger.chain"


def test_prose_mismatch_detected(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.append(
        ts="2026-09-07T07:00:00Z",
        actor="a",
        grant_id=None,
        action="x",
        params_hash=None,
        outcome="information",
    )
    led.prose_path.write_text("someone rewrote the prose [deadbeefdead]\n")
    with pytest.raises(IntegrityError) as ex:
        led.verify()
    assert ex.value.reason == "ledger.prose.mismatch"
    led.prose_path.write_text("")
    with pytest.raises(IntegrityError) as ex:
        led.verify()
    assert ex.value.reason == "ledger.prose.count"


def test_corrupt_line(tmp_path):
    # a line that does not parse is LOCAL corruption (round 6, F9): IntegrityError,
    # a storage failure, never a VerifyError attributed to peer input
    p = tmp_path / "l.jsonl"
    p.write_text("{not json\n")
    with pytest.raises(IntegrityError) as ex:
        Ledger(p).entries()
    assert ex.value.reason == "ledger.corrupt" and not isinstance(ex.value, VerifyError)


# ---- integrity in operation (gate finding 11) ------------------------------------------


def _two(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.append(
        ts="2026-09-07T07:00:00Z",
        actor="a",
        grant_id=None,
        action="x",
        params_hash=None,
        outcome="information",
    )
    led.append(
        ts="2026-09-07T07:00:01Z",
        actor="a",
        grant_id=None,
        action="y",
        params_hash=None,
        outcome="information",
    )
    return led


def test_broken_chain_is_refused_on_load_not_only_on_verify(tmp_path):
    led = _two(tmp_path)
    lines = led.path.read_text().splitlines()
    e = json.loads(lines[0])
    e["outcome"] = "applied"
    lines[0] = json.dumps(e, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n")
    fresh = Ledger(tmp_path / "l.jsonl")
    with pytest.raises(IntegrityError) as ex:
        fresh.entries()
    assert ex.value.reason == "ledger.chain"
    with pytest.raises(IntegrityError):
        fresh.head()
    with pytest.raises(IntegrityError):
        fresh.append(
            ts="2026-09-07T07:00:02Z",
            actor="a",
            grant_id=None,
            action="z",
            params_hash=None,
            outcome="information",
        )


def test_truncated_last_line_is_refused(tmp_path):
    led = _two(tmp_path)
    data = led.path.read_bytes()
    led.path.write_bytes(data[:-10])  # a crash mid-line
    with pytest.raises(IntegrityError) as ex:
        Ledger(tmp_path / "l.jsonl").entries()
    assert ex.value.reason == "ledger.truncated"
    led.path.write_bytes(data[:-1])  # complete JSON, no newline: still an interrupted write
    with pytest.raises(IntegrityError) as ex:
        Ledger(tmp_path / "l.jsonl").entries()
    assert ex.value.reason == "ledger.truncated"


def test_replacement_prose_with_the_tag_preserved_fails(tmp_path):
    led = _two(tmp_path)
    lines = led.prose_path.read_text().splitlines()
    tag = lines[0][lines[0].rindex("[") :]
    lines[0] = "the operator approved everything " + tag
    led.prose_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError) as ex:
        led.verify()
    assert ex.value.reason == "ledger.prose.mismatch"


def test_newlines_in_fields_stay_one_prose_line(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.append(
        ts="2026-09-07T07:00:00Z",
        actor="evil\nagent",
        grant_id=None,
        action="info.received",
        params_hash=None,
        outcome="information",
        msg_id=None,
        detail="line one\nline two\r\n line three\x00",
    )
    led.append(
        ts="2026-09-07T07:00:01Z",
        actor="a",
        grant_id=None,
        action="y",
        params_hash=None,
        outcome="information",
    )
    prose = led.prose_path.read_text()
    assert prose.count("\n") == 2 and " " not in prose and "\x00" not in prose
    assert (
        "evil\\nagent" in prose
        and "line one\\nline two\\r\\n\\u2028line three\\x00" in prose
        or "\\x" in prose
    )
    assert led.verify() == led.head()


def test_repair_regenerates_only_missing_trailing_prose(tmp_path):
    led = _two(tmp_path)
    good = led.prose_path.read_text()
    lines = good.splitlines()
    led.prose_path.write_text(lines[0] + "\n")  # the second prose write never landed
    with pytest.raises(IntegrityError) as ex:
        led.verify()
    assert ex.value.reason == "ledger.prose.count"
    assert led.repair() == 1
    assert led.prose_path.read_text() == good and led.verify() == led.head()
    assert led.repair() == 0  # nothing to do
    # a mismatch in the middle is not repaired
    led.prose_path.write_text("rewritten " + lines[0][-14:] + "\n")
    with pytest.raises(IntegrityError) as ex:
        led.repair()
    assert ex.value.reason == "ledger.repair.refused"
    # more prose than entries is not repaired either
    led.prose_path.write_text(good + "extra line [000000000000]\n")
    with pytest.raises(IntegrityError) as ex:
        led.repair()
    assert ex.value.reason == "ledger.repair.refused"
    # a broken chain is never repaired
    led.prose_path.write_text(good)
    data = led.path.read_bytes()
    led.path.write_bytes(data.replace(b'"action":"x"', b'"action":"q"'))
    with pytest.raises(IntegrityError) as ex:
        led.repair()
    assert ex.value.reason == "ledger.chain"
