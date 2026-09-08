"""JCS (RFC 8785) conformance and the strict reader (review 2026-09-07,
point 5): number serialization is ES6 Number::toString, checked against
the RFC's Appendix B vectors and its section 3.2.3 example; `jcs.loads`
refuses duplicate keys and non-finite numbers, and the hub answers 400
to a body it refuses."""
import json
import struct

import pytest

from natively import jcs

from conftest import http

# RFC 8785 Appendix B: IEEE-754 binary64 (hex) -> ES6 string
VECTORS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def _f(hexstr):
    return struct.unpack(">d", bytes.fromhex(hexstr))[0]


@pytest.mark.parametrize("hexstr,expected", VECTORS)
def test_rfc8785_appendix_b_number_vectors(hexstr, expected):
    assert jcs.canonicalize(_f(hexstr)) == expected.encode()


def test_non_finite_numbers_cannot_be_canonicalized():
    for hexstr in ("7fffffffffffffff", "7ff0000000000000", "fff0000000000000"):
        with pytest.raises(ValueError):
            jcs.canonicalize(_f(hexstr))


def test_integral_floats_and_small_exponents_match_es6():
    # the review's probes: the pre-change code produced 100.0, 3.0, 1e-07
    for value, expected in ((100.0, "100"), (3.0, "3"), (1e-7, "1e-7"), (1e21, "1e+21"), (1e-6, "0.000001"),
                            (0.5, "0.5"), (-2.5e-5, "-0.000025"), (123456789012345680000.0, "123456789012345680000")):
        assert jcs.canonicalize(value) == expected.encode()
    # 1 and 1.0 are one JSON number
    assert jcs.canonicalize({"a": 1}) == jcs.canonicalize({"a": 1.0})


def test_integers_beyond_the_double_range_are_refused():
    assert jcs.canonicalize(2 ** 53) == b"9007199254740992"
    for n in (2 ** 53 + 1, -(2 ** 53) - 1, 10 ** 30):
        with pytest.raises(ValueError):
            jcs.canonicalize(n)


def test_rfc8785_section_3_2_3_example():
    doc = json.loads('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
                     ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
                     ' "literals": [null, true, false]}')
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
    assert jcs.canonicalize(doc) == expected.encode("utf-8")


def test_loads_refuses_duplicate_keys_and_non_finite_numbers():
    assert jcs.loads(b'{"a": 1, "b": [1, 2.5]}') == {"a": 1, "b": [1, 2.5]}
    assert jcs.loads('{"a": {"b": 1}}') == {"a": {"b": 1}}
    for bad in ('{"a": 1, "a": 2}', '{"x": {"a": 1, "a": 1}}', "NaN", "[Infinity]", "-Infinity", "1e400", "[1e999]",
                "9007199254740993", '{"n": 1%s}' % ("0" * 400), "[-9007199254740993]"):
        with pytest.raises(ValueError):
            jcs.loads(bad)
    # what json.loads would have done silently
    assert json.loads('{"a": 1, "a": 2}') == {"a": 2}


def test_hub_answers_400_to_a_body_with_duplicate_keys(hub):
    for path, body in (("/v1/msg", b'{"msg_id": "a", "msg_id": "b", "to": "x"}'),
                       ("/v1/register", b'{"node": "a", "node": "b"}'),
                       ("/v1/msg", b'{"msg_id": "a", "to": "x", "n": NaN}'),
                       ("/v1/msg", b'{"msg_id": "a", "to": "x", "n": 1%s}' % (b"0" * 400))):
        status, resp = http("POST", hub.url + path, body=body, raw=True)
        assert status == 400, (path, status, resp)
