"""载荷校验测试：拒绝浮点/布尔/越界，合法输入精确保留。"""

from __future__ import annotations

import pytest

from app.models import MAX_CONSTRAINTS, MAX_VARS, parse_payload, PayloadError


def base(**over):
    p = {
        "audit_id": "run-001",
        "variables": ["I1", "I2"],
        "constraints": [
            {"coeffs": [1, 2], "b": 3, "stable": True},
            {"coeffs": [-1, 0], "b": 0},
        ],
    }
    p.update(over)
    return p


def test_valid():
    p = parse_payload(base())
    assert p.audit_id == "run-001"
    assert p.variables == ("I1", "I2")
    assert p.constraints[0].coeffs == (1, 2)
    assert p.constraints[0].b == 3
    assert p.stable_flags == (True, False)


def test_float_coeff_rejected():
    p = base()
    p["constraints"][0]["coeffs"][0] = 1.5
    with pytest.raises(PayloadError, match="整数"):
        parse_payload(p)


def test_float_b_rejected():
    p = base()
    p["constraints"][0]["b"] = 1.0  # JSON number 1.0 -> float
    with pytest.raises(PayloadError):
        parse_payload(p)


def test_bool_rejected_as_int():
    p = base()
    p["constraints"][0]["b"] = True
    with pytest.raises(PayloadError, match="整数"):
        parse_payload(p)


def test_string_number_rejected():
    p = base()
    p["constraints"][0]["b"] = "3"
    with pytest.raises(PayloadError):
        parse_payload(p)


def test_big_int_accepted():
    p = base()
    p["constraints"][0]["b"] = 10**100
    assert parse_payload(p).constraints[0].b == 10**100


def test_too_many_vars():
    with pytest.raises(PayloadError):
        parse_payload(base(variables=[f"x{i}" for i in range(MAX_VARS + 1)],
                           constraints=[{"coeffs": [0] * (MAX_VARS + 1), "b": 1}]))


def test_zero_vars():
    with pytest.raises(PayloadError):
        parse_payload(base(variables=[]))


def test_too_many_constraints():
    p = base()
    p["constraints"] = [{"coeffs": [0, 0], "b": 1}] * (MAX_CONSTRAINTS + 1)
    with pytest.raises(PayloadError):
        parse_payload(p)


def test_coeff_length_mismatch():
    p = base()
    p["constraints"][1]["coeffs"] = [1]
    with pytest.raises(PayloadError, match="长度"):
        parse_payload(p)


def test_duplicate_variable_names():
    with pytest.raises(PayloadError, match="重复"):
        parse_payload(base(variables=["I1", "I1"]))


def test_bad_audit_id():
    for bad in ["", "   ", "a b", "../etc", "a/b", "x" * 200]:
        with pytest.raises(PayloadError):
            parse_payload(base(audit_id=bad))


def test_audit_id_allowed_chars():
    for good in ["A.b-1_2@x", "编号01"]:  # 非 ASCII 字母也允许
        parse_payload(base(audit_id=good))


def test_stable_must_be_bool():
    p = base()
    p["constraints"][0]["stable"] = "yes"
    with pytest.raises(PayloadError, match="stable"):
        parse_payload(p)


def test_not_an_object():
    with pytest.raises(PayloadError):
        parse_payload([1, 2, 3])
    with pytest.raises(PayloadError):
        parse_payload("nope")


def test_zero_le_minus_one_is_allowed_and_inconsistent():
    # 0 <= -1 是合法录入（非法的是数据类型，不是矛盾数学）
    p = parse_payload(base(constraints=[{"coeffs": [0, 0], "b": -1}]))
    assert p.constraints[0].b == -1


def test_canonical_fingerprint_stable():
    from app.storage import fingerprint
    p1 = parse_payload(base())
    p2 = parse_payload(base())
    assert fingerprint(p1.canonical()) == fingerprint(p2.canonical())
    p3 = base()
    p3["constraints"][0]["stable"] = False
    # stable 标识属于载荷的一部分
    assert fingerprint(p1.canonical()) != fingerprint(parse_payload(p3).canonical())
