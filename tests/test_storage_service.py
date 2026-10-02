"""冻结存储与审计服务：幂等重放、冲突保持原证据、非法载荷不落盘。"""

from __future__ import annotations

import json
import threading
from fractions import Fraction

import pytest

from app.models import verify_certificate
from app.service import AuditService, IdConflictError
from app.storage import AuditStore, fingerprint


def make_service(tmp_path):
    return AuditService(AuditStore(str(tmp_path / "data")))


P1 = {
    "audit_id": "run-A",
    "variables": ["x"],
    "constraints": [{"coeffs": [0], "b": -1, "stable": False}],
}
P2_FEASIBLE = {
    "audit_id": "run-B",
    "variables": ["x"],
    "constraints": [{"coeffs": [1], "b": 1}],
}

# 磁阱三约束场景：安全上界 I<=0、电源下界 I>=1、宽松场强上界 I<=10
P3_ZERO_MULT = {
    "audit_id": "trap-run-3cons",
    "variables": ["I1"],
    "constraints": [
        {"coeffs": [1], "b": 0, "label": "安全上界", "stable": True},
        {"coeffs": [-1], "b": -1, "label": "电源下界", "stable": False},
        {"coeffs": [1], "b": 10, "label": "场强上界", "stable": True},
    ],
}


def _assert_three_term_certificate(res: dict) -> None:
    """三条原始约束必须各占一个乘子与一项贡献，第三项乘子为 0。"""
    assert res["status"] == "infeasible"
    payload_cons = P3_ZERO_MULT["constraints"]
    multipliers = res["multipliers"]
    terms = res["terms"]
    assert len(multipliers) == 3
    assert len(terms) == 3
    # 索引/标签/右端与原始录入顺序一一对应
    for i, con in enumerate(payload_cons):
        assert multipliers[i]["index"] == i
        t = terms[i]
        assert t["index"] == i
        assert t["label"] == con["label"]
        assert t["b"] == str(con["b"])
        assert t["multiplier"] == multipliers[i]["value"]
        assert t["weighted_coeffs"] == [
            str(Fraction(multipliers[i]["value"]) * con["coeffs"][0])
        ]
        assert Fraction(t["weighted_rhs"]) == (
            Fraction(multipliers[i]["value"]) * con["b"]
        )
    assert [m["value"] for m in multipliers] == ["1", "1", "0"]
    verify_certificate(res)
    # 精确复算合并式 0 <= -1
    lhs = sum((Fraction(t["weighted_coeffs"][0]) for t in terms), Fraction(0))
    rhs = sum((Fraction(t["weighted_rhs"]) for t in terms), Fraction(0))
    assert lhs == 0 and rhs == -1
    assert res["combined_lhs"] == ["0"]
    assert res["combined_rhs"] == "-1"
    assert res["combined_relation"] == "0 <= -1"


def test_three_constraints_keeps_zero_multiplier_evidence(tmp_path):
    svc = make_service(tmp_path)
    rec, replayed = svc.audit(P3_ZERO_MULT)
    assert replayed is False
    _assert_three_term_certificate(rec["result"])


def test_three_constraints_replay_and_fetch_stay_complete(tmp_path):
    data_dir = str(tmp_path / "data")
    svc = AuditService(AuditStore(data_dir))
    r1, _ = svc.audit(P3_ZERO_MULT)

    # 相同载荷同号重传：200，三项证据完整且记录完全相同
    r2, replayed = svc.audit(json.loads(json.dumps(P3_ZERO_MULT)))
    assert replayed is True
    _assert_three_term_certificate(r2["result"])
    assert r2 == r1

    # 按编号重新读取（模拟重启后的新服务实例）
    svc2 = AuditService(AuditStore(data_dir))
    r3 = svc2.fetch("trap-run-3cons")
    _assert_three_term_certificate(r3["result"])
    assert r3["audit_id"] == r1["audit_id"]
    assert r3["created_at"] == r1["created_at"]
    assert r3["fingerprint"] == r1["fingerprint"]

    # 落盘文件本身也必须含三项（而非读取时临时拼接）
    path = svc2.store._path("trap-run-3cons")
    with open(path, encoding="utf-8") as f:
        on_disk = json.load(f)
    assert len(on_disk["result"]["terms"]) == 3
    assert "evidence_term_count" not in on_disk["result"]


def _legacy_compacted_record(svc: AuditService) -> dict:
    """构造历史版本落盘的被剔除零乘子条目的冻结记录。"""
    rec, _ = svc.audit(P3_ZERO_MULT)
    legacy = json.loads(json.dumps(rec))
    result = legacy["result"]
    result["terms"] = [t for t in result["terms"]
                       if t["multiplier"] != "0"]
    result["multipliers"] = [m for m in result["multipliers"]
                             if m["value"] != "0"]
    result["evidence_term_count"] = 2
    svc.store._write_atomic("trap-run-3cons", legacy)
    return legacy


def test_legacy_compacted_record_restored_on_fetch(tmp_path):
    data_dir = str(tmp_path / "data")
    svc = AuditService(AuditStore(data_dir))
    legacy = _legacy_compacted_record(svc)
    assert len(legacy["result"]["terms"]) == 2  # 历史缺失项确实存在

    restored = svc.fetch("trap-run-3cons")
    _assert_three_term_certificate(restored["result"])
    # 审计编号、创建时间、载荷指纹、裁决均不得改变
    assert restored["audit_id"] == legacy["audit_id"]
    assert restored["created_at"] == legacy["created_at"]
    assert restored["fingerprint"] == legacy["fingerprint"]
    assert restored["payload"] == legacy["payload"]
    assert restored["method"] == legacy["method"]
    assert restored["result"]["status"] == "infeasible"
    assert "evidence_term_count" not in restored["result"]


def test_legacy_restored_record_idempotent_across_restart(tmp_path):
    data_dir = str(tmp_path / "data")
    svc = AuditService(AuditStore(data_dir))
    legacy = _legacy_compacted_record(svc)

    # 重启后的新实例读取即恢复
    svc2 = AuditService(AuditStore(data_dir))
    got = svc2.fetch("trap-run-3cons")
    _assert_three_term_certificate(got["result"])
    assert got["created_at"] == legacy["created_at"]
    assert got["fingerprint"] == legacy["fingerprint"]

    # 恢复后相同载荷重传仍为幂等重放，记录不再被改动
    rec, replayed = svc2.audit(json.loads(json.dumps(P3_ZERO_MULT)))
    assert replayed is True
    _assert_three_term_certificate(rec["result"])
    assert rec["created_at"] == legacy["created_at"]

    svc3 = AuditService(AuditStore(data_dir))
    again = svc3.fetch("trap-run-3cons")
    assert again == rec


def test_legacy_restored_record_still_conflicts_on_changed_payload(tmp_path):
    svc = make_service(tmp_path)
    _legacy_compacted_record(svc)
    restored = svc.fetch("trap-run-3cons")
    changed = json.loads(json.dumps(P3_ZERO_MULT))
    changed["constraints"][2]["b"] = 11
    with pytest.raises(IdConflictError):
        svc.audit(changed)
    assert svc.fetch("trap-run-3cons") == restored


def test_first_submit_freezes(tmp_path):
    svc = make_service(tmp_path)
    rec, replayed = svc.audit(P1)
    assert replayed is False
    assert rec["result"]["status"] == "infeasible"
    assert rec["fingerprint"].startswith("sha256:")


def test_identical_payload_replays_same_record(tmp_path):
    svc = make_service(tmp_path)
    r1, _ = svc.audit(P1)
    r2, replayed = svc.audit(json.loads(json.dumps(P1)))
    assert replayed is True
    assert r1["fingerprint"] == r2["fingerprint"]
    assert r1["created_at"] == r2["created_at"]
    assert r1 is not r2 and r1 == r2


def test_changed_payload_same_id_conflicts_and_preserves(tmp_path):
    svc = make_service(tmp_path)
    r1, _ = svc.audit(P1)
    changed = json.loads(json.dumps(P1))
    changed["constraints"][0]["b"] = 1  # 改成 0 <= 1，可行
    with pytest.raises(IdConflictError):
        svc.audit(changed)
    # 原证据不变
    fetched = svc.fetch("run-A")
    assert fetched["fingerprint"] == r1["fingerprint"]
    assert fetched["result"]["status"] == "infeasible"
    assert fetched["result"]["combined_rhs"] == "-1"
    # 改 label / 系数 / stable 同样冲突
    for mutate in (
        lambda p: p["constraints"][0].__setitem__("b", 0),
        lambda p: p["constraints"][0].__setitem__("coeffs", [1]),
        lambda p: p["constraints"][0].__setitem__("stable", True),
        lambda p: p.__setitem__("variables", ["y"]),
    ):
        p = json.loads(json.dumps(P1))
        mutate(p)
        with pytest.raises(IdConflictError):
            svc.audit(p)
    assert svc.fetch("run-A")["fingerprint"] == r1["fingerprint"]


def test_invalid_payload_leaves_no_record(tmp_path):
    svc = make_service(tmp_path)
    bad = json.loads(json.dumps(P1))
    bad["constraints"][0]["b"] = 1.5
    with pytest.raises(ValueError):
        svc.audit(bad)
    assert svc.fetch("run-A") is None
    # 同编号随后可以正常首次提交
    rec, replayed = svc.audit(P1)
    assert replayed is False


def test_fetch_unknown(tmp_path):
    assert make_service(tmp_path).fetch("nope") is None


def test_concurrent_first_submits_single_record(tmp_path):
    """并发首次提交同载荷：只允许一个结论落盘。"""
    svc = make_service(tmp_path)
    results = []

    def worker():
        results.append(svc.audit(json.loads(json.dumps(P2_FEASIBLE))))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    fps = {r[0]["fingerprint"] for r in results}
    assert len(fps) == 1
    assert sum(1 for _, rep in results if rep) == 7
    files = list((tmp_path / "data").iterdir())
    assert len(files) == 1


def test_concurrent_conflicting_payloads(tmp_path):
    """并发提交不同载荷：一个成功，其余冲突，磁盘记录唯一且不变。"""
    svc = make_service(tmp_path)
    outcomes = []

    def worker(payload):
        try:
            outcomes.append(("ok", svc.audit(payload)))
        except IdConflictError:
            outcomes.append(("conflict", None))

    p_a = {**P2_FEASIBLE, "audit_id": "same"}
    p_b = {
        "audit_id": "same",
        "variables": ["x"],
        "constraints": [{"coeffs": [0], "b": -1}],
    }
    threads = [
        threading.Thread(target=worker,
                         args=(json.loads(json.dumps(p_a)),)),
        threading.Thread(target=worker,
                         args=(json.loads(json.dumps(p_b)),)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    statuses = sorted(o[0] for o in outcomes)
    assert statuses == ["conflict", "ok"]
    assert len(list((tmp_path / "data").iterdir())) == 1


def test_fingerprint_canonical_order_independent():
    a = {"audit_id": "z", "variables": ["x"],
         "constraints": [{"b": 1, "coeffs": [1], "label": None, "stable": False}]}
    b = {"constraints": [{"coeffs": [1], "stable": False, "label": None, "b": 1}],
         "variables": ["x"], "audit_id": "z"}
    assert fingerprint(a) == fingerprint(b)
