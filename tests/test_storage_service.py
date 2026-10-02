"""冻结存储与审计服务：幂等重放、冲突保持原证据、非法载荷不落盘。"""

from __future__ import annotations

import json
import threading

import pytest

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
