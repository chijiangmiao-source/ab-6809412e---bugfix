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

# 磁阱电流三约束：安全上界 I<=0、电源下界 I>=1、宽松场强上界 I<=10。
# 前两条已构成矛盾，第三条乘子必为 0，但证书仍须为其保留一个位置。
P3_ZERO_MU = {
    "audit_id": "trap-three",
    "variables": ["I1"],
    "constraints": [
        {"coeffs": [1], "b": 0, "label": "安全上界", "stable": True},
        {"coeffs": [-1], "b": -1, "label": "电源下界", "stable": True},
        {"coeffs": [1], "b": 10, "label": "宽松场强上界", "stable": False},
    ],
}


def _assert_three_item_evidence(rec):
    """三项证据完整、与原始录入顺序一一对应、相加恰为 0 <= -1。"""
    result = rec["result"]
    assert result["status"] == "infeasible"
    assert result["stable_flags"] == [True, True, False]

    assert [m["index"] for m in result["multipliers"]] == [0, 1, 2]
    assert [m["value"] for m in result["multipliers"]] == ["1", "1", "0"]

    terms = result["terms"]
    assert [t["index"] for t in terms] == [0, 1, 2]
    labels = ["安全上界", "电源下界", "宽松场强上界"]
    bs = ["0", "-1", "10"]
    weighted = [["1"], ["-1"], ["0"]]
    wrhs = ["0", "-1", "0"]
    for i, t in enumerate(terms):
        assert t["label"] == labels[i]
        assert t["b"] == bs[i]
        assert t["weighted_coeffs"] == weighted[i]
        assert t["weighted_rhs"] == wrhs[i]
        assert Fraction(t["weighted_rhs"]) == (
            Fraction(t["multiplier"]) * Fraction(t["b"])
        )
    assert result["combined_lhs"] == ["0"]
    assert result["combined_rhs"] == "-1"
    assert result["combined_relation"] == "0 <= -1"
    verify_certificate(result)
    assert "evidence_term_count" not in result


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


# ---- 零乘子约束必须逐项保留在冻结证书中 ----

def test_zero_multiplier_constraint_kept_in_full_evidence(tmp_path):
    """三约束场景首次提交：第三项乘子为 0 也必须在逐项证据中。"""
    svc = make_service(tmp_path)
    rec, replayed = svc.audit(P3_ZERO_MU)
    assert replayed is False
    _assert_three_item_evidence(rec)
    # 条目与原始录入顺序、标签、系数、右端一一对应
    payload_cons = rec["payload"]["constraints"]
    assert payload_cons == P3_ZERO_MU["constraints"]


def test_zero_multiplier_constraint_replay_still_full(tmp_path):
    """相同载荷重传：返回同一条完整冻结记录（含零乘子项）。"""
    svc = make_service(tmp_path)
    r1, _ = svc.audit(P3_ZERO_MU)
    r2, replayed = svc.audit(json.loads(json.dumps(P3_ZERO_MU)))
    assert replayed is True
    _assert_three_item_evidence(r2)
    assert r1 == r2
    assert r2["created_at"] == r1["created_at"]
    assert r2["fingerprint"] == r1["fingerprint"]


def test_zero_multiplier_constraint_fetch_still_full(tmp_path):
    """按审计编号读取（含跨“重启”的新 store 实例）证据完整。"""
    store1 = AuditStore(str(tmp_path / "data"))
    svc1 = AuditService(store1)
    r1, _ = svc1.audit(P3_ZERO_MU)
    _assert_three_item_evidence(r1)

    # 新实例模拟服务重启：仅从磁盘读取
    store2 = AuditStore(str(tmp_path / "data"))
    fetched = AuditService(store2).fetch("trap-three")
    _assert_three_item_evidence(fetched)
    assert fetched["created_at"] == r1["created_at"]
    assert fetched["fingerprint"] == r1["fingerprint"]


# ---- 早期“压缩”残缺冻结记录的恢复 ----

def _write_legacy_compacted(store: AuditStore, created_at="2026-09-28T00:00:00Z"):
    """按早期版本逻辑落盘一条残缺记录：零乘子条目被丢弃。"""
    from app.models import AuditPayload, parse_payload
    from app.simplex import solve

    parsed: AuditPayload = parse_payload(P3_ZERO_MU)
    full = solve(list(parsed.variables),
                 tuple(parsed.constraints)).as_dict()
    full["stable_flags"] = list(parsed.stable_flags)
    compacted = dict(full)
    compacted["terms"] = [t for t in full["terms"]
                          if t["multiplier"] != "0"]
    compacted["multipliers"] = [m for m in full["multipliers"]
                                if m["value"] != "0"]
    compacted["evidence_term_count"] = len(compacted["terms"])
    legacy = {
        "audit_id": "trap-three",
        "created_at": created_at,
        "fingerprint": fingerprint(parsed.canonical()),
        "payload": parsed.canonical(),
        "result": compacted,
        "method": "phase-I-simplex/exact-rational/Bland",
    }
    store._write_atomic("trap-three", legacy)
    return legacy, full


def test_legacy_compacted_record_restored_on_fetch(tmp_path):
    """按编号读取历史残缺记录：恢复为完整可复核结果，

    编号、创建时间、载荷指纹、可行性裁决与枢轴数均不得改变。
    """
    store = AuditStore(str(tmp_path / "data"))
    legacy, full = _write_legacy_compacted(store)

    restored = store.get("trap-three")
    _assert_three_item_evidence(restored)
    assert restored["audit_id"] == "trap-three"
    assert restored["created_at"] == "2026-09-28T00:00:00Z"
    assert restored["fingerprint"] == legacy["fingerprint"]
    assert restored["payload"] == legacy["payload"]
    assert restored["method"] == legacy["method"]
    assert restored["result"]["status"] == "infeasible"
    assert restored["result"]["pivots"] == full["pivots"]

    # 新实例（模拟重启）再读：磁盘上已是完整记录，内容一致
    again = AuditStore(str(tmp_path / "data")).get("trap-three")
    assert again == restored


def test_legacy_compacted_record_restored_on_replay(tmp_path):
    """同号重传历史残缺记录也触发恢复，且仍视为同载荷重放 (200)。"""
    store = AuditStore(str(tmp_path / "data"))
    legacy, _ = _write_legacy_compacted(store)

    rec, replayed = AuditService(store).audit(
        json.loads(json.dumps(P3_ZERO_MU))
    )
    assert replayed is True
    _assert_three_item_evidence(rec)
    assert rec["created_at"] == "2026-09-28T00:00:00Z"
    assert rec["fingerprint"] == legacy["fingerprint"]


def test_legacy_restored_record_still_conflicts_on_changed_payload(tmp_path):
    """恢复后的记录对改动载荷依旧冲突，原（已恢复的）证据不变。"""
    store = AuditStore(str(tmp_path / "data"))
    _write_legacy_compacted(store)
    svc = AuditService(store)
    svc.fetch("trap-three")  # 先触发恢复

    changed = json.loads(json.dumps(P3_ZERO_MU))
    changed["constraints"][2]["b"] = 99
    with pytest.raises(IdConflictError):
        svc.audit(changed)
    rec = svc.fetch("trap-three")
    _assert_three_item_evidence(rec)
    assert rec["created_at"] == "2026-09-28T00:00:00Z"


def test_migrate_all_restores_legacy_records_on_startup(tmp_path):
    """启动迁移扫描：恢复历史残缺记录，完整记录与非审计文件不受影响。"""
    store = AuditStore(str(tmp_path / "data"))
    legacy, _ = _write_legacy_compacted(store)
    # 一条完整的不可行记录不应被重写（created_at 等保持不变）
    ok_rec, _ = AuditService(store).audit({
        "audit_id": "other-inf",
        "variables": ["x"],
        "constraints": [{"coeffs": [0], "b": -1}],
    })
    # 一个无关文件，扫描必须跳过而不报错
    (tmp_path / "data" / "notes.txt").write_text("ignore", encoding="utf-8")

    fresh = AuditStore(str(tmp_path / "data"))
    assert fresh.migrate_all() == 1
    # 幂等：再次扫描没有需要修复的记录
    assert fresh.migrate_all() == 0

    restored = fresh.get("trap-three")
    _assert_three_item_evidence(restored)
    assert restored["created_at"] == legacy["created_at"]
    assert restored["fingerprint"] == legacy["fingerprint"]
    other = fresh.get("other-inf")
    assert other["created_at"] == ok_rec["created_at"]
    assert other["result"]["combined_rhs"] == "-1"
