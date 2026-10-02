"""verify 单次容器入口。

依次完成:
  1. 代码测试 (pytest)；
  2. HTTP 冒烟 (健康检查 / 页面 / 未知编号 404)；
  3. 用“相加得 0 <= -1”的约束组经真实 HTTP 提交核对不可行证书；
     独立重算 mu >= 0、Σmu*a = 0、Σmu*b < 0，逐条核对每个乘子/合并项
     与原始录入顺序一一对应（含乘子为 0 的宽松约束），并核对幂等(200)、
     按编号读取与冲突(409，原证据不变)；
  4. 再提交一个可行系统核对有理解与余量。

任一步失败立即以非零退出码退出；全部成功退出 0。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from fractions import Fraction

WEB_URL = os.environ.get("WEB_URL", "http://web:8080")
TIMEOUT_S = float(os.environ.get("VERIFY_TIMEOUT_S", "30"))


def step(title: str):
    print(f"\n=== verify: {title} ===", flush=True)


def http(method: str, path: str, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(WEB_URL + path, data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def wait_healthy() -> None:
    step("等待 web 健康")
    deadline = time.time() + TIMEOUT_S
    last = None
    while time.time() < deadline:
        try:
            status, body = http("GET", "/healthz")
            if status == 200 and body.get("status") == "ok":
                print("healthz OK:", body)
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.5)
    raise SystemExit(f"web 在 {TIMEOUT_S}s 内未就绪: {last}")


def run_pytest() -> None:
    step("代码测试 pytest")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=os.environ.get("VERIFY_SRC_DIR", "/srv"),
    )
    if proc.returncode != 0:
        raise SystemExit(f"pytest 失败，退出码 {proc.returncode}")


def http_smoke() -> None:
    step("HTTP 冒烟")
    status, body = http("GET", "/healthz")
    assert status == 200 and body["status"] == "ok", body

    with urllib.request.urlopen(WEB_URL + "/", timeout=10) as resp:
        html = resp.read().decode("utf-8")
    assert resp.status == 200 and "单纯形" in html

    status, _ = http("GET", "/api/audits/no-such-id-verify")
    assert status == 404, f"未知编号应为 404，实际 {status}"
    print("健康检查 / 页面 / 404 全部符合预期")


def check_certificate(audit_id: str, payload: dict, expect_rhs: str) -> dict:
    status, body = http("POST", "/api/audits", payload)
    assert status == 201, (status, body)
    res = body["result"]
    assert res["status"] == "infeasible", res
    _verify_certificate_terms(audit_id, payload, res, expect_rhs)

    # 幂等：完全相同载荷重放 -> 200 同一记录
    status2, body2 = http("POST", "/api/audits",
                          json.loads(json.dumps(payload)))
    assert status2 == 200 and body2["replayed"] is True
    assert body2["fingerprint"] == body["fingerprint"]
    assert body2["created_at"] == body["created_at"]
    _verify_certificate_terms(audit_id, payload, body2["result"], expect_rhs)
    print(f"[{audit_id}] 重放返回同一冻结记录 (200)，证据仍完整")

    # 按编号读取 -> 同一条完整冻结证据
    status3, body3 = http("GET", f"/api/audits/{audit_id}")
    assert status3 == 200, (status3, body3)
    assert body3["fingerprint"] == body["fingerprint"]
    assert body3["created_at"] == body["created_at"]
    _verify_certificate_terms(audit_id, payload, body3["result"], expect_rhs)
    print(f"[{audit_id}] 按编号读取返回同一完整证据")

    # 冲突：同编号改载荷 -> 409，原证据不变
    changed = json.loads(json.dumps(payload))
    changed["constraints"][0]["b"] = changed["constraints"][0]["b"] + 1
    status4, body4 = http("POST", "/api/audits", changed)
    assert status4 == 409, (status4, body4)
    status5, body5 = http("GET", f"/api/audits/{audit_id}")
    assert status5 == 200 and body5["result"]["combined_rhs"] == expect_rhs
    _verify_certificate_terms(audit_id, payload, body5["result"], expect_rhs)
    print(f"[{audit_id}] 改动载荷冲突 409，原证据保持不变")
    return res


def _verify_certificate_terms(audit_id, payload, res, expect_rhs=None):
    """仅依据证书逐项数据独立重算 μ≥0、Σμ·a=0、Σμ·b<0。

    并要求每条原始约束（含乘子为 0 者）都有一个乘子和一项合并式贡献，
    索引、标签、系数、右端与原始录入顺序一一对应。
    """
    n = len(payload["variables"])
    raw_cons = payload["constraints"]
    terms = res["terms"]
    multipliers = res["multipliers"]
    assert len(terms) == len(raw_cons), (
        f"[{audit_id}] 合并式项数 {len(terms)} != 约束条数 {len(raw_cons)}"
    )
    assert len(multipliers) == len(raw_cons), (
        f"[{audit_id}] 乘子数 {len(multipliers)} != 约束条数 {len(raw_cons)}"
    )
    lhs = [Fraction(0) for _ in range(n)]
    rhs = Fraction(0)
    for i, (t, con) in enumerate(zip(terms, raw_cons)):
        assert t["index"] == i, f"[{audit_id}] 项 {t['index']} 错位（应为 {i}）"
        assert multipliers[i]["index"] == i
        mu = Fraction(t["multiplier"])
        assert Fraction(multipliers[i]["value"]) == mu
        assert mu >= 0, "乘子必须非负"
        assert t["label"] == con.get("label"), (
            f"[{audit_id}] 项 {i} 标签与录入不一致"
        )
        assert Fraction(t["b"]) == Fraction(con["b"]), (
            f"[{audit_id}] 项 {i} 右端与录入不一致"
        )
        assert len(t["weighted_coeffs"]) == n
        for j, a in enumerate(con["coeffs"]):
            assert Fraction(t["weighted_coeffs"][j]) == mu * Fraction(a), (
                f"[{audit_id}] 项 {i} 加权系数与录入不一致"
            )
            lhs[j] += Fraction(t["weighted_coeffs"][j])
        assert Fraction(t["weighted_rhs"]) == mu * Fraction(t["b"])
        rhs += Fraction(t["weighted_rhs"])
    assert all(v == 0 for v in lhs), f"左侧合并必须全为 0: {lhs}"
    assert rhs < 0, f"右侧合并必须严格为负: {rhs}"
    assert res["combined_lhs"] == [str(v) for v in lhs]
    assert res["combined_rhs"] == str(rhs)
    if expect_rhs is not None:
        assert res["combined_rhs"] == expect_rhs
    assert res["combined_relation"] == f"0 <= {res['combined_rhs']}"
    print(
        f"[{audit_id}] 证书核验通过: {len(terms)} 项证据齐全，"
        f"μ>=0, Σμ·a=0, Σμ·b={rhs}"
    )


def main() -> int:
    run_pytest()
    wait_healthy()
    http_smoke()

    step("用相加得 0 <= -1 的约束组核对证书")
    # 组 1: 单条 0·x <= -1，乘子 1，直接合并为 0 <= -1
    check_certificate(
        "verify-zero-minus-one",
        {
            "audit_id": "verify-zero-minus-one",
            "variables": ["I1"],
            "constraints": [
                {"coeffs": [0], "b": -1, "stable": True}
            ],
        },
        "-1",
    )
    # 组 2: x <= 0 与 -x <= -1，乘子 1+1 合并为 0 <= -1
    check_certificate(
        "verify-combo",
        {
            "audit_id": "verify-combo",
            "variables": ["I1", "I2"],
            "constraints": [
                {"coeffs": [1, 0], "b": 0, "stable": False},
                {"coeffs": [-1, 0], "b": -1, "stable": True},
            ],
        },
        "-1",
    )

    # 组 3（磁阱电流审计）: I<=0 与 I>=1 已矛盾，I<=10 是宽松场强上界，
    # 其乘子恰为 0；证书仍须为三条原始约束各保留一个乘子与一项贡献。
    step("三约束含零乘子项：证据逐项完整性")
    trap = {
        "audit_id": "verify-trap-three",
        "variables": ["I1"],
        "constraints": [
            {"coeffs": [1], "b": 0, "label": "安全上界", "stable": True},
            {"coeffs": [-1], "b": -1, "label": "电源下界", "stable": True},
            {"coeffs": [1], "b": 10, "label": "宽松场强上界",
             "stable": False},
        ],
    }
    status, body = http("POST", "/api/audits", trap)
    assert status == 201, (status, body)
    _verify_certificate_terms("verify-trap-three", trap, body["result"], "-1")
    # 第三项必须在列且乘子为 0
    t2 = body["result"]["terms"][2]
    assert t2["index"] == 2 and t2["label"] == "宽松场强上界"
    assert t2["b"] == "10" and t2["multiplier"] == "0"
    assert t2["weighted_coeffs"] == ["0"] and t2["weighted_rhs"] == "0"
    assert body["result"]["multipliers"][2]["value"] == "0"

    # 同号重传：三项证据完整、第三项乘子仍为 0
    status, replay = http("POST", "/api/audits",
                          json.loads(json.dumps(trap)))
    assert status == 200 and replay["replayed"] is True
    assert replay["created_at"] == body["created_at"]
    assert replay["fingerprint"] == body["fingerprint"]
    _verify_certificate_terms("verify-trap-three", trap,
                              replay["result"], "-1")
    assert replay["result"]["terms"][2]["multiplier"] == "0"

    # 按编号重新读取冻结结果
    status, fetched = http("GET", "/api/audits/verify-trap-three")
    assert status == 200
    assert fetched["created_at"] == body["created_at"]
    _verify_certificate_terms("verify-trap-three", trap,
                              fetched["result"], "-1")
    assert fetched["result"]["terms"][2]["multiplier"] == "0"
    print("[verify-trap-three] 首次提交 / 同号重传 / 按号读取 "
          "均含三项证据，第三项乘子为 0，相加恰为 0 <= -1")
    print("（重启后重开由 pytest 用例 "
          "test_trap_three_evidence_survives_restart 覆盖）")

    # 改动载荷复用同一编号 -> 409，原三项证据不变
    changed = json.loads(json.dumps(trap))
    changed["constraints"][2]["b"] = 99
    status, conflict = http("POST", "/api/audits", changed)
    assert status == 409, (status, conflict)
    assert conflict["existing_fingerprint"] != conflict["new_fingerprint"]
    status, after = http("GET", "/api/audits/verify-trap-three")
    assert status == 200
    _verify_certificate_terms("verify-trap-three", trap,
                              after["result"], "-1")
    assert after["result"]["terms"][2]["b"] == "10"
    print("[verify-trap-three] 改动载荷冲突 409，原三项证据保持不变")

    step("可行系统冒烟: 1 <= x <= 2")
    p = {
        "audit_id": "verify-feasible",
        "variables": ["I1"],
        "constraints": [
            {"coeffs": [1], "b": 2},
            {"coeffs": [-1], "b": -1},
        ],
    }
    status, body = http("POST", "/api/audits", p)
    assert status == 201 and body["result"]["status"] == "feasible"
    x = Fraction(body["result"]["currents"]["I1"])
    assert 1 <= x <= 2
    for m in body["result"]["margins"]:
        assert Fraction(m["residual"]) >= 0
    print("可行解与精确余量核验通过")

    print("\nVERIFY OK: 代码测试、镜像运行与 HTTP 冒烟、精确证书全部通过", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"VERIFY FAILED: {exc}", flush=True)
        sys.exit(1)
