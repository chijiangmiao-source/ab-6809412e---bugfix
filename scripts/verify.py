"""verify 单次容器入口。

依次完成:
  1. 代码测试 (pytest)；
  2. HTTP 冒烟 (健康检查 / 页面 / 未知编号 404)；
  3. 用“相加得 0 <= -1”的约束组经真实 HTTP 提交核对不可行证书；
     独立重算 mu >= 0、Σmu*a = 0、Σmu*b < 0，并核对幂等(200)与冲突(409)。

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

    terms = res["terms"]
    n = len(payload["variables"])
    lhs = [Fraction(0) for _ in range(n)]
    rhs = Fraction(0)
    for t in terms:
        mu = Fraction(t["multiplier"])
        assert mu >= 0, "乘子必须非负"
        assert len(t["weighted_coeffs"]) == n
        assert Fraction(t["weighted_rhs"]) == mu * Fraction(t["b"])
        for j in range(n):
            lhs[j] += Fraction(t["weighted_coeffs"][j])
        rhs += Fraction(t["weighted_rhs"])
    assert all(v == 0 for v in lhs), f"左侧合并必须全为 0: {lhs}"
    assert rhs < 0, f"右侧合并必须严格为负: {rhs}"
    assert res["combined_rhs"] == expect_rhs == str(rhs)
    assert res["combined_relation"] == f"0 <= {expect_rhs}"
    print(f"[{audit_id}] 证书核验通过: mu>=0, Σmu·a=0, Σmu·b={rhs}")

    # 幂等：完全相同载荷重放 -> 200 同一记录
    status2, body2 = http("POST", "/api/audits",
                          json.loads(json.dumps(payload)))
    assert status2 == 200 and body2["replayed"] is True
    assert body2["fingerprint"] == body["fingerprint"]
    assert body2["created_at"] == body["created_at"]
    print(f"[{audit_id}] 重放返回同一冻结记录 (200)")

    # 冲突：同编号改载荷 -> 409，原证据不变
    changed = json.loads(json.dumps(payload))
    changed["constraints"][0]["b"] = changed["constraints"][0]["b"] + 1
    status3, body3 = http("POST", "/api/audits", changed)
    assert status3 == 409, (status3, body3)
    status4, body4 = http("GET", f"/api/audits/{audit_id}")
    assert status4 == 200 and body4["result"]["combined_rhs"] == expect_rhs
    print(f"[{audit_id}] 改动载荷冲突 409，原证据保持不变")
    return res


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
