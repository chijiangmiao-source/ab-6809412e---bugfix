"""HTTP 端到端测试：真实套接字上的状态码、幂等/冲突/非法语义与健康检查。"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from fractions import Fraction

import pytest

from app.web import make_server


@pytest.fixture()
def server(tmp_path):
    httpd = make_server(host="127.0.0.1", port=0,
                        data_dir=str(tmp_path / "data"))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    port = httpd.server_address[1]
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def req(base, method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(base + path, data=data, headers=headers,
                               method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


P_INFEASIBLE = {
    "audit_id": "cert-1",
    "variables": ["x"],
    "constraints": [{"coeffs": [0], "b": -1, "stable": True}],
}


def test_healthz(server):
    status, body = req(server, "GET", "/healthz")
    assert status == 200 and body["status"] == "ok"


def test_index_html(server):
    r = urllib.request.Request(server + "/")
    with urllib.request.urlopen(r, timeout=10) as resp:
        html = resp.read().decode("utf-8")
    assert resp.status == 200 and "单纯形" in html


def test_submit_infeasible_returns_certificate(server):
    status, body = req(server, "POST", "/api/audits", P_INFEASIBLE)
    assert status == 201
    assert body["replayed"] is False
    res = body["result"]
    assert res["status"] == "infeasible"
    assert res["combined_relation"] == "0 <= -1"
    # 浏览器/工程师可以独立核验
    mus = [Fraction(t["multiplier"]) for t in res["terms"]]
    assert mus == [1]
    assert res["terms"][0]["b"] == "-1"


def test_replay_identical_is_200(server):
    assert req(server, "POST", "/api/audits", P_INFEASIBLE)[0] == 201
    status, body = req(server, "POST", "/api/audits",
                       json.loads(json.dumps(P_INFEASIBLE)))
    assert status == 200 and body["replayed"] is True


def test_conflict_is_409_and_evidence_unchanged(server):
    req(server, "POST", "/api/audits", P_INFEASIBLE)
    changed = json.loads(json.dumps(P_INFEASIBLE))
    changed["constraints"][0]["b"] = 0
    status, body = req(server, "POST", "/api/audits", changed)
    assert status == 409
    assert body["error"] == "audit_id_conflict"
    assert body["existing_fingerprint"] != body["new_fingerprint"]

    status, body = req(server, "GET", "/api/audits/cert-1")
    assert status == 200
    assert body["result"]["status"] == "infeasible"
    assert body["result"]["combined_rhs"] == "-1"


def test_invalid_payload_400_no_artifact(server):
    bad = json.loads(json.dumps(P_INFEASIBLE))
    bad["constraints"][0]["b"] = -1.25
    status, body = req(server, "POST", "/api/audits", bad)
    assert status == 400 and body["error"] == "invalid_payload"
    assert req(server, "GET", "/api/audits/cert-1")[0] == 404


def test_invalid_payload_after_freeze_keeps_old(server):
    """非法重传不得覆盖或污染已冻结的旧结论。"""
    status, body = req(server, "POST", "/api/audits", P_INFEASIBLE)
    assert status == 201
    fp = body["fingerprint"]

    bad = json.loads(json.dumps(P_INFEASIBLE))
    bad["constraints"][0]["b"] = 1.5
    status, _ = req(server, "POST", "/api/audits", bad)
    assert status == 400

    status, body = req(server, "GET", "/api/audits/cert-1")
    assert status == 200
    assert body["fingerprint"] == fp
    assert body["result"]["combined_rhs"] == "-1"


def test_bad_json_400(server):
    r = urllib.request.Request(
        server + "/api/audits", data=b"{not json",
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(r, timeout=10)
        assert False
    except urllib.error.HTTPError as e:
        assert e.code == 400


def test_feasible_flow(server):
    p = {
        "audit_id": "feas-1",
        "variables": ["x", "y"],
        "constraints": [
            {"coeffs": [1, 1], "b": 1, "stable": False},
            {"coeffs": [-1, -1], "b": 0, "stable": False},
        ],
    }
    status, body = req(server, "POST", "/api/audits", p)
    assert status == 201 and body["result"]["status"] == "feasible"
    x = Fraction(body["result"]["currents"]["x"])
    y = Fraction(body["result"]["currents"]["y"])
    assert x + y <= 1
    for m in body["result"]["margins"]:
        assert Fraction(m["residual"]) >= 0


def test_huge_integer_preserves_precision(server):
    """超过 2^53 的整数（前端用 BigInt 式文本提交）必须端到端保持精度。"""
    z = 10**60
    p = {
        "audit_id": "bigint-feas",
        "variables": ["I1"],
        "constraints": [
            {"coeffs": [z], "b": z, "label": None, "stable": False},
            {"coeffs": [-z], "b": -z, "label": None, "stable": False},
        ],
    }
    status, body = req(server, "POST", "/api/audits", p)
    assert status == 201, body
    assert body["result"]["status"] == "feasible"
    assert Fraction(body["result"]["currents"]["I1"]) == 1

    p2 = {
        "audit_id": "bigint-inf",
        "variables": ["I1"],
        "constraints": [
            {"coeffs": [z], "b": z},
            {"coeffs": [-z], "b": -(2 * z)},
        ],
    }
    status, body = req(server, "POST", "/api/audits", p2)
    assert status == 201, body
    assert body["result"]["status"] == "infeasible"
    assert Fraction(body["result"]["combined_rhs"]) == -z
    assert body["result"]["terms"][0]["multiplier"] == "1"


def test_404_unknown_id(server):
    assert req(server, "GET", "/api/audits/ghost")[0] == 404


def test_persistence_across_server_instances(tmp_path):
    data = str(tmp_path / "data")

    def start():
        import app.web as web
        web.Handler.service = None
        httpd = make_server("127.0.0.1", 0, data)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd

    s1 = start()
    port1 = s1.server_address[1]
    req(f"http://127.0.0.1:{port1}", "POST", "/api/audits", P_INFEASIBLE)
    s1.shutdown()
    s1.server_close()

    s2 = start()
    port2 = s2.server_address[1]
    status, body = req(f"http://127.0.0.1:{port2}", "GET",
                       "/api/audits/cert-1")
    assert status == 200 and body["result"]["combined_rhs"] == "-1"
    s2.shutdown()
    s2.server_close()
