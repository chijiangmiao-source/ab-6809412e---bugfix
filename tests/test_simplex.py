"""Phase-I 精确单纯形测试：

* 可行解回代满足每条 a·x <= b，余量非负且精确；
* 不可行证书满足 μ >= 0、μ^T A = 0、μ^T b < 0，并独立核验逐项合并；
* 与 Fourier–Motzkin 消元在大量小算例上判定一致；
* 退化算例（Bland 规则必须终止）、大整数、自由变量负解。
"""

from __future__ import annotations

import itertools
import random

import pytest

from app.simplex import Constraint, solve
from app.models import verify_certificate

from fourier_motzkin import fm_feasible


def C(coeffs, b, label=None, internal=False):
    return Constraint(tuple(coeffs), b, label=label, internal=internal)


def assert_feasible(names, cons):
    r = solve(names, cons)
    assert r.__class__.__name__ == "FeasibleResult", "应当可行"
    for con in [c for c in cons if not c.internal]:
        lhs = sum(
            con.coeffs[j] * r.currents[name]
            for j, name in enumerate(names)
        )
        assert lhs <= con.b
        m = next(x for x in r.margins if x.index == cons.index(con))
        assert m.residual == con.b - lhs
        assert m.residual >= 0
    return r


def assert_infeasible(names, cons):
    r = solve(names, cons)
    assert r.__class__.__name__ == "InfeasibleResult", "应当无解"
    assert all(mu >= 0 for mu in r.multipliers)
    m = len(cons)
    n = len(names)
    for j in range(n):
        s = sum(r.multipliers[i] * cons[i].coeffs[j] for i in range(m))
        assert s == 0, f"列 {j} 合并非零: {s}"
        assert r.combined_lhs[j] == s
    rhs = sum(r.multipliers[i] * cons[i].b for i in range(m))
    assert rhs < 0
    assert rhs == r.combined_rhs
    # 逐项数据自洽
    for i, t in enumerate(r.terms):
        assert t.multiplier == r.multipliers[i]
        assert list(t.coeffs) == [
            r.multipliers[i] * a for a in cons[i].coeffs
        ]
        assert t.rhs == r.multipliers[i] * cons[i].b
    d = r.as_dict()
    verify_certificate(d)
    return r


def test_zero_leq_minus_one():
    """verify 容器使用的证书算例: 0 <= -1。"""
    r = assert_infeasible(["x"], [C([0], -1)])
    assert r.multipliers == [1]
    assert r.combined_rhs == -1
    assert r.pivots == 0  # 初始基即最优，直接出证书


def test_simple_interval_feasible():
    r = assert_feasible(["x"], [C([1], 2), C([-1], -1)])  # 1 <= x <= 2
    assert 1 <= r.currents["x"] <= 2


def test_simple_interval_infeasible():
    r = assert_infeasible(["x"], [C([1], 1), C([-1], -2)])  # x<=1, x>=2
    assert r.multipliers[0] > 0 and r.multipliers[1] > 0
    assert r.combined_rhs == -1


def test_negative_b_feasible_free_var():
    # -x <= -5  => x >= 5，自由变量必须能取正值
    r = assert_feasible(["x"], [C([-1], -5)])
    assert r.currents["x"] >= 5


def test_negative_solution_free_var():
    # x <= -3，自由变量必须能取负值（验证 u-v 拆分有效）
    r = assert_feasible(["x"], [C([1], -3)])
    assert r.currents["x"] <= -3


def test_two_var_infeasible():
    assert_infeasible(["x", "y"], [C([1, 1], 1), C([-1, -1], -2)])


def test_two_var_feasible():
    r = assert_feasible(
        ["x", "y"],
        [C([2, 4], 10), C([-1, 0], 0), C([0, -1], 0)],
    )
    assert 2 * r.currents["x"] + 4 * r.currents["y"] <= 10


def test_rational_solution_is_exact():
    # 2x <= 1 => x 可能是 1/2
    r = assert_feasible(["x"], [C([2], 1), C([-2], -1)])
    assert r.currents["x"] * 2 == 1
    assert r.margins[0].residual == 0


def test_huge_integers_exact():
    z = 10**80
    # z*x <= z, z*x >= z  => x = 1，全程任意精度
    r = assert_feasible(["x"], [C([z], z), C([-z], -z)])
    assert r.currents["x"] == 1


def test_huge_integers_certificate():
    z = 10**80
    r = assert_infeasible(["x"], [C([z], z), C([-z], -2 * z)])
    assert r.combined_rhs == -z


def test_redundant_zero_rows():
    # 0 <= 0 是重言式，不应影响判定
    assert_feasible(["x"], [C([0], 0), C([1], 5), C([-1], 0, internal=True)])


def test_certificate_with_internal_rows():
    # 稳定行 -x<=0 与 x<=-1 矛盾；证书含内部行且逐列合并严格为 0
    r = assert_infeasible(
        ["x"], [C([-1], 0, internal=True), C([1], -1)]
    )
    assert r.multipliers[0] == 1 and r.multipliers[1] == 1
    assert r.combined_rhs == -1
    assert r.terms[0].internal is True


@pytest.mark.parametrize("seed", range(40))
def test_fuzz_against_fourier_motzkin(seed):
    """随机小系统：单纯形判定必须与 FM 消元一致。"""
    rng = random.Random(seed)
    n = rng.randint(1, 3)
    m = rng.randint(1, 6)
    A = [[rng.randint(-2, 2) for _ in range(n)] for _ in range(m)]
    b = [rng.randint(-3, 3) for _ in range(m)]
    names = [f"x{j}" for j in range(n)]
    cons = [C(row, rhs) for row, rhs in zip(A, b)]
    expected = fm_feasible(A, b)
    if expected:
        r = assert_feasible(names, cons)
        # 直接用 Fraction 再核验一次
        for row, rhs in zip(A, b):
            assert sum(row[j] * r.currents[names[j]] for j in range(n)) <= rhs
    else:
        assert_infeasible(names, cons)


def test_all_sign_patterns_2d():
    """与 FM 对照若干典型 2 变量系统，并全枚举两约束单变量系统。"""
    systems = [
        ([1, 0], 1, [-1, 0], -2),    # x<=1, x>=2
        ([1, 0], 0, [-1, 0], 0),     # x=0 可行
        ([1, 1], 0, [-1, -1], 0),    # x+y=0 可行
    ]
    for a1, b1, a2, b2 in systems:
        cons = [C(a1, b1), C(a2, b2)]
        assert (
            solve(["x", "y"], cons).__class__.__name__
            == ("FeasibleResult" if fm_feasible([a1, a2], [b1, b2])
                else "InfeasibleResult")
        )

    # 全枚举单变量系统: a in {-2..2}, b in {-2..2}，两约束
    vals = range(-2, 3)
    for a1, a2, b1, b2 in itertools.product(vals, vals, vals, vals):
        cons = [C([a1], b1), C([a2], b2)]
        r = solve(["x"], cons)
        expected = fm_feasible([[a1], [a2]], [b1, b2])
        got = r.__class__.__name__ == "FeasibleResult"
        assert got == expected, (a1, b1, a2, b2)
        if not got:
            assert_infeasible(["x"], cons)


def test_degenerate_system_terminates():
    """经典退化循环样例（Beale）的等价不等式化形式必须在 Bland 下终止。

    构造多约束在原点重合的退化系统；非 Bland 规则可能循环。
    """
    # x1,x2,x3 >= 0 (内部行) + 三条上界交于原点的约束
    cons = [
        C([-1, 0, 0], 0, internal=True),
        C([0, -1, 0], 0, internal=True),
        C([0, 0, -1], 0, internal=True),
        C([1, 1, 1], 0),
        C([1, 0, 0], 0),
        C([0, 1, 0], 0),
    ]
    r = assert_feasible(["x1", "x2", "x3"], cons)
    assert r.currents["x1"] == 0
    assert r.currents["x2"] == 0
    assert r.currents["x3"] == 0


def test_highly_degenerate_system_terminates():
    """多条约束在原点同时取等的高度退化系统：Bland 必须有限终止、不得循环。"""
    cons = [
        C([1, -11, -5, 18], 0),
        C([1, -3, -1, 2], 0),
        C([2, 0, 0, 0], 2),
        C([-1, 0, 0, 0], 0, internal=True),
        C([0, -1, 0, 0], 0, internal=True),
        C([0, 0, -1, 0], 0, internal=True),
        C([0, 0, 0, -1], 0, internal=True),
    ]
    r = assert_feasible(["x1", "x2", "x3", "x4"], cons)
    assert r.pivots > 0  # 确实经历了枢轴，且有限终止（未循环）
    assert r.currents["x1"] <= 1
    assert (r.currents["x1"] - 11 * r.currents["x2"]
            - 5 * r.currents["x3"] + 18 * r.currents["x4"]) <= 0


def test_eight_variables_forty_eight_constraints():
    names = [f"I{j}" for j in range(8)]
    cons = [C([1 if k == j else 0 for j in range(8)], 100)
            for k in range(8)]
    cons += [C([-1 if k == j else 0 for j in range(8)], 0, internal=True)
             for k in range(8)]
    # 加 32 条一般约束，构成可行盒
    rng = random.Random(7)
    while len(cons) < 48:
        row = [rng.randint(-2, 2) for _ in range(8)]
        if all(v == 0 for v in row):
            continue
        cons.append(C(row, 1000))
    r = assert_feasible(names, cons)
    assert len(r.margins) == 40  # 8 条内部行不出现在用户余量中


def test_as_dict_round_trip_strings():
    r = assert_infeasible(["x"], [C([0], -1)])
    d = r.as_dict()
    # 所有数字都是字符串（精确有理），无浮点
    import json
    s = json.dumps(d)
    assert "0 <= -1" in s
    assert d["combined_rhs"] == "-1"
