"""任意精度有理数 Phase-I 单纯形。

输入约束: a_i · x <= b_i (i = 1..m)，系数与右端均为整数。

变量模型: 所有电流变量均为自由变量（可正可负），统一按 x = u - v
(u,v >= 0) 处理。约束可带“稳定”元数据标识（不改变数学含义，由上层保存）。
若调用方需要显式非负要求，可追加 internal 行 -x_j <= 0；内部行同样参与
求解与不可行证书，因此证书对每个变量的左侧合并系数仍能严格为 0。

算法:
  * 全部数值使用 :class:`fractions.Fraction`，无浮点;
  * 对右端 b_i<0 的行整体乘以 -1，记 sigma_i = sign(b_i)，
    变换后 c_i = sigma_i*a_i, beta_i = |b_i| >= 0；
    行方程为 c_i·x + sigma_i*s_i + a_i = beta_i
    (b>=0 时 s 为松弛, b<0 时 s 为剩余);
  * 每行人工变量 a_i>=0 初始取值 beta_i 构成合法基;
  * 最小化 w = 人工变量之和，Bland 固定枢轴规则:
    入基取约化成本为负的最小列，出基取最小比值、并列时取基变量下标最小者;
    人工列永不重新入基。规则上杜绝退化循环;
  * w* = 0 -> 可行, 从终基读出有理电流并计算精确余量;
    w* > 0 -> 不可行。终表目标行松弛/剩余列约化成本即 Farkas 乘子
    mu_i >= 0（基列为 0）: 自由变量 u/v 两列约化成本互为相反数且均 >=0，
    故 mu^T A 逐系数为 0，且 mu^T b = -w* < 0。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Sequence


class UnboundedPhaseI(RuntimeError):
    """理论上不应发生: 人工变量和 w>=0 必有下界。"""


@dataclass(frozen=True)
class Constraint:
    coeffs: tuple[int, ...]
    b: int
    label: str | None = None
    internal: bool = False  # 内部追加行（如稳定约束），仍参与证书


@dataclass
class Margin:
    index: int
    label: str | None
    b: int
    residual: Fraction  # b - a·x，精确余量（>= 0 表示满足）

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "label": self.label,
            "b": str(self.b),
            "residual": _frac_str(self.residual),
        }


@dataclass
class CombinedTerm:
    """lambda_i * (a_i · x <= b_i) 在合并式中的逐项贡献。"""

    index: int
    label: str | None
    internal: bool
    multiplier: Fraction
    coeffs: tuple[Fraction, ...]
    rhs: Fraction
    b: int

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "label": self.label,
            "internal": self.internal,
            "b": str(self.b),
            "multiplier": _frac_str(self.multiplier),
            "weighted_coeffs": [_frac_str(c) for c in self.coeffs],
            "weighted_rhs": _frac_str(self.rhs),
        }


@dataclass
class FeasibleResult:
    currents: dict[str, Fraction] = field(default_factory=dict)
    margins: list[Margin] = field(default_factory=list)
    pivots: int = 0

    def as_dict(self) -> dict:
        return {
            "status": "feasible",
            "pivots": self.pivots,
            "currents": {name: _frac_str(v) for name, v in self.currents.items()},
            "margins": [m.as_dict() for m in self.margins],
        }


@dataclass
class InfeasibleResult:
    multipliers: list[Fraction] = field(default_factory=list)
    terms: list[CombinedTerm] = field(default_factory=list)
    combined_lhs: list[Fraction] = field(default_factory=list)  # 必全为 0
    combined_rhs: Fraction = Fraction(0)  # 必严格为负
    pivots: int = 0

    def as_dict(self) -> dict:
        return {
            "status": "infeasible",
            "pivots": self.pivots,
            "multipliers": [
                {"index": i, "value": _frac_str(y)}
                for i, y in enumerate(self.multipliers)
            ],
            "terms": [t.as_dict() for t in self.terms],
            "combined_lhs": [_frac_str(c) for c in self.combined_lhs],
            "combined_rhs": _frac_str(self.combined_rhs),
            "combined_relation": "0 <= " + _frac_str(self.combined_rhs),
        }


Result = FeasibleResult | InfeasibleResult


def _frac_str(v: Fraction) -> str:
    if v.denominator == 1:
        return str(v.numerator)
    return f"{v.numerator}/{v.denominator}"


def solve(
    variable_names: Sequence[str],
    constraints: Sequence[Constraint],
) -> Result:
    n = len(variable_names)
    m = len(constraints)
    if not 1 <= n <= 8:
        raise ValueError("变量个数必须在 1 到 8 之间")
    if not 1 <= m <= 48:
        raise ValueError("约束条数必须在 1 到 48 之间")

    # ---- 列布局: [u_1,v_1,...,u_n,v_n] [slack m 列] [人工 m 列] ----
    slack0 = 2 * n
    art0 = 2 * n + m
    total_cols = 2 * n + 2 * m

    # sigma_i = +1 (b>=0 行不变) / -1 (b<0 行乘 -1)；变换后 c=sigma*a, beta=|b|
    sigma = [1 if con.b >= 0 else -1 for con in constraints]

    tab: list[list[Fraction]] = [
        [Fraction(0) for _ in range(total_cols)] for _ in range(m)
    ]
    rhs: list[Fraction] = []
    basis: list[int] = []
    for i, con in enumerate(constraints):
        s_i = sigma[i]
        for j, a in enumerate(con.coeffs):
            tab[i][2 * j] = Fraction(s_i * a)      # u_j
            tab[i][2 * j + 1] = Fraction(-s_i * a)  # v_j
        tab[i][slack0 + i] = Fraction(s_i)  # b<0 时为剩余变量(-1)
        tab[i][art0 + i] = Fraction(1)
        rhs.append(Fraction(s_i * con.b))  # |b| >= 0
        basis.append(art0 + i)

    # w = Σ art_i = Σ beta_i - Σ c_i·u + Σ c_i·v - Σ sigma_i*s_i
    obj: list[Fraction] = [Fraction(0) for _ in range(total_cols)]
    obj0 = Fraction(0)
    for i, con in enumerate(constraints):
        s_i = sigma[i]
        obj0 += Fraction(s_i * con.b)
        for j, a in enumerate(con.coeffs):
            obj[2 * j] -= Fraction(s_i * a)
            obj[2 * j + 1] += Fraction(s_i * a)
        obj[slack0 + i] -= Fraction(s_i)
    # 人工列目标系数恒为 0，且永不允许重新入基

    pivots = 0
    while True:
        # Bland 入基: 约化成本为负的最小列（跳过基列与人工列）
        entering = -1
        basis_set = set(basis)
        for col in range(art0):
            if col in basis_set:
                continue
            if obj[col] < 0:
                entering = col
                break
        if entering < 0:
            break  # 最优

        # Bland 出基: 严格最小比值；并列取基变量下标最小
        leaving = -1
        best_ratio: Fraction | None = None
        for r in range(m):
            a = tab[r][entering]
            if a > 0:
                ratio = rhs[r] / a
                if (
                    best_ratio is None
                    or ratio < best_ratio
                    or (ratio == best_ratio and basis[r] < basis[leaving])
                ):
                    best_ratio = ratio
                    leaving = r
        if leaving < 0:
            raise UnboundedPhaseI("Phase-I 目标无界，约束构造有误")

        # ---- 高斯-若当枢轴 ----
        a = tab[leaving][entering]
        for j in range(total_cols):
            tab[leaving][j] /= a
        rhs[leaving] /= a

        for r in range(m):
            if r == leaving:
                continue
            factor = tab[r][entering]
            if factor == 0:
                continue
            for j in range(total_cols):
                tab[r][j] -= factor * tab[leaving][j]
            rhs[r] -= factor * rhs[leaving]
        factor = obj[entering]
        for j in range(total_cols):
            obj[j] -= factor * tab[leaving][j]
        obj0 += factor * rhs[leaving]
        basis[leaving] = entering
        pivots += 1

    values = [Fraction(0) for _ in range(total_cols)]
    for r, col in enumerate(basis):
        values[col] = rhs[r]

    if obj0 == 0:
        currents = {
            name: values[2 * j] - values[2 * j + 1]
            for j, name in enumerate(variable_names)
        }
        margins = []
        for i, con in enumerate(constraints):
            if con.internal:
                continue
            residual = Fraction(con.b) - sum(
                (Fraction(con.coeffs[j]) * currents[name]
                 for j, name in enumerate(variable_names)),
                Fraction(0),
            )
            margins.append(Margin(i, con.label, con.b, residual))
        return FeasibleResult(currents=currents, margins=margins, pivots=pivots)

    # ---- 不可行: Farkas 乘子 mu_i = 终表 slack/剩余列约化成本 ----
    multipliers = []
    for i in range(m):
        mu = obj[slack0 + i]
        if mu < 0:
            raise RuntimeError("Farkas 乘子为负，枢轴实现有误")
        multipliers.append(mu)

    combined_lhs = [
        sum((multipliers[i] * Fraction(constraints[i].coeffs[j])
             for i in range(m)), Fraction(0))
        for j in range(n)
    ]
    combined_rhs = sum(
        (multipliers[i] * Fraction(constraints[i].b) for i in range(m)),
        Fraction(0),
    )
    if any(v != 0 for v in combined_lhs):
        raise RuntimeError("Farkas 证书左合并非零")
    if combined_rhs != -obj0 or combined_rhs >= 0:
        raise RuntimeError("Farkas 证书右端不满足严格为负")

    terms = [
        CombinedTerm(
            index=i,
            label=con.label,
            internal=con.internal,
            multiplier=multipliers[i],
            coeffs=tuple(multipliers[i] * Fraction(a) for a in con.coeffs),
            rhs=multipliers[i] * Fraction(con.b),
            b=con.b,
        )
        for i, con in enumerate(constraints)
    ]
    return InfeasibleResult(
        multipliers=multipliers,
        terms=terms,
        combined_lhs=combined_lhs,
        combined_rhs=combined_rhs,
        pivots=pivots,
    )
