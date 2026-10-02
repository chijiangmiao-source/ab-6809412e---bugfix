"""独立交叉验证: Fourier–Motzkin 消元判定可行性（与单纯形完全不同的算法）。

仅用于测试，允许指数级膨胀，故只处理很小的算例。
"""

from __future__ import annotations

from fractions import Fraction


def fm_feasible(A: list[list[int]], b: list[int]) -> bool:
    """判断是否存在自由变量 x 使 A x <= b（有理数域）。"""
    rows = [([Fraction(x) for x in row], Fraction(rhs)) for row, rhs in zip(A, b)]

    while rows and rows[0][0]:
        pos, zero, neg = [], [], []
        for row, rhs in rows:
            c = row[0]
            if c > 0:
                pos.append((row, rhs))
            elif c < 0:
                neg.append((row, rhs))
            else:
                zero.append((row[1:], rhs))
        new = list(zero)
        for rp, bp in pos:
            cp = rp[0]
            for rn, bn in neg:
                cn = rn[0]  # < 0
                # 合并: (1/cp)*rp 与 (-1/cn)*rn 相加消去首变量
                f1, f2 = 1 / cp, -1 / cn
                new.append(
                    (
                        [f1 * rp[k] + f2 * rn[k] for k in range(1, len(rp))],
                        f1 * bp + f2 * bn,
                    )
                )
        rows = new

    return all(rhs >= 0 for _, rhs in rows)
