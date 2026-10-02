"""审计冻结记录存储。

同一 audit_id + 完全相同载荷 -> 返回同一记录（幂等）；
同一 audit_id + 不同载荷     -> 冲突，原记录保持不变；
非法载荷在写入前即被拒绝，不会残留或覆盖任何结论。

每条记录一个 JSON 文件，临时文件 + fsync + 原子 rename 落盘，
进程内以锁串行化“检查-写入”，避免并发首次提交产生双结论。

不可行证书为**每一条原始约束**保留一个乘子与一项合并式贡献，
包括乘子为 0 的条目（零贡献项同样可逐项复核：索引、标签、系数、
右端与原始录入顺序一一对应）。历史版本曾在落盘时剔除零乘子条目，
读取时会按冻结载荷就地恢复为完整证据，且不改变审计编号、创建时间、
载荷指纹与可行性裁决。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from fractions import Fraction


class IdConflictError(Exception):
    def __init__(self, existing: dict, new_fingerprint: str):
        self.existing = existing
        self.new_fingerprint = new_fingerprint
        super().__init__("audit_id 已绑定不同载荷")


def canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def fingerprint(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


def _needs_restore(record: dict) -> bool:
    """检测历史版本落盘时剔除过零乘子条目的不完整证书。"""
    result = record.get("result")
    if not isinstance(result, dict) or result.get("status") != "infeasible":
        return False
    constraints = record.get("payload", {}).get("constraints", [])
    m = len(constraints)
    if "evidence_term_count" in result:
        return True
    if len(result.get("multipliers", [])) < m:
        return True
    term_indices = {t.get("index") for t in result.get("terms", [])}
    return any(i not in term_indices for i in range(m))


def restore_full_evidence(record: dict) -> dict:
    """按冻结载荷把被剔除的零乘子条目补回原位，返回完整记录。

    仅重建 result 中的 multipliers/terms；审计编号、创建时间、载荷指纹、
    载荷本身与裁决全部原样保留。补入项乘子为 0，故合并式不变；
    若现存条目自身相加与冻结的合并式不一致（文件损坏），抛 ValueError
    且不写回。
    """
    result = record["result"]
    constraints = record["payload"]["constraints"]
    m = len(constraints)

    mult_by_idx = {int(x["index"]): x for x in result.get("multipliers", [])}
    term_by_idx = {int(t["index"]): t for t in result.get("terms", [])}

    full_multipliers: list[dict] = []
    full_terms: list[dict] = []
    for i, con in enumerate(constraints):
        old_term = term_by_idx.get(i)
        if old_term is not None:
            full_terms.append(old_term)
            mu_str = old_term["multiplier"]
            old_mult = mult_by_idx.get(i)
            if old_mult is not None and old_mult.get("value") != mu_str:
                raise ValueError("冻结证书乘子与逐项贡献不一致")
            full_multipliers.append(old_mult or {"index": i, "value": mu_str})
            continue
        # 被历史版本剔除的条目：乘子必为 0，否则不应缺失
        if i in mult_by_idx and Fraction(mult_by_idx[i]["value"]) != 0:
            raise ValueError("冻结证书缺失非零乘子条目，记录可能已损坏")
        full_multipliers.append({"index": i, "value": "0"})
        # 用户录入约束不存在 internal 行；internal 仅求解器内部使用
        full_terms.append({
            "index": i,
            "label": con.get("label"),
            "internal": False,
            "b": str(con["b"]),
            "multiplier": "0",
            "weighted_coeffs": ["0" for _ in con["coeffs"]],
            "weighted_rhs": "0",
        })

    n = len(constraints[0]["coeffs"]) if constraints else 0
    lhs = [Fraction(0) for _ in range(n)]
    rhs_sum = Fraction(0)
    for t in full_terms:
        mu = Fraction(t["multiplier"])
        if mu < 0:
            raise ValueError("冻结证书含负乘子，记录可能已损坏")
        weighted = [Fraction(s) for s in t["weighted_coeffs"]]
        if len(weighted) != n:
            raise ValueError("冻结证书逐项系数长度与载荷不符")
        if Fraction(t["weighted_rhs"]) != mu * Fraction(t["b"]):
            raise ValueError("冻结证书逐项加权右端不自洽")
        for j in range(n):
            lhs[j] += weighted[j]
        rhs_sum += Fraction(t["weighted_rhs"])

    stored_lhs = [Fraction(s) for s in result.get("combined_lhs", [])]
    stored_rhs = Fraction(result["combined_rhs"])
    if stored_lhs != lhs or stored_rhs != rhs_sum or stored_rhs >= 0:
        raise ValueError("补全零乘子条目后合并式与冻结结论不一致，拒绝恢复")

    restored_result = {
        k: v for k, v in result.items() if k != "evidence_term_count"
    }
    restored_result["multipliers"] = full_multipliers
    restored_result["terms"] = full_terms

    restored = dict(record)
    restored["result"] = restored_result
    return restored


class AuditStore:
    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        # 可重入：submit 持锁时调用 get() 做读取即恢复
        self._lock = threading.RLock()

    def _path(self, audit_id: str) -> str:
        safe = hashlib.sha256(audit_id.encode("utf-8")).hexdigest()
        return os.path.join(self.data_dir, f"{safe}.json")

    def _read_raw(self, audit_id: str) -> dict | None:
        path = self._path(audit_id)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            record = self._read_raw(audit_id)
            if record is None or not _needs_restore(record):
                return record
            try:
                restored = restore_full_evidence(record)
            except (ValueError, KeyError, TypeError, ZeroDivisionError):
                # 损坏的旧记录不自动改写；原样返回便于人工复核
                return record
            # 恢复只补零乘子条目：编号/创建时间/指纹/载荷/裁决均不变
            self._write_atomic(audit_id, restored)
            return restored

    def submit(self, audit_id: str, payload_canonical: dict, result: dict) -> tuple[dict, bool]:
        """返回 (记录, 是否为重放)。冲突时抛 :class:`IdConflictError`。"""
        new_fp = fingerprint(payload_canonical)
        with self._lock:
            existing = self.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] != new_fp:
                    raise IdConflictError(existing, new_fp)
                return existing, True

            record = {
                "audit_id": audit_id,
                "created_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "fingerprint": new_fp,
                "payload": payload_canonical,
                "result": result,
                "method": "phase-I-simplex/exact-rational/Bland",
            }
            self._write_atomic(audit_id, record)
            return record, False

    def _write_atomic(self, audit_id: str, record: dict) -> None:
        path = self._path(audit_id)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
