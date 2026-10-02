"""审计冻结记录存储。

同一 audit_id + 完全相同载荷 -> 返回同一记录（幂等）；
同一 audit_id + 不同载荷     -> 冲突，原记录保持不变；
非法载荷在写入前即被拒绝，不会残留或覆盖任何结论。

每条记录一个 JSON 文件，临时文件 + fsync + 原子 rename 落盘，
进程内以锁串行化“检查-写入”，避免并发首次提交产生双结论。

证书完整性: 不可行结果必须为**每条**原始约束保留一个乘子与一项合并式
贡献，即使该约束在本次矛盾证明中的乘子恰为 0；审查员据此才能把条目
索引/标签/稳定标识/系数/右端与原始录入顺序逐一对应。早期版本曾在落盘
时丢弃乘子为 0 的条目，读取时会对这类历史记录做惰性补全：依据冻结载荷
重新求解，补回全部条目，但 audit_id / created_at / fingerprint /
可行性裁决一律不变。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

from .simplex import Constraint, solve


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


def _constraints_from_payload(payload: dict) -> list[Constraint]:
    """从冻结载荷按原始录入顺序重建求解器约束（标签随条目保留）。"""
    return [
        Constraint(
            coeffs=tuple(int(a) for a in item["coeffs"]),
            b=int(item["b"]),
            label=item.get("label"),
        )
        for item in payload["constraints"]
    ]


def _evidence_complete(record: dict) -> bool:
    """完整证书: 不可行结果的乘子与合并项条数均等于原始约束条数。

    乘子为 0 的约束也必须逐项在列，因此只看条数即可识别早期版本
    “落盘时丢弃零乘子条目”的残缺冻结。
    """
    result = record.get("result") or {}
    if result.get("status") != "infeasible":
        return True
    n_cons = len(record.get("payload", {}).get("constraints", []))
    return (
        len(result.get("multipliers", [])) == n_cons
        and len(result.get("terms", [])) == n_cons
    )


def _rebuild_infeasible_result(record: dict) -> dict:
    """按冻结载荷重解，补全每条约束（含零乘子）的证书条目。

    仅替换 result 内部；audit_id / created_at / fingerprint / payload /
    method 与可行性裁决均保持不变。载荷在冻结前已通过整数校验，
    且求解是纯函数，重解必然仍是 infeasible（同输入同输出）。
    """
    payload = record["payload"]
    rebuilt = solve(
        list(payload["variables"]),
        _constraints_from_payload(payload),
    )
    if rebuilt.__class__.__name__ != "InfeasibleResult":
        raise RuntimeError(
            "补全证书时重解裁决发生变化，拒绝修改冻结记录: "
            f"{record.get('audit_id')}"
        )
    result = rebuilt.as_dict()
    old = record["result"]
    # 保留旧记录中的非证书附加字段（如 stable_flags）；
    # evidence_term_count 是早期压缩版本的过时字段，必须丢弃。
    for key, value in old.items():
        if key == "evidence_term_count":
            continue
        result.setdefault(key, value)
    return result


def _restore_record(record: dict) -> tuple[dict, bool]:
    """必要时惰性补全历史残缺证书。

    返回 (记录, 是否发生了修复写盘)。补全只改写 result 的证书条目，
    不改 audit_id / created_at / fingerprint / payload / 裁决。
    """
    if _evidence_complete(record):
        return record, False
    restored = dict(record)
    restored["result"] = _rebuild_infeasible_result(record)
    return restored, True


class AuditStore:
    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, audit_id: str) -> str:
        safe = hashlib.sha256(audit_id.encode("utf-8")).hexdigest()
        return os.path.join(self.data_dir, f"{safe}.json")

    def _read_unlocked(self, audit_id: str) -> dict | None:
        path = self._path(audit_id)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def get(self, audit_id: str) -> dict | None:
        """读取冻结记录；对历史残缺证书做一次惰性补全并重写。"""
        with self._lock:
            record = self._read_unlocked(audit_id)
            if record is None:
                return None
            restored, changed = _restore_record(record)
            if changed:
                self._write_atomic(audit_id, restored)
            return restored

    def submit(self, audit_id: str, payload_canonical: dict, result: dict) -> tuple[dict, bool]:
        """返回 (记录, 是否为重放)。冲突时抛 :class:`IdConflictError`。"""
        new_fp = fingerprint(payload_canonical)
        with self._lock:
            existing = self._read_unlocked(audit_id)
            if existing is not None:
                if existing["fingerprint"] != new_fp:
                    raise IdConflictError(existing, new_fp)
                restored, changed = _restore_record(existing)
                if changed:
                    # 修复历史残缺证据；编号/创建时间/指纹/裁决均不变
                    self._write_atomic(audit_id, restored)
                return restored, True

            if not _evidence_complete(
                {"payload": payload_canonical, "result": result}
            ):
                # 防御：求解器必须为每条约束产出条目；绝不落盘残缺证书
                raise RuntimeError("证书缺少部分约束条目，拒绝冻结")
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

    def migrate_all(self) -> int:
        """扫描数据目录，恢复所有历史残缺证书；返回修复的记录数。

        仅供服务启动时调用：编号/创建时间/载荷指纹/裁决均不变。
        单条记录异常不影响其他记录与服务启动。
        """
        restored_count = 0
        with self._lock:
            for name in sorted(os.listdir(self.data_dir)):
                if not name.endswith(".json"):
                    continue
                path = os.path.join(self.data_dir, name)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        record = json.load(f)
                    restored, changed = _restore_record(record)
                except (OSError, ValueError, KeyError, RuntimeError):
                    continue
                if changed:
                    try:
                        self._write_atomic(restored["audit_id"], restored)
                        restored_count += 1
                    except OSError:
                        continue
        return restored_count
