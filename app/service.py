"""审计编排: 校验 -> 精确 Phase-I 求解 -> 冻结/重放。"""

from __future__ import annotations

from .models import AuditPayload, parse_payload
from .simplex import solve
from .storage import AuditStore, IdConflictError

__all__ = ["AuditService", "IdConflictError"]


class AuditService:
    def __init__(self, store: AuditStore):
        self.store = store

    def audit(self, raw_payload) -> tuple[dict, bool]:
        """返回 (冻结记录, 是否为重放命中)。载荷非法时抛 ValueError，不写任何记录。"""
        parsed: AuditPayload = parse_payload(raw_payload)
        result = solve(parsed.variables, parsed.constraints).as_dict()
        result["stable_flags"] = list(parsed.stable_flags)
        record, replayed = self.store.submit(
            parsed.audit_id, parsed.canonical(), result
        )
        return record, replayed

    def fetch(self, audit_id: str) -> dict | None:
        return self.store.get(audit_id)
