"""Schema-tolerant audit-log helpers.

The helpers preserve compatibility with the original database while recording
run and authentication-attempt identifiers when the version-2 migration has
been applied. Context is also embedded in ``auth_logs_details`` so legacy
databases do not silently lose experiment linkage.
"""

import json
from typing import Any, Dict, Optional


def _columns(cursor, table: str):
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s
        """,
        (table,),
    )
    return {row[0] for row in cursor.fetchall()}


def insert_auth_log(
    conn,
    *,
    username: str,
    event_type: str,
    success: bool,
    message: Optional[str] = None,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
    mfa_mode: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    payload: Dict[str, Any] = dict(details or {})
    if message is not None:
        payload["message"] = str(message)
    if run_id is not None:
        payload["run_id"] = str(run_id)
    if attempt_id is not None:
        payload["attempt_id"] = str(attempt_id)
    if mfa_mode is not None:
        payload["mfa_mode"] = str(mfa_mode)

    with conn.cursor() as cursor:
        available = _columns(cursor, "auth_logs")
        database_username = username
        if username and "username" in available:
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username=%s)",
                (username,),
            )
            exists = cursor.fetchone()
            if not exists or not exists[0]:
                payload["attempted_username"] = str(username)
                database_username = None
        values = {
            "username": database_username,
            "event_type": event_type,
            "ip_address": ip_address,
            "auth_logs_details": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            "user_agent": user_agent,
            "success": bool(success),
            "run_id": run_id,
            "attempt_id": attempt_id,
            "mfa_mode": mfa_mode,
        }
        columns = [name for name in values if name in available]
        if not columns:
            raise RuntimeError("auth_logs has no compatible columns")
        query = "INSERT INTO auth_logs (%s) VALUES (%s)" % (
            ", ".join(columns),
            ", ".join(["%s"] * len(columns)),
        )
        cursor.execute(query, [values[name] for name in columns])
