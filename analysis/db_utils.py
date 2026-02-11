"""Shared DB helpers for analysis scripts.

These scripts are run in different contexts (host OS, Mininet host/NS).
The rest of the project already has a DB pool config, but analysis tools
should remain robust even when that pool cannot be initialized.

This helper:
  - loads project .env (best effort)
  - reads DB_* environment variables
  - attempts safe fallbacks (e.g., unix socket peer auth for local DB)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor


def _load_dotenv_best_effort(env_path: Path) -> None:
    """Load .env into os.environ if possible. Never raises."""
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(dotenv_path=str(env_path), override=False)
        return
    except Exception:
        pass

    # Fallback: minimal parser (KEY=VALUE, ignores quotes & comments).
    try:
        if not env_path.exists():
            return
        for raw in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)
    except Exception:
        return


def _project_env_path() -> Path:
    # analysis/ -> project root
    return Path(__file__).resolve().parent.parent / ".env"


def read_db_params() -> Dict[str, Any]:
    """Return DB params using DB_* env vars (after loading .env)."""
    _load_dotenv_best_effort(_project_env_path())

    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "5432"))
    name = os.getenv("DB_NAME", "sdn_mfa_db")
    user = os.getenv("DB_USER", "sdn_user")
    password = os.getenv("DB_PASSWORD")

    # Also support older/internal names if present.
    host = os.getenv("SDN_DB_HOST", host)
    port = int(os.getenv("SDN_DB_PORT", str(port)))
    name = os.getenv("SDN_DB_NAME", name)
    user = os.getenv("SDN_DB_USER", user)
    password = os.getenv("SDN_DB_PASSWORD", password)

    return {
        "host": host,
        "port": port,
        "dbname": name,
        "user": user,
        "password": password,
    }


def _try_connect(params: Dict[str, Any]) -> Tuple[Optional[psycopg2.extensions.connection], Optional[Exception]]:
    try:
        # Filter None values psycopg2 may not like.
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        conn = psycopg2.connect(**clean)
        return conn, None
    except Exception as e:
        return None, e


def get_connection() -> psycopg2.extensions.connection:
    """Get a working DB connection with fallbacks.

    Fallback logic:
      1) Use DB_* from .env / environment.
      2) If auth fails on localhost, try unix socket (peer) with no password.
      3) If host is an IP and fails, try localhost.
    """
    base = read_db_params()

    conn, err = _try_connect(base)
    if conn:
        return conn

    # Auth failure often happens when tcp requires md5 but local uses peer.
    msg = str(err).lower() if err else ""
    if ("password authentication failed" in msg or "authentication failed" in msg) and base.get("host") in (
        "localhost",
        "127.0.0.1",
    ):
        peer_params = dict(base)
        peer_params.pop("password", None)
        peer_params["host"] = ""  # unix socket
        conn2, _ = _try_connect(peer_params)
        if conn2:
            return conn2

    # If .env host points to Mininet IP but we are on host OS, try localhost.
    if base.get("host") not in ("localhost", "127.0.0.1", ""):
        local_params = dict(base)
        local_params["host"] = "localhost"
        conn3, _ = _try_connect(local_params)
        if conn3:
            return conn3

    # Final: raise a readable error
    safe = dict(base)
    if safe.get("password"):
        safe["password"] = "***"
    raise RuntimeError(f"Database connection failed. Tried params={safe}. Last error: {err}")


def dict_cursor_connection() -> psycopg2.extensions.connection:
    """Convenience: returns a connection whose cursors can be RealDictCursor."""
    conn = get_connection()
    # Caller will use conn.cursor(cursor_factory=RealDictCursor)
    return conn


__all__ = ["get_connection", "read_db_params", "dict_cursor_connection", "RealDictCursor"]
