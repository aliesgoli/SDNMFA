import logging
import os
import sys
from typing import Optional, Tuple


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
while PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from database.db_config import get_db_connection, release_db_connection
from database.audit_log import insert_auth_log
from security.password_service import SCHEME as CURRENT_PASSWORD_SCHEME
from security.password_service import hash_password, verify_password


log = logging.getLogger(__name__)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_user(
    username: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
    mfa_mode: Optional[str] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate a password and record one linked password-login event."""
    conn = get_db_connection()
    if not conn:
        return False, None, "Database connection failed"
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT username, password_hash, password_scheme, is_active,
                       failed_attempts,
                       (locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP)
                FROM users WHERE username=%s FOR UPDATE;
                """,
                (username,),
            )
            row = cursor.fetchone()
            if not row:
                # A fixed scrypt operation makes account discovery less useful.
                hash_password(str(password), salt=b"\x00" * 16)
                return False, None, "Invalid credentials"

            stored_username, stored_hash, scheme, is_active, failed, locked = row
            if not is_active:
                return False, stored_username, "Invalid credentials"
            if locked:
                insert_auth_log(
                    conn, username=stored_username, event_type="login_locked",
                    success=False, message="Temporary account lockout",
                    run_id=run_id, attempt_id=attempt_id, mfa_mode=mfa_mode,
                    ip_address=ip_address, user_agent=user_agent,
                )
                conn.commit()
                return False, stored_username, "Account temporarily locked"

            if scheme == CURRENT_PASSWORD_SCHEME or str(stored_hash).startswith(
                CURRENT_PASSWORD_SCHEME + "$"
            ):
                is_valid = verify_password(stored_hash, password)
            else:
                cursor.execute(
                    "SELECT (%s = crypt(%s, %s)) AS is_valid;",
                    (stored_hash, password, stored_hash),
                )
                password_row = cursor.fetchone()
                is_valid = bool(password_row and password_row[0])

            if is_valid:
                new_hash = None if scheme == CURRENT_PASSWORD_SCHEME else hash_password(password)
                cursor.execute(
                    """
                    UPDATE users SET failed_attempts=0, locked_until=NULL,
                        last_failed_login=NULL,
                        password_hash=COALESCE(%s, password_hash),
                        password_scheme=CASE WHEN %s IS NULL THEN password_scheme ELSE %s END,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE username=%s
                    """,
                    (new_hash, new_hash, CURRENT_PASSWORD_SCHEME, stored_username),
                )
            else:
                next_failed = int(failed or 0) + 1
                cursor.execute(
                    """
                    UPDATE users SET failed_attempts=%s,
                        last_failed_login=CURRENT_TIMESTAMP,
                        locked_until=CASE WHEN %s >= %s
                            THEN CURRENT_TIMESTAMP + (%s * INTERVAL '1 second')
                            ELSE NULL END,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE username=%s
                    """,
                    (
                        next_failed, next_failed, MAX_FAILED_ATTEMPTS,
                        LOCKOUT_SECONDS, stored_username,
                    ),
                )

        insert_auth_log(
            conn,
            username=stored_username,
            event_type="login",
            success=is_valid,
            message="Password verified" if is_valid else "Invalid credentials",
            run_id=run_id,
            attempt_id=attempt_id,
            mfa_mode=mfa_mode,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        conn.commit()
        if not is_valid:
            return False, stored_username, "Invalid credentials"
        return True, stored_username, None
    except Exception as exc:
        conn.rollback()
        log.exception("Password login failed for %s", username)
        return False, None, "Authentication service error"
    finally:
        release_db_connection(conn)
