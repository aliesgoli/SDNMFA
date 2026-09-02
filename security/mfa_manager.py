import logging
import os
import sys
from typing import Optional, Tuple


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
while PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from database.login_user import login_user
from otp.otp_service import validate_otp, generate_otp, store_otp, deliver_otp
from security.biometric_service import verify_biometric
from database.db_config import get_db_connection, release_db_connection
from database.audit_log import insert_auth_log
from config.experiment_protocol import POLICY_SELECTION, POLICY_SPECS


logger = logging.getLogger(__name__)
MFA_POLICIES = {
    key: list(POLICY_SPECS[mode]["factor_keys"])
    for key, mode in POLICY_SELECTION.items()
}
POLICY_NAMES = dict(POLICY_SELECTION)


def get_user_factor_status(username: str) -> Tuple[bool, dict, str]:
    """Return explicit enrollment state for the software MFA factors."""
    conn = get_db_connection()
    if not conn:
        return False, {}, "Database connection failed"
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT is_active,
                       otp_enabled,
                       biometric_template IS NOT NULL,
                       biometric_mode
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
            row = cur.fetchone()
        if not row:
            return False, {}, "User not found"
        return True, {
            "is_active": bool(row[0]),
            "otp_enabled": bool(row[1]),
            "biometric_enrolled": bool(row[2]),
            "biometric_mode": row[3],
        }, "Factor status loaded"
    except Exception as exc:
        if conn:
            conn.rollback()
        logger.error("Could not load factor status for %s: %s", username, exc)
        return False, {}, "Could not load MFA enrollment state"
    finally:
        release_db_connection(conn)


def policy_readiness(username: str, policy_key: str) -> Tuple[bool, str]:
    if policy_key not in MFA_POLICIES:
        return False, "Unsupported MFA policy: %s" % policy_key
    loaded, status, message = get_user_factor_status(username)
    if not loaded:
        return False, message
    if not status["is_active"]:
        return False, "User account is inactive"
    policy = MFA_POLICIES[policy_key]
    if "otp" in policy and not status["otp_enabled"]:
        return False, "Software OTP is not enabled for this user"
    if "biometric" in policy and not status["biometric_enrolled"]:
        return False, "Software-simulated biometric is not enrolled for this user"
    if (
        "biometric" in policy
        and status.get("biometric_mode") not in {
            "software_simulated", "software_simulated_v2"
        }
    ):
        return False, "Biometric must be re-enrolled with the current software-simulated format"
    return True, "Policy factors are ready"


def _log_event(
    username: str,
    event_type: str,
    success: bool,
    message: Optional[str] = None,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
    mfa_mode: Optional[str] = None,
) -> None:
    conn = get_db_connection()
    if not conn:
        logger.error("Could not log %s: database unavailable", event_type)
        return
    try:
        insert_auth_log(
            conn,
            username=username,
            event_type=event_type,
            success=success,
            message=message,
            run_id=run_id,
            attempt_id=attempt_id,
            mfa_mode=mfa_mode,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Failed to insert MFA log for %s", username)
    finally:
        release_db_connection(conn)


def _mark_successful_login(username: str) -> None:
    """Update account activity only after the selected MFA policy passes."""
    conn = get_db_connection()
    if not conn:
        logger.error("Could not update last_login for %s: database unavailable", username)
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = %s
                """,
                (username,),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Could not update last_login for %s", username)
    finally:
        release_db_connection(conn)


def authenticate_user(
    username: str,
    password: str,
    otp_code: Optional[str] = None,
    biometric_data: Optional[str] = None,
    policy_key: str = "1",
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> Tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required"
    if policy_key not in MFA_POLICIES:
        return False, "Unsupported MFA policy: %s" % policy_key

    ready, readiness_message = policy_readiness(username, policy_key)
    if not ready:
        return False, readiness_message

    policy = MFA_POLICIES[policy_key]
    policy_name = POLICY_NAMES[policy_key]
    context = {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "mfa_mode": policy_name,
    }

    if "otp" in policy and otp_code is None:
        _log_event(
            username,
            "mfa_otp",
            False,
            "OTP required but not provided",
            **context
        )
        return False, "OTP required but not provided"

    auth_success, _, error_message = login_user(
        username,
        password,
        run_id=run_id,
        attempt_id=attempt_id,
        mfa_mode=policy_name,
    )
    _log_event(
        username,
        "mfa_password",
        auth_success,
        "Password authentication completed" if auth_success else error_message,
        **context
    )
    if not auth_success:
        return False, "Password authentication failed: %s" % error_message

    if "otp" in policy:
        otp_success, otp_message = validate_otp(
            username,
            str(otp_code),
            attempt_id=attempt_id,
        )
        _log_event(
            username,
            "mfa_otp",
            otp_success,
            otp_message,
            **context
        )
        if not otp_success:
            return False, "OTP authentication failed: %s" % otp_message

    if "biometric" in policy:
        if not biometric_data:
            _log_event(
                username,
                "mfa_biometric",
                False,
                "Biometric data required but not provided",
                **context
            )
            return False, "Biometric data required but not provided"
        biometric_success, biometric_message = verify_biometric(
            username,
            biometric_data,
            run_id=run_id,
            attempt_id=attempt_id,
            mfa_mode=policy_name,
        )
        _log_event(
            username,
            "mfa_biometric",
            biometric_success,
            biometric_message,
            **context
        )
        if not biometric_success:
            return False, "Biometric authentication failed: %s" % biometric_message

    _mark_successful_login(username)
    _log_event(
        username,
        "mfa_complete",
        True,
        "Policy %s passed" % policy_name,
        **context
    )
    return True, "Authentication successful"


def prepare_mfa_authentication(
    username: str,
    policy_key: str,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> Tuple[bool, str, Optional[str]]:
    if policy_key not in MFA_POLICIES:
        return False, "Unsupported MFA policy: %s" % policy_key, None
    ready, readiness_message = policy_readiness(username, policy_key)
    if not ready:
        return False, readiness_message, None
    if "otp" not in MFA_POLICIES[policy_key]:
        return True, "Ready for authentication", None
    otp = generate_otp()
    stored, message = store_otp(
        username,
        otp,
        run_id=run_id,
        attempt_id=attempt_id,
    )
    if not stored:
        return False, "Error generating OTP: %s" % message, None
    deliver_otp(username, otp)
    return True, "OTP has been generated for policy %s" % policy_key, otp


if __name__ == "__main__":
    print("Run controller/mfa_controller.py for linked experiment logging.")
