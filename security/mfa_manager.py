import logging
from typing import Optional, Tuple
from contextlib import contextmanager
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

try:
    from SDNMFA.database.login_user import login_user
    from SDNMFA.otp.otp_service import validate_otp, generate_otp, store_otp, deliver_otp
    from SDNMFA.security.biometric_service import verify_biometric
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
except ImportError:
    from database.login_user import login_user
    from otp.otp_service import validate_otp, generate_otp, store_otp, deliver_otp
    from security.biometric_service import verify_biometric
    from database.db_config import get_db_connection, release_db_connection

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MFA_POLICIES = {
    "1": ["password"],
    "2": ["password", "otp"],
    "3": ["password", "biometric"],
    "4": ["password", "otp", "biometric"]
}

POLICY_NAMES = {
    "1": "password_only",
    "2": "password_otp",
    "3": "password_biometric",
    "4": "password_otp_biometric"
}

@contextmanager
def db_connection():
    conn = None
    try:
        conn = get_db_connection()
        yield conn
    except Exception as e:
        logger.error("Database connection error: %s", e)
        raise
    finally:
        if conn:
            release_db_connection(conn)

def authenticate_user(username: str, password: str,
                      otp_code: Optional[str] = None,
                      biometric_data: Optional[str] = None,
                      policy_key: str = "1") -> Tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required"

    if policy_key not in MFA_POLICIES:
        return False, f"Unsupported MFA policy: {policy_key}"

    policy = MFA_POLICIES[policy_key]
    policy_name = POLICY_NAMES[policy_key]

    if "otp" in policy and otp_code is None:
        otp = generate_otp()
        store_success, store_msg = store_otp(username, otp)
        if store_success:
            deliver_otp(username, otp)
            return False, f"OTP has been generated and delivered. Please provide OTP code."
        else:
            return False, f"Error generating OTP: {store_msg}"

    if "password" in policy:
        auth_success, _, error_msg = login_user(username, password)
        if not auth_success:
            _log_event(username, "mfa_password", False, error_msg)
            return False, f"Password authentication failed: {error_msg}"
        _log_event(username, "mfa_password", True, "Password authentication completed")

    if "otp" in policy:
        if not otp_code:
            return False, "OTP required but not provided"
        otp_success, otp_msg = validate_otp(username, otp_code)
        if not otp_success:
            _log_event(username, "mfa_otp", False, otp_msg)
            return False, f"OTP authentication failed: {otp_msg}"
        _log_event(username, "mfa_otp", True, "OTP verified")

    if "biometric" in policy:
        if not biometric_data:
            return False, "Biometric data required but not provided"
        bio_success, bio_msg = verify_biometric(username, biometric_data)
        if not bio_success:
            _log_event(username, "mfa_biometric", False, bio_msg)
            return False, f"Biometric authentication failed: {bio_msg}"
        _log_event(username, "mfa_biometric", True, "Biometric verified")

    _log_event(username, "mfa_complete", True, f"Policy {policy_name} passed")
    logger.info("MFA successful for user '%s' with policy '%s'", username, policy_name)
    return True, "Authentication successful"

def _log_event(username: str, event_type: str, success: bool, message: str = None):
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO auth_logs (username, event_type, success, auth_logs_details)
                    VALUES (%s, %s, %s, %s);
                """, (username, event_type, success, message))
            conn.commit()
    except Exception as e:
        logger.error("Failed to insert MFA log for %s: %s", username, e)

def prepare_mfa_authentication(username: str, policy_key: str) -> Tuple[bool, str, Optional[str]]:

    if policy_key not in MFA_POLICIES:
        return False, f"Unsupported MFA policy: {policy_key}", None

    policy = MFA_POLICIES[policy_key]

    if "otp" in policy:
        otp = generate_otp()
        store_success, store_msg = store_otp(username, otp)
        if store_success:
            deliver_otp(username, otp)
            return True, f"OTP has been generated for policy {policy_key}", otp
        else:
            return False, f"Error generating OTP: {store_msg}", None

    return True, "Ready for authentication", None

if __name__ == "__main__":
    print("MFA Manager CLI")
    print("=" * 40)

    uname = input("Username: ").strip()
    pwd = input("Password: ").strip()

    print("\nSelect MFA Policy:")
    print("1. Password Only")
    print("2. Password + OTP")
    print("3. Password + Biometric")
    print("4. Password + OTP + Biometric")

    policy_input = input("Enter choice (1-4): ").strip()

    otp_input = None
    bio_input = None

    if policy_input in ["2", "4"]:
        success, message, otp = prepare_mfa_authentication(uname, policy_input)
        if success and otp:
            print(f"\n{message}")
            print(f"OTP: {otp}")
            otp_input = input("Enter OTP: ").strip()
        else:
            print(f"Error: {message}")
            exit(1)

    if policy_input in ["3", "4"]:
        bio_input = input("Enter biometric data: ").strip() or None

    result, result_msg = authenticate_user(uname, pwd, otp_code=otp_input, biometric_data=bio_input,
                                           policy_key=policy_input)
    print("\nResult:", result, "-", result_msg)
