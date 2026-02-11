import sys
import os
import secrets
import string
import hashlib
import logging
from datetime import datetime, timezone
from typing import Tuple, Optional

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
except ImportError:
    from database.db_config import get_db_connection, release_db_connection

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('otp_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 120

def generate_otp(length: int = OTP_LENGTH) -> str:
    try:
        new_otp = ''.join(secrets.choice(string.digits) for _ in range(length))
        logger.info("OTP generated successfully")
        return new_otp
    except Exception as gen_error:
        logger.error("Error generating OTP: %s", gen_error)
        raise

def hash_otp(otp_value: str) -> str:
    try:
        salt = secrets.token_hex(16)
        hashed_value = hashlib.pbkdf2_hmac(
            'sha256',
            otp_value.encode(),
            salt.encode(),
            100000
        ).hex()
        return f"{salt}${hashed_value}"
    except Exception as hash_error:
        logger.error("Error hashing OTP: %s", hash_error)
        raise

def verify_otp_hash(stored_hash: str, otp_input: str) -> bool:
    try:
        if not stored_hash or '$' not in stored_hash:
            return False

        salt, expected = stored_hash.split('$')
        got = hashlib.pbkdf2_hmac(
            'sha256',
            otp_input.encode(),
            salt.encode(),
            100000
        ).hex()
        return secrets.compare_digest(got, expected)
    except Exception as verify_error:
        logger.error("Error verifying OTP hash: %s", verify_error)
        return False

def validate_inputs(username: str, otp_input: Optional[str] = None) -> Tuple[bool, str]:
    if not username or not username.strip():
        return False, "Username required"

    if len(username.strip()) > 100:
        return False, "Username too long"

    if otp_input is not None:
        if not otp_input or not otp_input.strip():
            return False, "OTP required"

        if not otp_input.isdigit():
            return False, "OTP must be numeric"

        if len(otp_input) != OTP_LENGTH:
            return False, "OTP must be 6 digits"

    return True, ""

def store_otp(username: str, otp_value: str, ttl_seconds: int = OTP_TTL_SECONDS) -> Tuple[bool, str]:
    valid_input, msg = validate_inputs(username)
    if not valid_input:
        return False, msg

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            error_message = "Database connection failed"
            logger.error(error_message)
            return False, error_message

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE otp_sessions SET used=TRUE WHERE username=%s AND used=FALSE;",
                (username,)
            )

            hashed_otp = hash_otp(otp_value)
            cur.execute("""
                INSERT INTO otp_sessions (username, otp_hash, created_at, expires_at, used)
                VALUES (%s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '%s seconds', FALSE);
            """, (username, hashed_otp, ttl_seconds))

        conn.commit()
        logger.info("OTP stored for user: %s", username)
        return True, "OTP stored successfully"

    except Exception as store_error:
        error_message = "Error storing OTP: %s" % store_error
        logger.error(error_message)
        if conn:
            conn.rollback()
        return False, error_message
    finally:
        if conn:
            release_db_connection(conn)

def validate_otp(username: str, otp_input: str) -> Tuple[bool, str]:
    valid_input, msg = validate_inputs(username, otp_input)
    if not valid_input:
        return False, msg

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            error_message = "Database connection failed"
            logger.error(error_message)
            return False, error_message

        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, otp_hash, expires_at, used
                FROM otp_sessions
                WHERE username=%s
                ORDER BY created_at DESC
                LIMIT 1;
            """, (username,))

            row = cur.fetchone()

            if not row:
                error_message = "No OTP found"
                logger.warning(error_message)
                return False, error_message

            otp_id, stored_hash, expires_at, used = row

            if used:
                error_message = "OTP already used"
                logger.warning("%s - User: %s", error_message, username)
                return False, error_message

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            current_time = datetime.now(timezone.utc)
            if current_time > expires_at:
                error_message = "OTP expired"
                logger.warning("%s - User: %s", error_message, username)
                return False, error_message

            if not verify_otp_hash(stored_hash, otp_input):
                error_message = "Invalid OTP"
                logger.warning("%s - User: %s", error_message, username)
                return False, error_message

            cur.execute("UPDATE otp_sessions SET used=TRUE WHERE id=%s;", (otp_id,))
            conn.commit()

            logger.info("OTP verified successfully - User: %s", username)
            return True, "OTP verification successful"

    except Exception as validation_error:
        error_message = "Validation error: %s" % validation_error
        logger.error(error_message)
        if conn:
            conn.rollback()
        return False, error_message
    finally:
        if conn:
            release_db_connection(conn)

def deliver_otp(username: str, otp: str) -> bool:
    try:
        print("OTP for %s: %s" % (username, otp))
        logger.info("OTP delivered via console - User: %s", username)
        return True
    except Exception as delivery_error:
        logger.error("Error delivering OTP: %s", delivery_error)
        return False

if __name__ == "__main__":
    try:
        username_input = input("Username: ").strip()

        input_valid, validation_msg = validate_inputs(username_input)
        if not input_valid:
            print("Error: %s" % validation_msg)
            exit(1)

        otp_code = generate_otp()

        success, result_msg = store_otp(username_input, otp_code)
        if not success:
            print("FAIL: %s" % result_msg)
            exit(1)

        deliver_otp(username_input, otp_code)

        code = input("Enter OTP: ").strip()

        is_valid, final_msg = validate_otp(username_input, code)

        if is_valid:
            print("OK")
        else:
            print("FAIL: %s" % final_msg)

    except KeyboardInterrupt:
        print("\nOperation cancelled")
        logger.info("Operation cancelled by user")
    except Exception as main_error:
        logger.error("Unexpected error: %s", main_error)
        print("System error occurred")
