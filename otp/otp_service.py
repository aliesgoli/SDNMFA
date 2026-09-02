import sys
import os
import secrets
import string
import hashlib
import hmac
import logging
from typing import Tuple, Optional

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
while project_root in sys.path:
    sys.path.remove(project_root)
sys.path.insert(0, project_root)
from database.db_config import get_db_connection, release_db_connection
from config.runtime_security import strong_secret_or_none

LOG_DIR = os.path.join(project_root, "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    OTP_LOG_HANDLER = logging.FileHandler(
        os.path.join(LOG_DIR, "otp_service.log"), encoding="utf-8"
    )
except OSError:
    OTP_LOG_HANDLER = logging.StreamHandler()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        OTP_LOG_HANDLER,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 120
OTP_MAX_ATTEMPTS = 5


def _otp_pepper() -> bytes:
    value = strong_secret_or_none(os.getenv("OTP_PEPPER"))
    if value is None:
        raise RuntimeError(
            "OTP_PEPPER must be a non-placeholder secret of at least 32 characters"
        )
    return value.encode("utf-8")

def generate_otp(length: int = OTP_LENGTH) -> str:
    try:
        new_otp = ''.join(secrets.choice(string.digits) for _ in range(length))
        logger.info("OTP generated successfully")
        return new_otp
    except Exception as gen_error:
        logger.error("Error generating OTP: %s", gen_error)
        raise

def hash_otp(
    otp_value: str,
    *,
    username: str = "",
    attempt_id: Optional[str] = None,
) -> str:
    try:
        salt = secrets.token_bytes(16)
        context = "%s\x00%s\x00%s" % (
            str(username).strip().casefold(),
            str(attempt_id or ""),
            str(otp_value),
        )
        digest = hmac.new(
            _otp_pepper(), salt + context.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return "v2$%s$%s" % (salt.hex(), digest)
    except Exception as hash_error:
        logger.error("Error hashing OTP: %s", hash_error)
        raise

def verify_otp_hash(
    stored_hash: str,
    otp_input: str,
    *,
    username: str = "",
    attempt_id: Optional[str] = None,
) -> bool:
    try:
        if not stored_hash or '$' not in stored_hash:
            return False
        if stored_hash.startswith("v2$"):
            version, salt_hex, expected = stored_hash.split("$", 2)
            if version != "v2" or len(bytes.fromhex(salt_hex)) != 16:
                return False
            context = "%s\x00%s\x00%s" % (
                str(username).strip().casefold(),
                str(attempt_id or ""),
                str(otp_input),
            )
            observed = hmac.new(
                _otp_pepper(),
                bytes.fromhex(salt_hex) + context.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return secrets.compare_digest(observed, expected)

        # Read-only compatibility with sessions created by the earlier build.
        salt, expected = stored_hash.split('$', 1)
        observed = hashlib.pbkdf2_hmac(
            'sha256', otp_input.encode(), salt.encode(), 100000
        ).hex()
        return secrets.compare_digest(observed, expected)
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

def store_otp(
    username: str,
    otp_value: str,
    ttl_seconds: int = OTP_TTL_SECONDS,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> Tuple[bool, str]:
    valid_input, msg = validate_inputs(username, otp_value)
    if not valid_input:
        return False, msg
    try:
        ttl_seconds = int(ttl_seconds)
    except (TypeError, ValueError):
        return False, "OTP TTL must be an integer"
    if not 1 <= ttl_seconds <= 3600:
        return False, "OTP TTL must be between 1 and 3600 seconds"

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

            hashed_otp = hash_otp(
                otp_value, username=username, attempt_id=attempt_id
            )
            cur.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='otp_sessions'
                """
            )
            available = {row[0] for row in cur.fetchall()}
            columns = ["username", "otp_hash", "created_at", "expires_at", "used"]
            expressions = [
                "%s",
                "%s",
                "CURRENT_TIMESTAMP",
                "CURRENT_TIMESTAMP + (%s * INTERVAL '1 second')",
                "FALSE",
            ]
            values = [username, hashed_otp, ttl_seconds]
            if "run_id" in available:
                columns.append("run_id")
                expressions.append("%s")
                values.append(run_id)
            if "attempt_id" in available:
                columns.append("attempt_id")
                expressions.append("%s")
                values.append(attempt_id)
            cur.execute(
                "INSERT INTO otp_sessions (%s) VALUES (%s)"
                % (", ".join(columns), ", ".join(expressions)),
                values,
            )

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

def validate_otp(
    username: str,
    otp_input: str,
    attempt_id: Optional[str] = None,
) -> Tuple[bool, str]:
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
            cur.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='otp_sessions'
                """
            )
            available = {row[0] for row in cur.fetchall()}
            if attempt_id and "attempt_id" in available:
                cur.execute(
                    """
                    SELECT id, otp_hash,
                           (expires_at <= CURRENT_TIMESTAMP) AS is_expired,
                           used, failed_attempts
                    FROM otp_sessions
                    WHERE username=%s AND attempt_id=%s
                    ORDER BY created_at DESC
                    LIMIT 1
                    FOR UPDATE;
                    """,
                    (username, attempt_id),
                )
            else:
                cur.execute(
                    """
                    SELECT id, otp_hash,
                           (expires_at <= CURRENT_TIMESTAMP) AS is_expired,
                           used, failed_attempts
                    FROM otp_sessions
                    WHERE username=%s
                    ORDER BY created_at DESC
                    LIMIT 1
                    FOR UPDATE;
                    """,
                    (username,),
                )

            row = cur.fetchone()

            if not row:
                error_message = "No OTP found"
                logger.warning(error_message)
                return False, error_message

            otp_id, stored_hash, is_expired, used, failed_attempts = row

            if used:
                error_message = "OTP already used"
                logger.warning("%s - User: %s", error_message, username)
                return False, error_message

            if is_expired:
                error_message = "OTP expired"
                logger.warning("%s - User: %s", error_message, username)
                return False, error_message

            if not verify_otp_hash(
                stored_hash,
                otp_input,
                username=username,
                attempt_id=attempt_id,
            ):
                next_failed = int(failed_attempts or 0) + 1
                cur.execute(
                    """
                    UPDATE otp_sessions
                    SET failed_attempts=%s,
                        used=CASE WHEN %s >= %s THEN TRUE ELSE used END,
                        invalidated_reason=CASE WHEN %s >= %s
                            THEN 'attempt_limit' ELSE invalidated_reason END
                    WHERE id=%s
                    """,
                    (
                        next_failed, next_failed, OTP_MAX_ATTEMPTS,
                        next_failed, OTP_MAX_ATTEMPTS, otp_id,
                    ),
                )
                conn.commit()
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
