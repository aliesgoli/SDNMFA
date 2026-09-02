import os
import sys
import base64
import binascii
import getpass
import secrets
import hashlib
import logging
from typing import Optional, Union, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
while PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

try:
    from dotenv import load_dotenv
except ImportError:  # dependency is checked by tools/preflight_check.py
    def load_dotenv(*_args, **_kwargs):
        return False
env_path = os.path.join(PROJECT_ROOT, '.env')
load_dotenv(env_path)

from database.db_config import get_db_connection, release_db_connection
from database.audit_log import insert_auth_log
from config.runtime_security import strong_secret_or_none
from security.simulated_biometric_v2 import (
    DEFAULT_THRESHOLD as V2_DEFAULT_THRESHOLD,
    MODE as SIMULATED_BIOMETRIC_MODE_V2,
    decode_sample as decode_v2_sample,
    encrypt_template as encrypt_v2_template,
    verify_probe as verify_v2_probe,
)
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    BIOMETRIC_LOG_HANDLER = logging.FileHandler(
        os.path.join(LOG_DIR, 'biometric_service.log'), encoding='utf-8'
    )
except OSError:
    BIOMETRIC_LOG_HANDLER = logging.StreamHandler()

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        BIOMETRIC_LOG_HANDLER,
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

MAX_BIOMETRIC_BYTES = 512 * 1024
MIN_BIOMETRIC_BYTES = 16
BIOMETRIC_PBKDF2_ITERATIONS = 200000
SIMULATED_BIOMETRIC_MODE = "software_simulated"
SIMULATED_TEST_TOKEN = "test"


def _biometric_pepper() -> bytes:
    """Return the configured pepper or fail closed for biometric operations."""
    value = strong_secret_or_none(os.getenv("BIOMETRIC_PEPPER"))
    if value is None:
        raise RuntimeError(
            "BIOMETRIC_PEPPER must be a non-placeholder secret of at least 32 characters"
        )
    return value.encode("utf-8")

def simulated_biometric_sample(username: str) -> str:
    """Return the deterministic lab sample represented by the input ``test``.

    This is a software fixture, not a physical biometric measurement. The
    username scope prevents the same fixture text from being shared by users.
    """
    normalized_username = str(username or "").strip().casefold()
    if not normalized_username:
        raise ValueError("Username is required for the simulated test sample")
    return "sdnmfa-simulated-biometric-v1::%s" % normalized_username


def _normalize_biometric_input(
    raw: Union[bytes, str], username: Optional[str] = None
) -> bytes:
    try:
        if isinstance(raw, str):
            raw = raw.strip()
            if raw.casefold() == SIMULATED_TEST_TOKEN:
                raw = simulated_biometric_sample(str(username or ""))
                raw_bytes = raw.encode("utf-8")
            elif raw.startswith("base64:"):
                encoded = raw[len("base64:"):].strip()
                missing = (-len(encoded)) % 4
                if missing:
                    encoded = encoded + ("=" * missing)
                raw_bytes = base64.b64decode(encoded, validate=True)
            else:
                raw_bytes = raw.encode("utf-8", errors="ignore")
        elif isinstance(raw, (bytes, bytearray)):
            raw_bytes = bytes(raw)
        else:
            raise TypeError("Unsupported biometric input type")

        if not (MIN_BIOMETRIC_BYTES <= len(raw_bytes) <= MAX_BIOMETRIC_BYTES):
            raise ValueError("Biometric input size out of acceptable range")

        digest = hashlib.sha256(raw_bytes).digest()
        return digest
    except (ValueError, TypeError, binascii.Error) as e:
        log.error("Normalization failed: %s", e)
        raise
    except Exception as e:
        log.error("Unexpected normalization error: %s", e)
        raise

def _hash_biometric_template(feature_digest: bytes) -> str:
    try:
        salt = secrets.token_hex(16)
        material = feature_digest + _biometric_pepper()
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            material,
            salt.encode("utf-8"),
            BIOMETRIC_PBKDF2_ITERATIONS,
        )
        return f"{salt}${BIOMETRIC_PBKDF2_ITERATIONS}${dk.hex()}"
    except Exception as e:
        log.error("Hashing biometric failed: %s", e)
        raise

def _verify_biometric_hash(stored: str, feature_digest: bytes) -> bool:
    try:
        if not stored or stored.count("$") != 2:
            return False
        salt, iterations_str, expected_hex = stored.split("$")
        iterations = int(iterations_str)
        if iterations != BIOMETRIC_PBKDF2_ITERATIONS:
            return False
        if len(bytes.fromhex(salt)) != 16 or len(bytes.fromhex(expected_hex)) != 32:
            return False
        material = feature_digest + _biometric_pepper()
        got = hashlib.pbkdf2_hmac("sha256", material, salt.encode("utf-8"), iterations).hex()
        return secrets.compare_digest(got, expected_hex)
    except Exception as e:
        log.error("Verify biometric failed: %s", e)
        return False

def is_biometric_enrolled(username: str) -> bool:
    conn = get_db_connection()
    if not conn:
        log.error("DB connection failed in is_biometric_enrolled")
        return False
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT biometric_template IS NOT NULL
                       AND biometric_mode IN (%s, %s)
                FROM users
                WHERE username=%s;
                """,
                (SIMULATED_BIOMETRIC_MODE, SIMULATED_BIOMETRIC_MODE_V2, username),
            )
            row = cur.fetchone()
            return bool(row and row[0])
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("is_biometric_enrolled error: %s", e)
        return False
    finally:
        release_db_connection(conn)

def enroll_biometric(username: str, raw_biometric: Union[bytes, str], overwrite_existing: bool = False) -> Tuple[bool, str]:
    if not username or not str(username).strip():
        return False, "Username is required"

    is_v2_sample = (
        isinstance(raw_biometric, str)
        and raw_biometric.strip().startswith("simv2:")
    )
    try:
        if is_v2_sample:
            v2_vector = decode_v2_sample(str(raw_biometric))
            digest = None
        else:
            v2_vector = None
            digest = _normalize_biometric_input(raw_biometric, username=username)
    except Exception as e:
        return False, f"Invalid biometric input: {e}"

    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT biometric_template IS NOT NULL FROM users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if not row:
                return False, "User not found"

            already_enrolled = bool(row[0])
            if already_enrolled and not overwrite_existing:
                cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_enroll', FALSE);", (username,))
                conn.commit()
                return False, "Biometric already enrolled. Use overwrite=True to replace."

            if is_v2_sample:
                template = encrypt_v2_template(username, v2_vector)
                biometric_mode = SIMULATED_BIOMETRIC_MODE_V2
                threshold = V2_DEFAULT_THRESHOLD
            else:
                template = _hash_biometric_template(digest)
                biometric_mode = SIMULATED_BIOMETRIC_MODE
                threshold = None

            cur.execute(
                """
                UPDATE users
                SET biometric_template = %s,
                    biometric_mode = %s,
                    biometric_threshold = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = %s;
                """,
                (template, biometric_mode, threshold, username),
            )
            cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_enroll', TRUE);", (username,))

        conn.commit()
        log.info("Biometric enrolled for user '%s'%s", username, " (overwritten)" if already_enrolled else "")
        return True, ("Biometric enrolled" if not already_enrolled else "Biometric overwritten")

    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Enroll biometric failed for '%s': %s", username, e)
        return False, f"Enroll biometric failed: {str(e)}"
    finally:
        release_db_connection(conn)


def verify_biometric(
    username: str,
    raw_biometric: Union[bytes, str],
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
    mfa_mode: Optional[str] = None,
) -> Tuple[bool, str]:
    if not username or not str(username).strip():
        return False, "Username is required"

    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT biometric_template, biometric_mode, biometric_threshold
                FROM users WHERE username=%s;
                """,
                (username,),
            )
            row = cur.fetchone()
            if not row:
                return False, "User not found"

            stored, biometric_mode, biometric_threshold = row
            if not stored or biometric_mode not in {
                SIMULATED_BIOMETRIC_MODE, SIMULATED_BIOMETRIC_MODE_V2
            }:
                insert_auth_log(
                    conn,
                    username=username,
                    event_type="biometric_verify",
                    success=False,
                    message="No current software-simulated biometric enrolled",
                    run_id=run_id,
                    attempt_id=attempt_id,
                    mfa_mode=mfa_mode,
                )
                conn.commit()
                return False, "No current software-simulated biometric enrolled"

            if biometric_mode == SIMULATED_BIOMETRIC_MODE_V2:
                try:
                    verification_result, score = verify_v2_probe(
                        username,
                        stored,
                        str(raw_biometric),
                        threshold=biometric_threshold or V2_DEFAULT_THRESHOLD,
                    )
                    detail = "score=%.6f threshold=%.6f" % (
                        score, biometric_threshold or V2_DEFAULT_THRESHOLD
                    )
                except Exception:
                    verification_result = False
                    detail = "invalid_or_tampered_v2_probe"
            else:
                try:
                    digest = _normalize_biometric_input(
                        raw_biometric, username=username
                    )
                    verification_result = _verify_biometric_hash(stored, digest)
                    detail = "legacy_exact_match"
                except Exception:
                    verification_result = False
                    detail = "invalid_legacy_probe"

            insert_auth_log(
                conn,
                username=username,
                event_type="biometric_verify",
                success=verification_result,
                message=(
                    "Biometric verification successful (%s)" % detail
                    if verification_result
                    else "Biometric verification failed (%s)" % detail
                ),
                run_id=run_id,
                attempt_id=attempt_id,
                mfa_mode=mfa_mode,
            )
            if verification_result:
                cur.execute("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE username = %s;", (username,))

        conn.commit()
        if verification_result:
            log.info("Biometric verified for '%s'", username)
            return True, "Biometric verification successful"
        else:
            log.warning("Biometric verification failed for '%s'", username)
            return False, "Biometric verification failed"

    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Verify biometric failed for '%s': %s", username, e)
        return False, f"Verify biometric failed: {str(e)}"
    finally:
        release_db_connection(conn)


def delete_biometric(username: str) -> Tuple[bool, str]:
    if not username or not str(username).strip():
        return False, "Username is required"

    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT biometric_template IS NOT NULL FROM users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if not row:
                return False, "User not found"

            if not row[0]:
                return False, "No biometric to delete"

            cur.execute(
                """
                UPDATE users
                SET biometric_template = NULL,
                    biometric_mode = NULL,
                    biometric_threshold = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = %s;
                """,
                (username,),
            )
            cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_delete', TRUE);", (username,))

        conn.commit()
        log.info("Biometric deleted for '%s'", username)
        return True, "Biometric deleted"

    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Delete biometric failed for '%s': %s", username, e)
        return False, f"Delete biometric failed: {str(e)}"
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    print("Biometric Service CLI")
    print("=====================")
    print("1) Enroll")
    print("2) Verify")
    print("3) Delete")
    choice = input("Choose (1/2/3): ").strip()

    uname = input("Username: ").strip()
    if choice == "1":
        overwrite_choice = input("Overwrite if exists? (y/n): ").strip().lower() == "y"
        data = getpass.getpass(
            "Simulated biometric sample ('test', text, or base64:<data>): "
        ).strip()
        result, message = enroll_biometric(uname, data, overwrite_existing=overwrite_choice)
        print("Result:", result, "-", message)
    elif choice == "2":
        data = getpass.getpass(
            "Simulated biometric sample ('test', text, or base64:<data>): "
        ).strip()
        result, message = verify_biometric(uname, data)
        print("Result:", result, "-", message)
    elif choice == "3":
        result, message = delete_biometric(uname)
        print("Result:", result, "-", message)
    else:
        print("Invalid choice")
