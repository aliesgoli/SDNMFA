import os
import sys
import base64
import binascii
import secrets
import hashlib
import logging
from typing import Union, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
env_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), '.env')
load_dotenv(env_path)


try:
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
except ImportError:
    from database.db_config import get_db_connection, release_db_connection
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'biometric_service.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

BIOMETRIC_PEPPER = (os.getenv("BIOMETRIC_PEPPER") or "default_fallback_pepper_change_me").encode("utf-8")
if os.getenv("BIOMETRIC_PEPPER") is None:
    log.warning("BIOMETRIC_PEPPER not set in .env, using default fallback! Change this for security.")

MAX_BIOMETRIC_BYTES = 512 * 1024
MIN_BIOMETRIC_BYTES = 16

def _normalize_biometric_input(raw: Union[bytes, str]) -> bytes:
    try:
        if isinstance(raw, str):
            raw = raw.strip()
            try:
                missing = (-len(raw)) % 4
                if missing:
                    raw = raw + ("=" * missing)
                raw_bytes = base64.b64decode(raw, validate=True)
            except (ValueError, TypeError, binascii.Error):
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
        iterations = 200000
        material = feature_digest + (BIOMETRIC_PEPPER or b"")
        dk = hashlib.pbkdf2_hmac("sha256", material, salt.encode("utf-8"), iterations)
        return f"{salt}${iterations}${dk.hex()}"
    except Exception as e:
        log.error("Hashing biometric failed: %s", e)
        raise

def _verify_biometric_hash(stored: str, feature_digest: bytes) -> bool:
    try:
        if not stored or stored.count("$") != 2:
            return False
        salt, iterations_str, expected_hex = stored.split("$")
        iterations = int(iterations_str)
        material = feature_digest + (BIOMETRIC_PEPPER or b"")
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
            cur.execute("SELECT biometric_template IS NOT NULL FROM users WHERE username=%s;", (username,))
            row = cur.fetchone()
            return bool(row and row[0])
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("is_biometric_enrolled error: %s", e)
        return False, None, f"System error: {str(e)}"
    finally:
        release_db_connection(conn)

def enroll_biometric(username: str, raw_biometric: Union[bytes, str], overwrite_existing: bool = False) -> Tuple[bool, str]:
    if not username or not str(username).strip():
        return False, "Username is required"

    try:
        digest = _normalize_biometric_input(raw_biometric)
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

            template = _hash_biometric_template(digest)

            cur.execute("UPDATE users SET biometric_template = %s, updated_at = CURRENT_TIMESTAMP WHERE username = %s;", (template, username))
            cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_enroll', TRUE);", (username,))

        conn.commit()
        log.info("Biometric enrolled for user '%s'%s", username, " (overwritten)" if already_enrolled else "")
        return True, ("Biometric enrolled" if not already_enrolled else "Biometric overwritten")

    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Enroll biometric failed for '%s': %s", username, e)
        return False, None, f"Enroll biometric failed: {str(e)}"
    finally:
        release_db_connection(conn)


def verify_biometric(username: str, raw_biometric: Union[bytes, str]) -> Tuple[bool, str]:
    if not username or not str(username).strip():
        return False, "Username is required"

    try:
        digest = _normalize_biometric_input(raw_biometric)
    except Exception as e:
        return False, f"Invalid biometric input: {e}"

    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT biometric_template FROM users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if not row:
                return False, "User not found"

            stored = row[0]
            if not stored:
                cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_verify', FALSE);", (username,))
                conn.commit()
                return False, "No biometric enrolled"

            verification_result = _verify_biometric_hash(stored, digest)

            cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_verify', %s);", (username, verification_result))
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
        return False, None, f"Verify biometric failed: {str(e)}"
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

            cur.execute("UPDATE users SET biometric_template = NULL, updated_at = CURRENT_TIMESTAMP WHERE username = %s;", (username,))
            cur.execute("INSERT INTO auth_logs (username, event_type, success) VALUES (%s, 'biometric_delete', TRUE);", (username,))

        conn.commit()
        log.info("Biometric deleted for '%s'", username)
        return True, "Biometric deleted"

    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Delete biometric failed for '%s': %s", username, e)
        return False, None, f"Delete biometric failed: {str(e)}"
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
        data = input("Paste biometric (raw/base64/string): ").strip()
        result, message = enroll_biometric(uname, data, overwrite_existing=overwrite_choice)
        print("Result:", result, "-", message)
    elif choice == "2":
        data = input("Paste biometric (raw/base64/string): ").strip()
        result, message = verify_biometric(uname, data)
        print("Result:", result, "-", message)
    elif choice == "3":
        result, message = delete_biometric(uname)
        print("Result:", result, "-", message)
    else:
        print("Invalid choice")
