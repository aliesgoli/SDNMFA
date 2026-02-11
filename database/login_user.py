import os
import sys
import logging
from contextlib import closing
from typing import Optional, Tuple

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
except ImportError:
    from database.db_config import get_db_connection, release_db_connection

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

def login_user(username: str, password: str,
               ip_address: Optional[str] = None,
               user_agent: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Authenticate user by validating password, update last login time, and log the attempt.
    Returns: (success, username, error_message)
    """

    validate_user_sql = """
        SELECT username, password_hash
        FROM users
        WHERE username = %s;
    """

    check_password_sql = """
        SELECT (password_hash = crypt(%s, password_hash)) AS is_valid
        FROM users
        WHERE username = %s;
    """

    update_login_sql = """
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE username = %s;
    """

    insert_log_sql = """
        INSERT INTO auth_logs (username, event_type, ip_address, user_agent, success)
        VALUES (%s, 'login', %s, %s, %s);
    """

    conn = get_db_connection()
    if not conn:
        error_msg_conn = "Database connection failed"
        log.error("%s. Login aborted.", error_msg_conn)
        return False, None, error_msg_conn

    try:
            with conn.cursor() as cur:
                cur.execute(validate_user_sql, (username,))
                user_row = cur.fetchone()

                if not user_row:
                    error_msg_user = "User not found"
                    log.warning("Login failed: %s - '%s'", error_msg_user, username)
                    return False, None, error_msg_user

                username_found, password_hash = user_row
                log.debug("User found: %s", username_found)

                cur.execute(check_password_sql, (password, username))
                password_result = cur.fetchone()

                if not password_result:
                    error_msg_pw_check = "Password verification failed"
                    log.warning("Login failed: %s - '%s'", error_msg_pw_check, username)
                    cur.execute(insert_log_sql, (username, ip_address, user_agent, False))
                    conn.commit()
                    return False, username, error_msg_pw_check

                is_valid = password_result[0]

                if not is_valid:
                    error_msg_invalid_pw = "Invalid password"
                    log.warning("Login failed: %s for user '%s'", error_msg_invalid_pw, username)
                    cur.execute(insert_log_sql, (username, ip_address, user_agent, False))
                    conn.commit()
                    return False, username, error_msg_invalid_pw

                cur.execute(update_login_sql, (username,))

                cur.execute(insert_log_sql, (username, ip_address, user_agent, True))

                conn.commit()

                log.info("User '%s' logged in successfully", username)
                return True, username, None

    except Exception as e:
        if conn:
            conn.rollback()
        return False, None, f"System error: {str(e)}"
    finally:
        release_db_connection(conn)

