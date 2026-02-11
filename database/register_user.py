import os
import sys
import logging
from contextlib import closing
from typing import Optional

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
except ImportError:
    from database.db_config import get_db_connection, release_db_connection

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

def register_user(username: str, full_name: str, email: str, password: str,
                  otp_secret: Optional[str] = None,
                  biometric_template: Optional[str] = None,
                  role: str = "user") -> bool:
    """
    Register new user in users table + log in auth_logs table
    """

    insert_user_sql = """
        INSERT INTO users (username, full_name, email, password_hash, role, otp_secret, biometric_template, last_password_change)
        VALUES (%s, %s, %s, crypt(%s, gen_salt('bf')), %s, %s, %s, CURRENT_TIMESTAMP)
        RETURNING id;
    """

    insert_log_sql = """
        INSERT INTO auth_logs (username, event_type, success)
        VALUES (%s, 'register', TRUE);
    """

    conn = get_db_connection()
    if not conn:
        log.error("Database connection failed. User registration aborted.")
        return False

    try:
        with conn.cursor() as cur:
                cur.execute(insert_user_sql,
                            (username, full_name, email, password, role, otp_secret, biometric_template))
                user_id = cur.fetchone()[0]

                cur.execute(insert_log_sql, (username,))
                conn.commit()

                log.info("User '%s' registered successfully with ID %s", username, user_id)
                print(f"✅ User '{username}' registered successfully.")
                return True

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ Error: Could not register user '{username}'")
        return False, None, f"Failed to register user '%s': %s {str(e)}"
    finally:
        release_db_connection(conn)


if __name__ == "__main__":
    success = register_user(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        password="!QAZzaq1@WSXxsw2"
    )
    print("Result:", "Success" if success else "Failed")
