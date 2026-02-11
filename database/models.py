import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from contextlib import closing

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.database.db_config import get_db_connection
except ImportError:
    from database.db_config import get_db_connection

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

SCHEMA_QUERIES = [
    """CREATE EXTENSION IF NOT EXISTS "pgcrypto";""",

    """
    CREATE TABLE IF NOT EXISTS users (
        id                  SERIAL PRIMARY KEY,
        username            VARCHAR(50) UNIQUE NOT NULL,
        full_name           VARCHAR(100),
        email               VARCHAR(100) UNIQUE,
        password_hash       TEXT NOT NULL,
        role                VARCHAR(20) DEFAULT 'user',
        otp_secret          TEXT,
        biometric_template  TEXT,
        is_active           BOOLEAN DEFAULT TRUE,
        last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login          TIMESTAMP,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);""",
    """CREATE INDEX IF NOT EXISTS idx_users_email    ON users (email);""",

    """
    CREATE TABLE IF NOT EXISTS auth_logs (
        log_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username            VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
        event_type          VARCHAR(50),
        ip_address          INET,
        auth_logs_details   TEXT,
        user_agent          TEXT,
        timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success             BOOLEAN
    );
    """,
    """CREATE INDEX IF NOT EXISTS idx_logs_username  ON auth_logs(username);""",
    """CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON auth_logs(timestamp);""",

    """
    CREATE TABLE IF NOT EXISTS otp_sessions (
        id          BIGSERIAL PRIMARY KEY,
        username    VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
        otp_hash    TEXT NOT NULL,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at  TIMESTAMP NOT NULL,
        used        BOOLEAN DEFAULT FALSE
    );
    """,
    """CREATE INDEX IF NOT EXISTS idx_otp_username ON otp_sessions(username);""",
    """CREATE INDEX IF NOT EXISTS idx_otp_expires  ON otp_sessions(expires_at);""",
    """CREATE INDEX IF NOT EXISTS idx_otp_used     ON otp_sessions(used);""",

    """
    CREATE TABLE IF NOT EXISTS trusted_devices (
        device_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username    VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
        device_name VARCHAR(100),
        last_used   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """CREATE INDEX IF NOT EXISTS idx_trusted_username ON trusted_devices(username);"""
    """
    CREATE TABLE IF NOT EXISTS attack_logs (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        attack_type VARCHAR(50) NOT NULL,
        target_host VARCHAR(100) NOT NULL,
        target_port INTEGER NOT NULL,
        duration_seconds INTEGER NOT NULL,
        rate_pps INTEGER NOT NULL,
        threads INTEGER NOT NULL,
        mfa_mode VARCHAR(50),
        attack_params JSONB,
        attack_result JSONB,
        packets_sent BIGINT,
        bytes_sent BIGINT,
        actual_rate_pps FLOAT,
        success BOOLEAN NOT NULL,
        message TEXT,
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """CREATE INDEX IF NOT EXISTS idx_attack_logs_username ON attack_logs(username);""",
    """CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(created_at);"""

    """ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS mfa_mode VARCHAR(50);""",
    """ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS attack_params JSONB;""",
    """ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS attack_result JSONB;""",
    
    """
        CREATE TABLE IF NOT EXISTS phishing_logs (
            id BIGSERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target_host TEXT NOT NULL,
            source_ip TEXT,
            user_agent TEXT,
            region TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """CREATE INDEX IF NOT EXISTS idx_phishing_logs_username ON phishing_logs(username);""",
        """CREATE INDEX IF NOT EXISTS idx_phishing_logs_created_at ON phishing_logs(created_at);"""
]

def table_exists(cur, name: str) -> bool:
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=%s);",
        (name,)
    )
    return bool(cur.fetchone()[0])

def column_exists(cur, table: str, column: str) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name=%s AND column_name=%s
        );
        """,
        (table, column)
    )
    return bool(cur.fetchone()[0])

def migrate_otp_codes_to_sessions(cur):
    if not table_exists(cur, "otp_codes"):
        return False

    log.warning("Legacy table 'otp_codes' detected. Starting migration -> 'otp_sessions'")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS otp_sessions (
            id          BIGSERIAL PRIMARY KEY,
            username    VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
            otp_code    TEXT NOT NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at  TIMESTAMP NOT NULL,
            used        BOOLEAN DEFAULT FALSE
        );
    """)

    has_used = column_exists(cur, "otp_codes", "used")

    insert_sql = """
        INSERT INTO otp_sessions (username, otp_code, created_at, expires_at, used)
        SELECT username, otp_hash, issued_at, expires_at, {used_expr}
        FROM otp_codes;
    """.format(used_expr="used" if has_used else "FALSE")

    cur.execute(insert_sql)
    cur.execute("DROP TABLE otp_codes;")

    log.info("Migration from 'otp_codes' to 'otp_sessions' completed.")
    return True

def create_or_migrate_schema():
    from auto_migrator import auto_migrate
    auto_migrate()

    with closing(get_db_connection()) as conn:
        if not conn:
            log.error("DB connection failed. Schema creation skipped.")
            print("Database connection failed.")
            return

        if hasattr(conn, 'cursor'):
            with conn:
                with conn.cursor() as cur:
                    for q in SCHEMA_QUERIES:
                        cur.execute(q)

            print("Database schema is up to date.")
        else:
            log.error("Connection object does not have cursor method")

if __name__ == "__main__":
    create_or_migrate_schema()
