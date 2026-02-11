import os
import sys
import time
import random
from typing import Dict, Any, List
import psycopg2

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.base_attack import AttackConfig, AttackResult
    from SDNMFA.database.db_config import get_db_connection
except ImportError:
    from attacks.base_attack import AttackConfig, AttackResult
    from database.db_config import get_db_connection

def run_unauthorized_access_attack(cfg: AttackConfig) -> AttackResult:
    total_attempts = min(cfg.rate_pps * max(1, cfg.duration_s), 50000)
    escalation_success = 0
    detection_score = 0
    start_time = time.time()

    misconfiguration_chance = 0.1

    real_user_targets = [
        "admin", "administrator", "root", "sysadmin", "webmaster",
        "support", "helpdesk", "operator", "manager", "supervisor"
    ]

    escalation_methods = [
        {"name": "role_manipulation", "success_rate": 0.01, "detection_risk": 5, "requires_mfa_bypass": True},
        {"name": "permission_bypass", "success_rate": 0.03, "detection_risk": 4, "requires_mfa_bypass": False},
        {"name": "session_hijacking", "success_rate": 0.02, "detection_risk": 6, "requires_mfa_bypass": True},
        {"name": "config_exploit", "success_rate": 0.015, "detection_risk": 3, "requires_mfa_bypass": False},
        {"name": "token_theft", "success_rate": 0.025, "detection_risk": 7, "requires_mfa_bypass": True},
        {"name": "api_exploit", "success_rate": 0.018, "detection_risk": 4, "requires_mfa_bypass": False},
        {"name": "mfa_bypass", "success_rate": 0.005, "detection_risk": 8, "requires_mfa_bypass": False}
    ]

    ip_pool = [f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(100)]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/7.68.0",
        "Python-urllib/3.8"
    ]

    def scan_vulnerabilities() -> List[Dict[str, Any]]:
        vulns = [
            {"type": "sql_injection", "severity": "high", "confidence": 0.85, "affects_mfa": False},
            {"type": "xss", "severity": "medium", "confidence": 0.70, "affects_mfa": False},
            {"type": "misconfiguration", "severity": "low", "confidence": 0.60, "affects_mfa": True},
            {"type": "session_fixation", "severity": "high", "confidence": 0.75, "affects_mfa": True},
            {"type": "jwt_vulnerability", "severity": "medium", "confidence": 0.65, "affects_mfa": True}
        ]
        return random.sample(vulns, random.randint(1, 3))

    def chain_exploits(vuln_list: List[Dict[str, Any]]) -> float:
        chain_success_chance = 0.0
        mfa_bypass_possible = False

        for vuln in vuln_list:
            if vuln["severity"] == "high":
                chain_success_chance += 0.3
            elif vuln["severity"] == "medium":
                chain_success_chance += 0.2
            else:
                chain_success_chance += 0.1

            if vuln["affects_mfa"]:
                mfa_bypass_possible = True

        if mfa_bypass_possible:
            chain_success_chance *= 1.5

        return min(chain_success_chance, 0.8)

    def check_mfa_requirement(username: str) -> bool:
        connection = get_db_connection()
        if not connection:
            return True

        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT otp_secret IS NOT NULL AS has_mfa, 
                           role IN ('admin', 'superadmin') AS is_privileged
                    FROM users WHERE username = %s;
                """, (username,))
                result_row = cursor.fetchone()

                if result_row:
                    has_mfa, is_privileged = result_row
                    return has_mfa or is_privileged

        except (psycopg2.DatabaseError, psycopg2.OperationalError):
            pass
        finally:
            if connection:
                connection.close()

        return True

    def attempt_mfa_bypass(_: str, bypass_method: Dict[str, Any]) -> bool:
        if random.random() < bypass_method["success_rate"]:
            if random.random() < misconfiguration_chance:
                return True

            bypass_techniques = [
                "session_fixation", "token_replay", "time_based_attack",
                "social_engineering", "sim_swapping"
            ]
            _ = random.choice(bypass_techniques)

            success_chance = 0.1 * (1 + misconfiguration_chance * 5)
            return random.random() < success_chance

        return False

    detected_vulnerabilities = scan_vulnerabilities()
    exploit_success_rate = chain_exploits(detected_vulnerabilities)

    test_user = "default_user"

    for i in range(total_attempts):
        current_ip = ip_pool[i % len(ip_pool)]
        user_agent = random.choice(user_agents)

        if random.random() < 0.7 and real_user_targets:
            test_user = random.choice(real_user_targets)
        else:
            test_user = f"user{random.randint(1, 500)}"

        db_connection = get_db_connection()
        if not db_connection:
            continue

        try:
            with db_connection.cursor() as db_cursor:
                db_cursor.execute("SELECT role, is_active, otp_secret FROM users WHERE username = %s;", (test_user,))
                user_data = db_cursor.fetchone()

                if not user_data:
                    db_cursor.execute("""
                        INSERT INTO users (username, full_name, email, password_hash, role) 
                        VALUES (%s, %s, %s, crypt(%s, gen_salt('bf')), 'user') 
                        ON CONFLICT (username) DO NOTHING;
                    """, (test_user, test_user, f"{test_user}@test.local", "Test1234"))
                    db_connection.commit()
                    current_role, is_active, _ = "user", True, None
                else:
                    current_role = user_data[0] or "user"
                    is_active = user_data[1] if user_data[1] is not None else True
                    _ = user_data[2]

                if not is_active:
                    continue

                selected_method = random.choice(escalation_methods)
                attempt_success_chance = selected_method["success_rate"] * exploit_success_rate

                mfa_required = check_mfa_requirement(test_user)
                mfa_bypassed = False

                if mfa_required and selected_method["requires_mfa_bypass"]:
                    mfa_bypassed = attempt_mfa_bypass(test_user, selected_method)
                    if not mfa_bypassed:
                        attempt_success_chance = 0.0
                    else:
                        attempt_success_chance *= 2.0

                success = False
                if random.random() < attempt_success_chance and current_role != "admin":
                    if random.random() < 0.8:
                        db_cursor.execute("UPDATE users SET role = 'admin' WHERE username = %s;", (test_user,))
                        db_connection.commit()
                        escalation_success += 1
                        success = True
                        detection_score += selected_method["detection_risk"] * (3 if mfa_bypassed else 2)

                log_details = {
                    "method": selected_method["name"],
                    "mfa_required": mfa_required,
                    "mfa_bypassed": mfa_bypassed,
                    "vulnerabilities": [v["type"] for v in detected_vulnerabilities],
                    "success": success
                }

                db_cursor.execute("""
                    INSERT INTO auth_logs (username, event_type, success, ip_address, user_agent, auth_logs_details) 
                    VALUES (%s, 'privilege_escalation_attempt', %s, %s, %s, %s);
                """, (test_user, success, current_ip, user_agent, str(log_details)))
                db_connection.commit()

                if i % 20 == 0 and i > 50:
                    detection_score += 3

                if i > 10 and (i / (time.time() - start_time)) > 50:
                    detection_score += 4

        except (psycopg2.DatabaseError, psycopg2.OperationalError):
            if db_connection:
                db_connection.rollback()
            detection_score += 2
        finally:
            if db_connection:
                db_connection.close()

        time.sleep(0.003 + random.uniform(0, 0.007))

        if detection_score > 45 and i > 200:
            break

    duration = time.time() - start_time

    metrics: Dict[str, Any] = {
        "total_attempts": total_attempts,
        "successful_escalations": escalation_success,
        "success_rate_percent": round((escalation_success / total_attempts * 100), 4) if total_attempts else 0,
        "detection_score": detection_score,
        "detected": detection_score > 40,
        "duration_seconds": round(duration, 2),
        "attempts_per_second": round(total_attempts / duration, 2) if duration else 0,
        "attack_type": "unauthorized_access",
        "target_host": cfg.target_host,
        "target_port": cfg.target_port,
        "attacker_username": cfg.username,
        "vulnerabilities_found": len(detected_vulnerabilities),
        "exploit_success_rate": round(exploit_success_rate, 3),
        "misconfiguration_chance": misconfiguration_chance,
        "mfa_bypass_attempts": sum(1 for m in escalation_methods if m["requires_mfa_bypass"]),
        "real_user_targets_used": len([u for u in real_user_targets if u == test_user]),
        "simulated": False
    }

    message = "Unauthorized access simulation completed"
    if detection_score > 40:
        message = f"Unauthorized access detected (score: {detection_score})"
    elif escalation_success > 0:
        message = f"Privilege escalation successful - {escalation_success} escalations"

        if misconfiguration_chance > 0.2:
            message += " (exploiting misconfiguration)"

    return AttackResult(escalation_success > 0, message, metrics)
