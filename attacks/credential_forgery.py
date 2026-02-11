import os
import sys
import time
import random
from typing import Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.base_attack import AttackConfig, AttackResult
    from SDNMFA.database.login_user import login_user
except ImportError:
    from attacks.base_attack import AttackConfig, AttackResult
    from database.login_user import login_user

COMMON_USERNAMES = [
    "admin", "root", "user", "test", "guest", "administrator",
    "support", "info", "webmaster", "server", "mysql", "oracle"
]

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "admin", "1234", "1234567890", "000000",
    "qwerty", "abc123", "password1", "admin123", "welcome"
]

def run_credential_forgery_attack(cfg: AttackConfig) -> AttackResult:
    total_attempts = min(cfg.rate_pps * max(1, cfg.duration_s), 50000)
    success_count = 0
    detection_score = 0
    start_time = time.time()

    attack_patterns = [
        {"type": "dictionary", "ratio": 0.6, "speed": 0.05},
        {"type": "brute_force", "ratio": 0.3, "speed": 0.02},
        {"type": "credential_stuffing", "ratio": 0.1, "speed": 0.1}
    ]

    attempts_count = 0
    last_attempt_time = start_time

    geo_patterns = {
        "US": {"success_rate": 0.25, "detection_risk": 0.3},
        "EU": {"success_rate": 0.20, "detection_risk": 0.4},
        "ASIA": {"success_rate": 0.18, "detection_risk": 0.35},
        "LATAM": {"success_rate": 0.15, "detection_risk": 0.25},
        "ME": {"success_rate": 0.12, "detection_risk": 0.2}
    }

    hour = (int(time.time()) % 86400) // 3600
    if 2 <= hour <= 6:
        time_mods = {"success_rate": 1.2, "detection_risk": 0.7}
    elif 9 <= hour <= 17:
        time_mods = {"success_rate": 1.0, "detection_risk": 1.0}
    else:
        time_mods = {"success_rate": 0.8, "detection_risk": 0.9}

    region = random.choice(list(geo_patterns.keys()))
    geo_success_rate = geo_patterns[region]["success_rate"]
    geo_detection_risk = geo_patterns[region]["detection_risk"]

    for i in range(total_attempts):
        pattern = random.choices(
            attack_patterns,
            weights=[p["ratio"] for p in attack_patterns]
        )[0]

        if pattern["type"] == "dictionary":
            username = random.choice(COMMON_USERNAMES)
            password = random.choice(COMMON_PASSWORDS)
        elif pattern["type"] == "brute_force":
            username = cfg.target_host.split('.')[0]
            password = f"{random.randint(100000, 999999)}"
        else:
            username = f"user{random.randint(1, 1000)}"
            password = f"pass{random.randint(1, 1000)}"

        success, _, message = login_user(username, password)
        if success and random.random() < geo_success_rate * time_mods["success_rate"]:
            success_count += 1

        current_time = time.time()
        time_diff = current_time - last_attempt_time

        if time_diff < 0.1:
            detection_score += 2 * geo_detection_risk * time_mods["detection_risk"]
        if time_diff > 1.0:
            detection_score += 1 * geo_detection_risk * time_mods["detection_risk"]
        if success and success_count > 3:
            detection_score += 5 * geo_detection_risk * time_mods["detection_risk"]

        last_attempt_time = current_time
        attempts_count += 1

        time.sleep(pattern["speed"])

        if detection_score > 50 and attempts_count > 100:
            break

    duration = time.time() - start_time

    metrics: Dict[str, Any] = {
        "total_attempts": attempts_count,
        "successful_logins": success_count,
        "success_rate_percent": round((success_count / attempts_count * 100), 4) if attempts_count else 0,
        "detection_score": detection_score,
        "detected": detection_score > 30,
        "duration_seconds": round(duration, 2),
        "attempts_per_second": round(attempts_count / duration, 2) if duration else 0,
        "attack_type": "credential_forgery",
        "target_host": cfg.target_host,
        "target_port": cfg.target_port,
        "attacker_username": cfg.username,
        "region": region,
        "geo_success_rate": geo_success_rate,
        "time_modifier": time_mods["success_rate"],
        "simulated": True
    }

    message = "Credential forgery attack completed"
    if detection_score > 30:
        message = f"Credential forgery attack detected (score: {detection_score})"

    return AttackResult(success_count > 0, message, metrics)
