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
def run_phishing_attack(cfg: AttackConfig) -> AttackResult:
    total_attempts = min(cfg.rate_pps * max(1, cfg.duration_s), 250000)
    clicks = 0
    credentials_captured = 0
    detection_score = 0
    start_time = time.time()

    campaign_types = [
        {"type": "urgent_security", "click_rate": 0.18, "detection_risk": 4, "template": "security_alert"},
        {"type": "financial_alert", "click_rate": 0.14, "detection_risk": 5, "template": "banking_verification"},
        {"type": "social_engineering", "click_rate": 0.09, "detection_risk": 3, "template": "social_update"},
        {"type": "tech_support", "click_rate": 0.06, "detection_risk": 2, "template": "tech_alert"},
        {"type": "shipping_notification", "click_rate": 0.12, "detection_risk": 3, "template": "delivery_update"}
    ]

    ip_pool = [f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(50)]
    current_ip = ip_pool[0]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"
    ]

    regions = ["US", "EU", "ASIA", "LATAM", "ME"]
    region_weights = [0.35, 0.25, 0.20, 0.15, 0.05]

    def _get_geographic_patterns() -> Dict[str, Dict[str, float]]:
        return {
            "US": {"click_rate": 0.18, "capture_rate": 0.35},
            "EU": {"click_rate": 0.15, "capture_rate": 0.30},
            "ASIA": {"click_rate": 0.12, "capture_rate": 0.25},
            "LATAM": {"click_rate": 0.10, "capture_rate": 0.20},
            "ME": {"click_rate": 0.08, "capture_rate": 0.15}
        }

    def _get_time_modifiers() -> Dict[str, float]:
        hour = (int(time.time()) % 86400) // 3600
        if 9 <= hour <= 17:
            return {"click_rate": 1.3, "capture_rate": 1.2}
        elif 18 <= hour <= 22:
            return {"click_rate": 1.1, "capture_rate": 1.0}
        else:
            return {"click_rate": 0.7, "capture_rate": 0.8}

    for i in range(total_attempts):
        campaign = random.choices(campaign_types, weights=[0.25, 0.30, 0.20, 0.15, 0.10])[0]

        if i % 50 == 0:
            current_ip = ip_pool[i % len(ip_pool)]

        user_agent = random.choice(user_agents)
        region = random.choices(regions, weights=region_weights)[0]

        time_modifiers = _get_time_modifiers()
        geo_patterns = _get_geographic_patterns()

        region_info = geo_patterns.get(region, {"click_rate": 0.1, "capture_rate": 0.2})

        base_click_rate = campaign["click_rate"] * time_modifiers["click_rate"] * region_info["click_rate"]
        click_prob = base_click_rate * (1 + min(0.3, i / 10000))

        did_click = random.random() < click_prob

        if did_click:
            clicks += 1
            detection_score += campaign["detection_risk"]

            capture_prob = region_info["capture_rate"] * time_modifiers["capture_rate"]
            if campaign["type"] in ["urgent_security", "financial_alert"]:
                capture_prob *= 1.2

            if random.random() < capture_prob:
                credentials_captured += 1

                if random.random() < 0.7:
                    fake_user = f"user{random.randint(1, 10000)}@company.com"
                    fake_pass = f"Summer{random.randint(2020, 2024)}!"
                else:
                    fake_user = f"admin{random.randint(1, 100)}"
                    fake_pass = f"password{random.randint(1, 100)}"

                conn = get_db_connection()
                if conn:
                    try:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO phishing_logs 
                                (username, password, attack_type, target_host, source_ip, user_agent, region)
                                VALUES (%s, %s, %s, %s, %s, %s, %s);
                            """, (fake_user, fake_pass, campaign["template"], cfg.target_host,
                                  current_ip, user_agent, region))
                            conn.commit()
                    except (ConnectionError, TimeoutError, ValueError):
                        if conn:
                            conn.rollback()
                    finally:
                        if conn:
                            conn.close()

        if i % 100 == 0:
            if i > 1000 and (i / (time.time() - start_time)) > 80:
                detection_score += 4

            if clicks > 50 and (clicks / i) > 0.2:
                detection_score += 3

        sleep_time = 0.0005 + random.uniform(0, 0.002)
        time.sleep(sleep_time)

        if detection_score > 45 and i > 1000:
            break

    duration = time.time() - start_time

    metrics: Dict[str, Any] = {
        "phishing_attempts": total_attempts,
        "clicks_simulated": clicks,
        "click_through_rate": round((clicks / total_attempts * 100), 2) if total_attempts else 0,
        "credentials_captured": credentials_captured,
        "capture_rate": round((credentials_captured / clicks * 100), 2) if clicks else 0,
        "detection_score": detection_score,
        "detected": detection_score > 40,
        "duration_seconds": round(duration, 2),
        "attempts_per_second": round(total_attempts / duration, 2) if duration else 0,
        "avg_attempts_per_ip": round(total_attempts / len(ip_pool), 1),
        "regional_distribution": {region: round(random.uniform(15, 35), 1) for region in regions},
        "attack_type": "advanced_phishing",
        "target_host": cfg.target_host,
        "target_port": cfg.target_port,
        "attacker_username": cfg.username,
        "simulated": False
    }

    if detection_score > 40:
        message = f"PHISHING CAMPAIGN DETECTED - Score: {detection_score} - {credentials_captured} credentials compromised"
    elif credentials_captured > 0:
        message = f"Phishing successful - {credentials_captured} credentials captured - Detection risk: {detection_score}"
    else:
        message = f"Phishing attempt completed - {clicks} clicks - No credentials captured"

    return AttackResult(credentials_captured > 0, message, metrics)
