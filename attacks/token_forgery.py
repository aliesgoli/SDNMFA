import os
import sys
import time
import random
import json
import base64
import hmac
import hashlib

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.base_attack import AttackConfig, AttackResult
except ImportError:
    from attacks.base_attack import AttackConfig, AttackResult

def generate_token(payload: dict, secret_key: str = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

    if not secret_key:
        return f"{header_encoded}.{payload_encoded}."

    signature = hmac.new(secret_key.encode(), f"{header_encoded}.{payload_encoded}".encode(), hashlib.sha256)
    signature_encoded = base64.urlsafe_b64encode(signature.digest()).decode().rstrip('=')
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def run_attack(cfg: AttackConfig) -> AttackResult:
    weak_secret_key = "default_weak_secret_123"
    attempts = min(cfg.rate_pps, 1000)
    success_count = 0
    detected_count = 0
    test_cases = []

    for i in range(attempts):
        victim_user = f"user{random.randint(1, 100)}"
        token_payload = {
            "sub": victim_user,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "admin": random.choice([True, False])
        }

        attack_type = random.choice(["unsigned", "weak_signed", "invalid_signature"])
        forged_token = ""

        if attack_type == "unsigned":
            forged_token = generate_token(token_payload)
            test_cases.append({"type": "unsigned", "token": forged_token[:50] + "..."})

        elif attack_type == "weak_signed":
            forged_token = generate_token(token_payload, weak_secret_key)
            test_cases.append({"type": "weak_signed", "token": forged_token[:50] + "..."})

        elif attack_type == "invalid_signature":
            forged_token = generate_token(token_payload, "invalid_secret_abc")
            test_cases.append({"type": "invalid_signature", "token": forged_token[:50] + "..."})

        validation_result = validate_token(forged_token, weak_secret_key)

        if validation_result == "accepted":
            success_count += 1
        elif validation_result == "detected":
            detected_count += 1

        if attempts > 10:
            time.sleep(0.001)

    success_rate = round(100.0 * success_count / attempts, 2) if attempts else 0.0
    detection_rate = round(100.0 * detected_count / attempts, 2) if attempts else 0.0

    metrics = {
        "attack_scenarios": ["unsigned", "weak_signed", "invalid_signature"],
        "total_attempts": attempts,
        "successful_hijacks": success_count,
        "detected_attacks": detected_count,
        "success_rate_percent": success_rate,
        "detection_rate_percent": detection_rate,
        "weak_secret_used": weak_secret_key,
        "sample_test_cases": test_cases[:3]
    }

    message = f"Token forgery completed: {success_count}/{attempts} successful"
    return AttackResult(True, message, metrics)

def validate_token(token: str, known_weak_key: str) -> str:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return "detected"

        header_encoded, payload_encoded, signature_encoded = parts

        header = json.loads(base64.urlsafe_b64decode(header_encoded + '===').decode())
        _ = json.loads(base64.urlsafe_b64decode(payload_encoded + '===').decode())

        if header.get('alg') == 'none':
            return "detected"

        if not signature_encoded:
            return "detected"

        expected_signature = hmac.new(known_weak_key.encode(),
                                      f"{header_encoded}.{payload_encoded}".encode(),
                                      hashlib.sha256)
        expected_encoded = base64.urlsafe_b64encode(expected_signature.digest()).decode().rstrip('=')

        if hmac.compare_digest(signature_encoded, expected_encoded):
            return "accepted"

        return "detected"

    except (ValueError, json.JSONDecodeError):
        return "detected"
