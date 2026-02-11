from __future__ import annotations
import os
import sys
import logging
import json
import urllib.request
import urllib.error
import subprocess
from datetime import datetime
from typing import Optional, Tuple

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
project_parent = os.path.abspath(os.path.join(project_root, '..'))
if project_parent not in sys.path:
    sys.path.insert(0, project_parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from SDNMFA.database.db_config import close_all_connections, get_db_connection, release_db_connection
    from SDNMFA.attacks.attack_manager import AttackManager, AttackConfig
    from SDNMFA.attacks.base_attack import AttackResult
    from SDNMFA.security.mfa_manager import authenticate_user
    from SDNMFA.otp.otp_service import generate_otp, store_otp, validate_otp, deliver_otp
except ImportError:
    from database.db_config import close_all_connections, get_db_connection, release_db_connection
    from attacks.attack_manager import AttackManager, AttackConfig
    from attacks.base_attack import AttackResult
    from security.mfa_manager import authenticate_user
    from otp.otp_service import generate_otp, store_otp, validate_otp, deliver_otp

LOG_DIR = os.path.abspath(os.path.join(project_root, 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.FileHandler(os.path.join(LOG_DIR, 'mfa_controller.log'), encoding='utf-8')]
)


def setup_noisy_loggers():
    module_candidates = [
        (['SDNMFA.database.db_config', 'database.db_config'], 'Database Config'),
        (['SDNMFA.otp.otp_service', 'otp.otp_service'], 'OTP Service'),
        (['SDNMFA.security.mfa_manager', 'security.mfa_manager'], 'MFA Manager'),
        (['attacks.attack_manager'], 'Attack Manager'),
        (['attacks.base_attack'], 'Base Attack'),
        (['attacks.credential_forgery'], 'Credential Forgery'),
        (['attacks.credential_theft'], 'Credential Theft'),
        (['attacks.phishing'], 'Phishing Attack'),
        (['attacks.token_forgery'], 'Token Forgery'),
        (['attacks.unauthorized_access'], 'Unauthorized Access'),
        (['attacks.dos_udp_flood'], 'DoS UDP Flood'),
        (['attacks.ddos_udp_flood'], 'DDoS UDP Flood'),
        (['attacks.mitm'], 'MITM Attack'),
    ]

    configured = []
    for names, description in module_candidates:
        if not isinstance(names, list):
            names = [names]

        for module_name in names:
            try:
                logger = logging.getLogger(module_name)
                logger.setLevel(logging.ERROR)
                configured.append(f"{description} ({module_name})")
                break
            except Exception as e:
                continue

    if configured:
        logger = logging.getLogger(__name__)

def _ryu_request(path: str, method: str = "GET", payload: dict | None = None, timeout: float = 2.0) -> tuple[bool, dict]:
    url = f"http://127.0.0.1:8080{path}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8").strip()
            return True, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8").strip()
            return False, json.loads(body) if body else {"status": int(e.code)}
        except Exception:
            return False, {"status": int(e.code)}
    except Exception as e:
        return False, {"error": str(e)}


def _get_in_port_from_fdb(mac: str) -> Optional[int]:
    try:
        out = subprocess.check_output(["bash", "-lc", "ovs-appctl fdb/show s1 2>/dev/null || true"], text=True)
        mac = mac.lower().strip()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                if parts[1].lower() == mac:
                    return int(parts[0])
    except Exception:
        return None
    return None

def _load_mininet_ctx() -> dict:
    try:
        with open("/tmp/sdnmfa_mn.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


setup_noisy_loggers()

logger = logging.getLogger(__name__)

MAX_AUTH_ATTEMPTS = 3

ATTACK_DEFAULTS = {
    "credential_forgery": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🔓 Credential Forgery with Dictionary Attack",
        "needs_gateway": False,
        "expected_packets": "100000+",
        "detection_threshold": "30-50 score"
    },
    "credential_theft": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🕵️ SQL Injection - Database Theft",
        "needs_gateway": False,
        "expected_packets": "Simulated",
        "detection_threshold": "Immediate"
    },
    "phishing": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🎣 Phishing Campaign - Credential Harvesting",
        "needs_gateway": False,
        "expected_packets": "200000+",
        "detection_threshold": "40+ score"
    },
    "token_forgery": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🔑 JWT Token Forgery - Auth System Attack",
        "needs_gateway": False,
        "expected_packets": "1000-2000",
        "detection_threshold": "Medium"
    },
    "unauthorized_access": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "⛔ Privilege Escalation - Unauthorized Access",
        "needs_gateway": False,
        "expected_packets": "60000+",
        "detection_threshold": "40+ score"
    },
    "dos_udp_flood": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "💥 DoS Attack - UDP Flood",
        "needs_gateway": False,
        "expected_packets": "250000+",
        "detection_threshold": "Immediate - 80%+"
    },
    "ddos_udp_flood": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🌊 Distributed DDoS - UDP Flood",
        "needs_gateway": False,
        "expected_packets": "1000000+",
        "detection_threshold": "Immediate - Critical"
    },
    "mitm": {
        "host": "10.0.0.2",
        "port": 18080,
        "duration": 5,
        "rate": 200,
        "threads": 1,
        "description": "🕵️ Man-in-the-Middle - ARP Poisoning",
        "needs_gateway": True,
        "gateway": "10.0.0.1",
        "expected_packets": "ARP Spoofing",
        "detection_threshold": "Detectable"
    }
}


class MFAController:



    def _to_jsonable(self, obj):
        """Convert arbitrary Python objects to JSON-serializable structures."""
        from dataclasses import asdict, is_dataclass
        import datetime
        import json

        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        if is_dataclass(obj):
            return {k: self._to_jsonable(v) for k, v in asdict(obj).items()}
        if isinstance(obj, dict):
            return {str(k): self._to_jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [self._to_jsonable(v) for v in obj]
        if hasattr(obj, '__dict__'):
            return {k: self._to_jsonable(v) for k, v in vars(obj).items()}
        return str(obj)

    def _safe_json(self, obj):
        """Return an object guaranteed to be JSON-serializable."""
        import json
        cleaned = self._to_jsonable(obj)
        json.dumps(cleaned, ensure_ascii=False)
        return cleaned

    def __init__(self):
        self.attack_manager = AttackManager()
        logger.info('MFAController initialized')

    def execute_attack(self, username: str, attack_type: str, target_host: str,
                       target_port: int, duration_s: int, rate_pps: int,
                       threads: int, mfa_mode: str, gateway_ip: Optional[str] = None) -> AttackResult:
        """Execute an attack and persist a detailed attempt record to attack_logs.

        What gets stored (if the DB schema supports it):
        - mfa_mode
        - attack_params (JSON)
        - attack_result (JSON)

        The insert is schema-flexible: it detects available columns and only writes those.
        """
        try:
            config = AttackConfig(
                username=username,
                target_host=target_host,
                target_port=target_port,
                duration_s=duration_s,
                rate_pps=rate_pps,
                threads=threads,
                mfa_mode=mfa_mode,
                attack_type=attack_type,
                gateway_ip=gateway_ip
            )

            attack_params = {
                "attack_type": attack_type,
                "target_host": target_host,
                "target_port": target_port,
                "duration_s": duration_s,
                "rate_pps": rate_pps,
                "threads": threads,
                "mfa_mode": mfa_mode,
                "gateway_ip": gateway_ip,
            }

            start_ts = datetime.now()

            print(f"\n⚡ Starting {attack_type} attack...")
            print(f"🎯 Target: {target_host}:{target_port}")
            print(f"⏱️  Duration: {duration_s}s | Rate: {rate_pps} pps | Threads: {threads}")

            if gateway_ip:
                print(f"🌐 Gateway: {gateway_ip}")

            print("\n" + "=" * 70)

            result = self.attack_manager.execute_attack(config.attack_type, config)
            end_ts = datetime.now()

            # Persist log (best-effort; never blocks the CLI)
            try:
                self._log_attack_attempt(
                    username=username,
                    mfa_mode=mfa_mode,
                    attack_type=attack_type,
                    target_host=target_host,
                    target_port=target_port,
                    duration_s=duration_s,
                    rate_pps=rate_pps,
                    threads=threads,
                    attack_params=self._safe_json(attack_params),
                    result=self._safe_json(result),
                    start_ts=start_ts,
                    end_ts=end_ts,
                )
            except Exception as log_e:
                print(f"⚠️ Could not write attack log to DB: {log_e}")

            return result

        except Exception as e:
            print(f"❌ Attack execution failed: {e}")
            return AttackResult(success=False, message=f"Attack failed: {str(e)}", metrics={})



    def _log_attack_attempt(
        self,
        *,
        username: str,
        mfa_mode: str,
        attack_type: str,
        target_host: str,
        target_port: int,
        duration_s: int,
        rate_pps: int,
        threads: int,
        attack_params: dict,
        result: object,
        start_ts: datetime,
        end_ts: datetime,
    ) -> None:
        """Persist an attack execution record to attack_logs.

        Best-effort: raises only if coding/DB errors occur; caller catches.
        Stores mfa_mode + attack_params/result (JSONB) when available.
        """
        conn = get_db_connection()
        if conn is None:
            raise RuntimeError("Database connection is not available")

        # Normalize common fields from result structure
        success = bool(result.get("success")) if isinstance(result, dict) else False
        message = None
        packets_sent = None
        bytes_sent = None
        actual_rate_pps = None

        if isinstance(result, dict):
            message = result.get("message") or result.get("details") or result.get("error")
            metrics = result.get("metrics") or {}
            if isinstance(metrics, dict):
                packets_sent = metrics.get("packets_sent")
                bytes_sent = metrics.get("bytes_sent")
                actual_rate_pps = metrics.get("actual_rate_pps") or metrics.get("pps")

        try:
            with conn.cursor() as cur:
                attack_params_json = self._safe_json(attack_params or {})
                attack_result_json = self._safe_json(result or {})
                cur.execute(
                    """
                    INSERT INTO attack_logs (
                        username, attack_type, target_host, target_port,
                        duration_seconds, rate_pps, threads,
                        mfa_mode, attack_params, attack_result,
                        packets_sent, bytes_sent, actual_rate_pps,
                        success, message, start_time, end_time
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s::jsonb, %s::jsonb,
                        %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    """,
                    (
                        username,
                        str(attack_type),
                        str(target_host),
                        int(target_port),
                        int(duration_s),
                        int(rate_pps),
                        int(threads),
                        str(mfa_mode) if mfa_mode is not None else None,
                        json.dumps(attack_params_json),
                        json.dumps(attack_result_json),
                        packets_sent,
                        bytes_sent,
                        actual_rate_pps,
                        success,
                        message,
                        start_ts,
                        end_ts,
                    ),
                )
            conn.commit()
        finally:
            release_db_connection(conn)

    def login(self, username: str, password: str, policy_key: str = "1") -> Tuple[bool, str]:
        otp_code = None
        biometric_data = None

        if policy_key in ["2", "4"]:
            new_otp = generate_otp()
            success, msg = store_otp(username, new_otp)
            if not success:
                if "Database connection failed" in msg or "connection" in msg.lower():
                    return False, "database_error"
                return False, msg

            deliver_otp(username, new_otp)
            print(f"\n🔐 Generated OTP: {new_otp}")

            otp_code = input("🔢 Enter OTP code: ").strip()

        if policy_key in ["3", "4"]:
            biometric_data = input("👆 Biometric Data: ").strip()

        success, message = authenticate_user(
            username=username,
            password=password,
            otp_code=otp_code,
            biometric_data=biometric_data,
            policy_key=policy_key
        )

        if success:
            print("✅ Authentication successful!")
            return True, "success"
        else:
            if "Database connection failed" in message or "connection" in message.lower():
                return False, "database_error"
            print(f"❌ Authentication failed: {message}")
            return False, message


class CLIInterface:
    @staticmethod
    def print_header(title: str):
        print(f"\n{'=' * 70}")
        print(f" {title.upper()} ".center(70))
        print(f"{'=' * 70}")

    @staticmethod
    def print_section(title: str):
        print(f"\n{title}")
        print("-" * 70)

    def display_available_attacks(self, controller: MFAController):
        self.print_section("📋 Available Attacks")

        attack_info = controller.attack_manager.get_available_attacks_display()

        for key, (display_name, attack_key) in sorted(attack_info.items()):
            defaults = ATTACK_DEFAULTS.get(attack_key, {})
            desc = defaults.get("description", "")
            expected = defaults.get("expected_packets", "")
            detection = defaults.get("detection_threshold", "")

            print(f"\n  {key}. {display_name}")
            if desc:
                print(f"      {desc}")
            if expected:
                print(f"      📊 Expected packets: {expected}")
            if detection:
                print(f"      🛡️  Detection threshold: {detection}")

    def get_attack_choice(self, controller: MFAController) -> str:
        attack_info = controller.attack_manager.get_available_attacks_display()
        valid_choices = list(attack_info.keys())

        while True:
            choices_str = ",".join([str(x) for x in valid_choices])
            choice_raw = input(f"\n🔢 Select attack number [{choices_str}]: ").strip()
            if choice_raw.isdigit():
                key = int(choice_raw)
            else:
                key = choice_raw
            if key in attack_info:
                return attack_info[key][1]
            choices_pretty = ", ".join([str(x) for x in valid_choices])
            print(f"❌ Invalid choice. Please select one of: {choices_pretty}")

    def get_attack_parameters(self, attack_type: str) -> Tuple[str, int, int, int, int, Optional[str]]:
        self.print_header(f"Attack Configuration: {attack_type}")

        defaults = ATTACK_DEFAULTS.get(attack_type, {
            "host": "10.0.0.2",
            "port": 18080,
            "duration": 5,
            "rate": 200,
            "threads": 1,
            "needs_gateway": False
        })

        print(f"\n💡 Recommended settings for {attack_type}:")
        print(f"   🎯 Target: {defaults['host']}:{defaults['port']}")
        print(f"   ⏱️  Duration: {defaults['duration']} seconds")
        print(f"   📊 Rate: {defaults['rate']} PPS")
        print(f"   🧵 Threads: {defaults['threads']}")

        if defaults.get('expected_packets'):
            print(f"   📈 Expected packets: {defaults['expected_packets']}")

        if defaults.get('detection_threshold'):
            print(f"   🛡️  Detection threshold: {defaults['detection_threshold']}")

        use_defaults = input("\n🔧 Use recommended settings? (Y/n): ").strip().lower()

        if use_defaults in ['', 'y', 'yes']:
            target_host = defaults['host']
            target_port = defaults['port']
            duration = defaults['duration']
            rate = defaults['rate']
            threads = defaults['threads']
            gateway_ip = defaults.get('gateway') if defaults.get('needs_gateway') else None

            print("\n✅ Using recommended settings")

        else:
            print("\n⚙️  Manual Configuration:")

            while True:
                target_host = input(f"🎯 Target IP [{defaults['host']}]: ").strip() or defaults['host']
                try:
                    import socket
                    socket.inet_aton(target_host)
                    break
                except socket.error:
                    print("❌ Invalid IP address format")

            while True:
                port_input = input(f"🔌 Port [{defaults['port']}]: ").strip()
                if not port_input:
                    target_port = defaults['port']
                    break
                try:
                    target_port = int(port_input)
                    if 0 <= target_port <= 65535:
                        break
                    print("❌ Port must be between 0 and 65535")
                except ValueError:
                    print("❌ Port must be a number")

            while True:
                duration_input = input(f"⏱️  Duration (seconds) [{defaults['duration']}]: ").strip()
                if not duration_input:
                    duration = defaults['duration']
                    break
                try:
                    duration = int(duration_input)
                    if 1 <= duration <= 300:
                        break
                    print("❌ Duration must be between 1 and 300 seconds")
                except ValueError:
                    print("❌ Duration must be a number")

            while True:
                rate_input = input(f"📊 Rate (PPS) [{defaults['rate']}]: ").strip()
                if not rate_input:
                    rate = defaults['rate']
                    break
                try:
                    rate = int(rate_input)
                    if 1 <= rate <= 1000000:
                        break
                    print("❌ Rate must be between 1 and 1,000,000 PPS")
                except ValueError:
                    print("❌ Rate must be a number")

            while True:
                threads_input = input(f"🧵 Threads [{defaults['threads']}]: ").strip()
                if not threads_input:
                    threads = defaults['threads']
                    break
                try:
                    threads = int(threads_input)
                    if 1 <= threads <= 64:
                        break
                    print("❌ Threads must be between 1 and 64")
                except ValueError:
                    print("❌ Threads must be a number")

            gateway_ip = None
            if defaults.get('needs_gateway'):
                while True:
                    gateway_input = input(f"🌐 Gateway IP [{defaults.get('gateway', '10.0.0.1')}]: ").strip()
                    gateway_ip = gateway_input or defaults.get('gateway', '10.0.0.1')
                    try:
                        import socket
                        socket.inet_aton(gateway_ip)
                        break
                    except socket.error:
                        print("❌ Invalid gateway IP format")

        print(f"\n📋 Configuration Summary:")
        print(f"   🎯 Target: {target_host}:{target_port}")
        print(f"   ⏱️  Duration: {duration}s | 📊 Rate: {rate} PPS | 🧵 Threads: {threads}")
        if gateway_ip:
            print(f"   🌐 Gateway: {gateway_ip}")

        return target_host, target_port, duration, rate, threads, gateway_ip

    def get_authentication_parameters(self) -> Tuple[str, str, str]:
        self.print_header("🔐 User Authentication")

        username = input("👤 Username: ").strip()
        password = input("🔑 Password: ").strip()

        self.print_section("📜 Select MFA Policy")
        print("1. 🔑 Password Only")
        print("2. 🔑🔢 Password + OTP")
        print("3. 🔑👆 Password + Biometric")
        print("4. 🔑🔢👆 Password + OTP + Biometric (Full MFA)")

        while True:
            policy_choice = input("\n🔢 Select policy [1-4]: ").strip()
            if policy_choice in ["1", "2", "3", "4"]:
                break
            print("❌ Invalid choice")

        return username, password, policy_choice

    def display_attack_results(self, result: AttackResult):
        self.print_header("📊 Attack Results")

        if result.success:
            print("✅ STATUS: ATTACK COMPLETED SUCCESSFULLY")
            print("⚠️  The attack was executed and simulated properly")
        else:
            print("❌ STATUS: ATTACK FAILED OR BLOCKED")
            print("🛡️  Defense systems neutralized the attack")

        print(f"\n📝 Message: {result.message}")

        if result.metrics:
            self.print_section("📈 Performance Metrics")

            critical_metrics = {
                'attack_type': 'Attack Type',
                'target_host': 'Target Host',
                'target_port': 'Target Port',
                'duration_seconds': 'Duration (seconds)',
                'packets_sent': 'Packets Sent',
                'bytes_sent': 'Bytes Sent',
                'actual_rate_pps': 'Actual Rate (PPS)',
                'rate_achievement_percent': 'Target Achievement (%)',
                'success_rate_percent': 'Success Rate (%)',
                'detection_score': 'Detection Score',
                'detected': 'Detected'
            }

            print("\n🔴 Critical Metrics:")
            for key, label in critical_metrics.items():
                if key in result.metrics:
                    value = result.metrics[key]
                    if value is not None:
                        if isinstance(value, float):
                            formatted_value = f"{value:.2f}"
                        elif isinstance(value, bool):
                            formatted_value = "✅ YES" if value else "❌ NO"
                        elif isinstance(value, int) and value > 1000:
                            formatted_value = f"{value:,}"
                        else:
                            formatted_value = str(value)

                        print(f"   • {label}: {formatted_value}")

            other_metrics = {k: v for k, v in result.metrics.items()
                             if k not in critical_metrics and v is not None}

            if other_metrics:
                print("\n🔵 Additional Details:")
                for key, value in other_metrics.items():
                    formatted_key = key.replace('_', ' ').title()
                    if isinstance(value, (dict, list)) and len(str(value)) > 100:
                        print(f"   • {formatted_key}: [Complex data]")
                    else:
                        print(f"   • {formatted_key}: {value}")

        print("\n" + "=" * 70)
        self._interpret_results(result)
        print("=" * 70)

    @staticmethod
    def _interpret_results(result: AttackResult):
        metrics = result.metrics

        if not metrics:
            return

        print("\n" + "=" * 70)
        print(" 🔬 Advanced Security Analysis ".center(70, "="))
        print("=" * 70)

        attack_type = metrics.get('attack_type', 'unknown')
        success = result.success

        if success:
            print("🎯 Attack Execution: ✅ COMPLETED")
        else:
            print("🎯 Attack Execution: ❌ FAILED")

        print()

        if attack_type in ['dos_udp_flood', 'ddos_udp_flood']:
            achievement = metrics.get('rate_achievement_percent', 0)
            packets_sent = metrics.get('packets_sent', 0)
            bytes_sent = metrics.get('bytes_sent', 0)

            print("📊 DoS/DDoS Analysis:")
            print(f"   • Packets Sent: {packets_sent:,}")
            print(f"   • Traffic Volume: {bytes_sent / (1024 * 1024):.2f} MB")
            print(f"   • Target Achievement: {achievement:.1f}%")
            print()

            if achievement >= 80:
                print("⚠️  Network Impact: 🔴 VERY HIGH")
                print("   ✓ Attack reached target rate")
                print("   ✓ Severe network stress detected")
                print("   ✓ Target service likely degraded or unavailable")
                print()
                print("🛡️  Security Recommendations:")
                print("   1️⃣  Enable Rate Limiting")
                print("   2️⃣  Implement SYN Cookies")
                print("   3️⃣  Deploy Firewall with DPI")
                print("   4️⃣  Setup IDS/IPS")
            elif achievement >= 50:
                print("⚡ Network Impact: 🟡 MODERATE")
                print("   • Attack partially successful")
                print("   • Service quality degraded")
                print()
                print("🛡️  Recommendations:")
                print("   1️⃣  Increase bandwidth capacity")
                print("   2️⃣  Tune detection thresholds")
            else:
                print("✅ Network Impact: 🟢 LOW")
                print("   • Network defenses effective")
                print("   • Service remained operational")

        elif attack_type in ['credential_forgery', 'unauthorized_access']:
            success_rate = metrics.get('success_rate_percent', 0)
            detected = metrics.get('detected', False)
            detection_score = metrics.get('detection_score', 0)
            total_attempts = metrics.get('total_attempts', 0)
            successful = metrics.get('successful_logins', 0) or metrics.get('successful_escalations', 0)

            print("🔐 Authentication Attack Analysis:")
            print(f"   • Total Attempts: {total_attempts:,}")
            print(f"   • Successful Attempts: {successful}")
            print(f"   • Success Rate: {success_rate:.4f}%")
            print(f"   • Detection Score: {detection_score:.0f}/100")
            print()

            if detected:
                print("🛡️  Security Status: ✅ ATTACK DETECTED")
                print("   ✓ Security systems identified the threat")
                print("   ✓ Defensive measures are working properly")
                print("   ✓ Recommend reviewing security logs")
            elif success_rate > 5:
                print("🚨 Security Status: 🔴 PARTIAL BREACH")
                print(f"   ⚠️  {success_rate:.2f}% of attempts succeeded")
                print()
                print("🆘 Urgent Actions Required:")
                print("   1️⃣  Review compromised accounts")
                print("   2️⃣  Force immediate password changes")
                print("   3️⃣  Enable MFA for all users")
                print("   4️⃣  Review access policies")
                print("   5️⃣  Complete system audit")
            else:
                print("✅ Security Status: 🟢 ALL ATTEMPTS BLOCKED")
                print("   • Authentication system is robust")
                print("   • MFA working effectively")

        elif attack_type == 'phishing':
            ctr = metrics.get('click_through_rate', 0)
            captured = metrics.get('credentials_captured', 0)
            detected = metrics.get('detected', False)
            attempts = metrics.get('phishing_attempts', 0)

            print("🎣 Phishing Campaign Analysis:")
            print(f"   • Phishing Attempts: {attempts:,}")
            print(f"   • Click-Through Rate: {ctr:.1f}%")
            print(f"   • Credentials Captured: {captured}")
            print()

            if captured > 10:
                print("🚨 Threat Level: 🔴 CRITICAL")
                print(f"   ⚠️  {captured} credentials compromised")
                print()
                print("🆘 Emergency Actions:")
                print("   1️⃣  Notify affected users immediately")
                print("   2️⃣  Temporarily disable accounts")
                print("   3️⃣  Force password changes")
                print("   4️⃣  Emergency security training")
                print("   5️⃣  Review logs for suspicious activity")
            elif captured > 0:
                print("⚠️  Threat Level: 🟡 MEDIUM")
                print(f"   • {captured} credential(s) at risk")
                print()
                print("📋 Recommendations:")
                print("   1️⃣  Targeted training for vulnerable users")
                print("   2️⃣  Enable 2FA")
                print("   3️⃣  Deploy advanced email filtering")
            elif detected:
                print("🛡️  Threat Level: 🟢 DETECTED & BLOCKED")
                print("   ✓ Phishing filter worked")
                print("   ✓ No credentials compromised")
            else:
                print("✅ Threat Level: 🟢 NO IMPACT")
                print("   • Users demonstrate good security awareness")

        elif attack_type == 'mitm':
            if success:
                print("🚨 Security Status: 🔴 CRITICAL - MITM SUCCESSFUL")
                print("   ⚠️  Network traffic intercepted")
                print("   ⚠️  ARP tables poisoned")
                print("   ⚠️  All communications compromised")
                print()
                print("🆘 Immediate Actions Required:")
                print("   1️⃣  Implement Dynamic ARP Inspection (DAI)")
                print("   2️⃣  Enable DHCP Snooping")
                print("   3️⃣  Configure Port Security")
                print("   4️⃣  Use HTTPS for all services")
                print("   5️⃣  Deploy VPN for sensitive communications")
                print("   6️⃣  Install IDS/IPS")
            else:
                print("✅ Security Status: 🟢 MITM PREVENTED")
                print("   • ARP spoofing blocked")
                print("   • Network defenses effective")

        elif attack_type == 'credential_theft':
            stolen = metrics.get('credentials_stolen', 0)
            weak = metrics.get('weak_hashes_crackable', 0)
            rows = metrics.get('rows_exfiltrated', 0)

            print("🕵️ Database Breach Analysis:")
            print(f"   • Records Exfiltrated: {rows}")
            print(f"   • Credentials Stolen: {stolen}")
            print(f"   • Weak Hashes: {weak}")
            print()

            if stolen > 0:
                print("🚨 Status: 🔴 DATABASE SECURITY BREACH")
                print(f"   ⚠️  {stolen} credentials stolen")
                if weak > 0:
                    print(f"   ⚠️  {weak} weak hashes crackable")
                print()
                print("🆘 Urgent Actions:")
                print("   1️⃣  Patch SQL injection vulnerability immediately")
                print("   2️⃣  Use Prepared Statements")
                print("   3️⃣  Deploy WAF")
                print("   4️⃣  Force password changes for all users")
                print("   5️⃣  Complete database audit")
                print("   6️⃣  Restrict database access")
            else:
                print("✅ Status: 🟢 DATABASE PROTECTED")
                print("   • SQL injection neutralized")

        elif attack_type == 'token_forgery':
            success_rate = metrics.get('success_rate_percent', 0)
            total = metrics.get('total_attempts', 0)
            successful = metrics.get('successful_hijacks', 0)

            print("🔑 Token Security Analysis:")
            print(f"   • Total Attempts: {total}")
            print(f"   • Successful Forgeries: {successful}")
            print(f"   • Success Rate: {success_rate:.2f}%")
            print()

            if success_rate > 10:
                print("🚨 Token Security: 🔴 CRITICAL - WEAK IMPLEMENTATION")
                print("   ⚠️  Token validation insufficient")
                print()
                print("🆘 Immediate Actions:")
                print("   1️⃣  Implement strong signature verification")
                print("   2️⃣  Use RS256 instead of HS256")
                print("   3️⃣  Add token expiration validation")
                print("   4️⃣  Implement token blacklisting")
            elif success_rate > 0:
                print("⚠️  Token Security: 🟡 SOME WEAKNESSES")
                print()
                print("📋 Recommendations:")
                print("   1️⃣  Review token validation logic")
                print("   2️⃣  Strengthen secret key")
            else:
                print("✅ Token Security: 🟢 STRONG")
                print("   • All forgery attempts detected")

        print("\n" + "=" * 70)
        print(" 📊 Security Summary ".center(70, "="))
        print("=" * 70)
        print()

        if success and metrics.get('detected', False):
            print("🎖️  Security Score: 🟢 EXCELLENT (Attack detected)")
        elif success and not metrics.get('detected', True):
            print("⚠️  Security Score: 🔴 WEAK (Attack successful, not detected)")
        elif not success:
            print("🛡️  Security Score: 🟢 GOOD (Attack neutralized)")

        print()
        print("📌 Note: Results saved to database")
        print("📌 For complete report use attack_analyzer.py")


def main():
    try:
        cli = CLIInterface()
        controller = MFAController()

        cli.print_header("🛡️ SDN MFA Security Testing System")
        print("🔬 Advanced Multi-Factor Authentication & Attack Simulation Platform")

        authenticated = False

        for attempt in range(1, MAX_AUTH_ATTEMPTS + 1):
            if attempt > 1:
                print(f"\n{'=' * 70}")
                print(f"🔄 Authentication Attempt {attempt}/{MAX_AUTH_ATTEMPTS}")
                print(f"{'=' * 70}")
            username, password, policy = cli.get_authentication_parameters()

            policy_map = {"1": "password_only", "2": "password_otp", "3": "password_biometric", "4": "password_otp_biometric"}
            mfa_mode = policy_map.get(policy, "password_only")

            success, error_code = controller.login(username, password, policy)

            if success:
                authenticated = True
                break

            if error_code == "database_error":
                print("\n⚠️  Database connection issue detected")
                print("🔄 System will retry automatically...")
                continue

            remaining = MAX_AUTH_ATTEMPTS - attempt
            if remaining > 0:
                print(f"\n⚠️  {remaining} attempt(s) remaining")
                print("💡 Please check your credentials and try again")
            else:
                print("\n❌ Maximum authentication attempts reached")

        if not authenticated:
            print("\n🚫 Access denied. Exiting program.")
            sys.exit(1)


        mn = _load_mininet_ctx()
        ok_status, _ = _ryu_request("/sdnmfa/status", "GET")
        if not ok_status:
            print("SDN controller is not reachable on 127.0.0.1:8080")
            sys.exit(1)
        if not mn:
            print("Mininet context file /tmp/sdnmfa_mininet.json not found")
            sys.exit(1)
        user_ip = mn.get("h1", {}).get("ip", "10.0.0.1")
        user_mac = str(mn.get("h1", {}).get("mac", "00:00:00:00:00:01")).lower()
        user_in_port = _get_in_port_from_fdb(user_mac)
        ttl_map = {"password_only": 60, "password_otp": 180, "password_biometric": 180, "password_otp_biometric": 300}
        ttl = int(ttl_map.get(mfa_mode, 60))
        ok_auth, _ = _ryu_request("/sdnmfa/authorize", "POST", {"src_ip": user_ip, "src_mac": user_mac, "mode": mfa_mode, "ttl": ttl, "in_port": user_in_port})
        if not ok_auth:
            print("Failed to authorize access in SDN controller")
            sys.exit(1)

        cli.display_available_attacks(controller)

        attack_type = cli.get_attack_choice(controller)

        host, port, duration, rate, threads, gateway = cli.get_attack_parameters(attack_type)

        cli.print_section("⚡ Attack Confirmation")
        print(f"Attack Type: {attack_type}")
        print(f"Target: {host}:{port}")
        if gateway:
            print(f"Gateway: {gateway}")
        print(f"Duration: {duration}s | Rate: {rate} PPS | Threads: {threads}")

        confirm = input("\n🚀 Start attack? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("ℹ️  Attack cancelled.")
            sys.exit(0)

        print("\n" + "=" * 70)
        print("⚡ Attack started... Press Ctrl+C to stop")
        print("=" * 70)

        try:
            result = controller.execute_attack(
                username=username,
                attack_type=attack_type,
                target_host=host,
                target_port=port,
                duration_s=duration,
                rate_pps=rate,
                threads=threads,
                mfa_mode=mfa_mode,
                gateway_ip=gateway
            )
        except KeyboardInterrupt:
            print("\n\nℹ️  Attack interrupted by user")
            sys.exit(0)

        cli.display_attack_results(result)

    except KeyboardInterrupt:
        print("\n\nℹ️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        logger.exception("Critical error in main")
        sys.exit(1)
    finally:
        try:
            mn = _load_mininet_ctx()
            user_ip = mn.get("h1", {}).get("ip") if isinstance(mn, dict) else None
            if user_ip:
                _ryu_request("/sdnmfa/revoke", "POST", {"src_ip": user_ip})
        except Exception:
            pass
        try:
            close_all_connections()
        except Exception:
            logger.exception("Failed to close database connections")


if __name__ == "__main__":
    main()
