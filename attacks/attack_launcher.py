import os
import sys
import argparse
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

if project_root not in sys.path:
    sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.attack_manager import AttackManager
    from SDNMFA.attacks.base_attack import AttackConfig
except ImportError:
    from attacks.attack_manager import AttackManager
    from attacks.base_attack import AttackConfig
def parse():
    p = argparse.ArgumentParser(description="Launch an attack using AttackManager (run inside Mininet host)")
    p.add_argument("--type", required=True, choices=[
        "credential_forgery", "credential_theft", "phishing", "token_forgery",
        "unauthorized_access", "dos_udp_flood", "ddos_udp_flood", "mitm"
    ])
    p.add_argument("--target", required=True, help="Target host IP (e.g., 10.0.0.2)")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--duration", type=int, default=10)
    p.add_argument("--rate", type=int, default=5000)
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--username", default="attacker_demo")
    return p.parse_args()

def main():
    args = parse()
    cfg = AttackConfig(
        username=args.username,
        target_host=args.target,
        target_port=args.port,
        duration_s=args.duration,
        rate_pps=args.rate,
        threads=args.threads,
        attack_type=args.type
    )
    mgr = AttackManager()
    print("Starting attack:", args.type, "->", args.target)
    res = mgr.run_attack(cfg)
    print("Attack finished:", res.success, res.message)
    print("Metrics:", res.metrics)

if __name__ == "__main__":
    main()

