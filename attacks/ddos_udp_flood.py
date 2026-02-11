import os
import sys

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
try:
    from SDNMFA.attacks.base_attack import BaseAttack, AttackConfig, AttackResult
except ImportError:
    from attacks.base_attack import BaseAttack, AttackConfig, AttackResult

class DDoSUdpFlood(BaseAttack):
    def __init__(self, cfg: AttackConfig):
        super().__init__(cfg)
        self.cfg.attack_type = "ddos_udp_flood"

    def run(self) -> AttackResult:
        self.cfg.attack_type = "ddos_udp_flood"
        return super().run()
