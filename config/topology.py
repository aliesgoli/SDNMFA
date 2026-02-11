import os
import json
import time
import logging
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import quietRun

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'topology.log')),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

MN_INFO_PATH = "/tmp/sdnmfa_mn.json"
SENSITIVE_DIR = "/tmp/sdnmfa_sensitive"
SENSITIVE_FILE = "sensitive.txt"
SENSITIVE_PORT = 18080

def _write_mn_info(h1, h2, h3, h4):
    data = {
        "h1": {"pid": int(h1.pid), "ip": str(h1.IP()), "mac": str(h1.MAC()).lower()},
        "h2": {"pid": int(h2.pid), "ip": str(h2.IP()), "mac": str(h2.MAC()).lower()},
        "h3": {"pid": int(h3.pid), "ip": str(h3.IP()), "mac": str(h3.MAC()).lower()},
        "h4": {"pid": int(h4.pid), "ip": str(h4.IP()), "mac": str(h4.MAC()).lower()},
        "sensitive": {"host": "10.0.0.2", "port": SENSITIVE_PORT, "path": f"http://10.0.0.2:{SENSITIVE_PORT}/{SENSITIVE_FILE}"}
    }
    with open(MN_INFO_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f)

def _start_sensitive_service(h2):
    h2.cmd(f"mkdir -p {SENSITIVE_DIR}")
    h2.cmd(f"bash -lc 'printf \"%s\n\" \"This is a sensitive resource.\" > {SENSITIVE_DIR}/{SENSITIVE_FILE}'")
    h2.cmd(f"bash -lc 'cd {SENSITIVE_DIR} && nohup python3 -m http.server {SENSITIVE_PORT} >/dev/null 2>&1 &'")

def create_custom_topology():
    setLogLevel('info')
    network_instance = None

    log.info("Creating Mininet instance")
    network_instance = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    log.info("Adding remote controller")
    controller = network_instance.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    log.info("Adding switches")
    switch1 = network_instance.addSwitch('s1')
    switch2 = network_instance.addSwitch('s2')

    log.info("Adding hosts")
    host1 = network_instance.addHost('h1', ip='10.0.0.1/24')
    host2 = network_instance.addHost('h2', ip='10.0.0.2/24')
    host3 = network_instance.addHost('h3', ip='10.0.0.3/24')
    host4 = network_instance.addHost('h4', ip='10.0.0.4/24')

    log.info("Creating links")
    network_instance.addLink(host1, switch1, cls=TCLink, bw=10, delay='5ms')
    network_instance.addLink(host2, switch2, cls=TCLink, bw=10, delay='5ms')
    network_instance.addLink(host3, switch1, cls=TCLink, bw=10, delay='2ms')
    network_instance.addLink(host4, switch2, cls=TCLink, bw=10, delay='2ms')
    network_instance.addLink(switch1, switch2, cls=TCLink, bw=20, delay='1ms')

    log.info("Starting network")
    network_instance.build()
    controller.start()
    switch1.start([controller])
    switch2.start([controller])

    _start_sensitive_service(host2)
    time.sleep(0.5)
    _write_mn_info(host1, host2, host3, host4)

    log.info("Testing connectivity with pingAll")
    network_instance.pingAll()

    log.info("Network is up. Launching CLI")
    CLI(network_instance)

    return network_instance

def main():
    network = None
    try:
        network = create_custom_topology()
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
    except Exception as error_msg:
        log.error("Unexpected error: %s", error_msg, exc_info=True)
    finally:
        if network:
            log.info("Stopping network")
            network.stop()
        quietRun('mn -c')
        try:
            if os.path.exists(MN_INFO_PATH):
                os.remove(MN_INFO_PATH)
        except Exception:
            pass
        log.info("Mininet cleanup done")

if __name__ == '__main__':
    main()
