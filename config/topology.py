"""Build one of the declared SDN-MFA Mininet topology profiles.

This program only creates isolated 10.0.0.0/24 Mininet networks. It never
accepts an external target. Runtime host PIDs and edge attachments are written
atomically for the controller-side campaign runner.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.util import quietRun

from config.experiment_protocol import (
    PROTECTED_HOST,
    PROTECTED_PORT,
    PROTECTED_RESOURCE_FILENAME,
    PROTECTED_RESOURCE_TEXT,
    CONTROL_PORT,
    CONTROL_RESOURCE_FILENAME,
    CONTROL_RESOURCE_TEXT,
    REFERENCE_LINK_CAPACITY_MBPS,
)
from config.topology_profiles import DEFAULT_TOPOLOGY, TOPOLOGY_PROFILES, topology_spec


LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "topology.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

MN_INFO_PATH = Path("/tmp/sdnmfa_mn.json")
SENSITIVE_DIR = "/tmp/sdnmfa_sensitive"
CONTROL_DIR = "/tmp/sdnmfa_control"
STP_CONVERGENCE_SECONDS = 35.0
CONNECTIVITY_ATTEMPTS = 3
CONNECTIVITY_PING_TIMEOUT_SECONDS = "1"


def _switch_dpid(switch: Any) -> int:
    raw_dpid = getattr(switch, "dpid", None)
    if raw_dpid is None:
        raise RuntimeError("Switch DPID is unavailable after startup")
    if isinstance(raw_dpid, int):
        return raw_dpid
    return int(str(raw_dpid), 16)


def _switch_runtime_options(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Return the common OpenFlow options for a declared OVS profile.

    Mininet only translates ``stp=True`` to ``stp_enable=true`` when its OVS
    switch uses standalone fail mode. This laboratory keeps secure fail mode
    so loss of the Ryu connection cannot silently enable normal switching;
    cyclic profiles therefore enable and verify STP explicitly after startup.
    """
    stp_enabled = bool(profile.get("stp"))
    return {
        "protocols": "OpenFlow13",
        "stp": stp_enabled,
        "failMode": "secure",
    }


def _enable_profile_stp(
    profile: Dict[str, Any], switches: Dict[str, Any]
) -> None:
    """Enable and verify OVS STP without weakening controller fail mode."""
    if not profile.get("stp"):
        return
    for name, switch in switches.items():
        bridge = shlex.quote(str(name))
        switch.cmd("ovs-vsctl set Bridge %s stp_enable=true" % bridge)
        observed = switch.cmd(
            "ovs-vsctl get Bridge %s stp_enable" % bridge
        ).strip().lower()
        if observed != "true":
            raise RuntimeError(
                "Could not enable STP on %s (observed %r)" % (name, observed)
            )


def _host_context(host: Any, switch: Any, role: Optional[str] = None) -> Dict[str, Any]:
    """Build the authoritative host attachment record used by experiments."""
    connections = host.connectionsTo(switch)
    if len(connections) != 1:
        raise RuntimeError(
            "Expected one link between %s and %s, found %s"
            % (host.name, switch.name, len(connections))
        )
    host_intf, switch_intf = connections[0]
    in_port = switch.ports.get(switch_intf)
    if in_port is None:
        raise RuntimeError("Could not resolve %s edge port on %s" % (host.name, switch.name))
    return {
        "pid": int(host.pid),
        "ip": str(host.IP()),
        "mac": str(host.MAC()).lower(),
        "interface": str(host_intf.name),
        "switch": str(switch.name),
        "switch_dpid": int(_switch_dpid(switch)),
        "in_port": int(in_port),
        "role": role,
    }


def _write_mn_info(
    topology_id: str,
    profile: Dict[str, Any],
    hosts: Dict[str, Any],
    switches: Dict[str, Any],
    initial_ping_loss_percent: Optional[float] = None,
) -> Dict[str, Any]:
    host_specs = {row["name"]: row for row in profile["hosts"]}
    host_contexts: Dict[str, Any] = {}
    role_index: Dict[str, list] = {}
    for name, host in hosts.items():
        row = host_specs[name]
        context = _host_context(host, switches[row["switch"]], role=row["role"])
        host_contexts[name] = context
        role_index.setdefault(str(row["role"]), []).append(name)

    data: Dict[str, Any] = {
        "schema_version": 3,
        "topology_id": topology_id,
        "topology_label": profile["label"],
        "generated_at_epoch": time.time(),
        "reference_link_capacity_mbps": REFERENCE_LINK_CAPACITY_MBPS,
        "hosts": host_contexts,
        "roles": role_index,
        "switches": {
            name: {"dpid": _switch_dpid(switch)} for name, switch in switches.items()
        },
        "switch_count": len(switches),
        "switch_link_count": len(profile["switch_links"]),
        # An STP-protected mesh intentionally blocks redundant links. Ryu only
        # needs to discover the active spanning-tree links used for transit.
        "expected_active_switch_link_count": (
            min(len(profile["switch_links"]), max(0, len(switches) - 1))
            if profile["stp"]
            else len(profile["switch_links"])
        ),
        "host_count": len(hosts),
        "sensitive": {
            "host": PROTECTED_HOST,
            "port": PROTECTED_PORT,
            "path": "http://%s:%s/%s"
            % (PROTECTED_HOST, PROTECTED_PORT, PROTECTED_RESOURCE_FILENAME),
        },
        "network_control": {
            "host": PROTECTED_HOST,
            "port": CONTROL_PORT,
            "path": "http://%s:%s/%s"
            % (PROTECTED_HOST, CONTROL_PORT, CONTROL_RESOURCE_FILENAME),
            "expected_text": CONTROL_RESOURCE_TEXT,
        },
    }
    # Flat aliases provide direct h1..hN lookup while the roles map supports
    # topology-independent source selection.
    data.update(host_contexts)
    if initial_ping_loss_percent is not None:
        data["initial_ping_loss_percent"] = float(initial_ping_loss_percent)
    temporary = MN_INFO_PATH.with_name("%s.%s.tmp" % (MN_INFO_PATH.name, os.getpid()))
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(MN_INFO_PATH)
    return data


def _start_sensitive_service(host: Any) -> None:
    host.cmd("mkdir -p %s" % shlex.quote(SENSITIVE_DIR))
    resource_path = "%s/%s" % (SENSITIVE_DIR, PROTECTED_RESOURCE_FILENAME)
    host.cmd(
        "python3 -c %s"
        % shlex.quote(
            "from pathlib import Path; Path(%r).write_text(%r, encoding='utf-8')"
            % (resource_path, PROTECTED_RESOURCE_TEXT + "\n")
        )
    )
    host.cmd(
        "cd %s && nohup python3 -m http.server %s >/tmp/sdnmfa_http.log 2>&1 &"
        % (shlex.quote(SENSITIVE_DIR), PROTECTED_PORT)
    )
    host.cmd("mkdir -p %s" % shlex.quote(CONTROL_DIR))
    control_path = "%s/%s" % (CONTROL_DIR, CONTROL_RESOURCE_FILENAME)
    host.cmd(
        "python3 -c %s"
        % shlex.quote(
            "from pathlib import Path; Path(%r).write_text(%r, encoding='utf-8')"
            % (control_path, CONTROL_RESOURCE_TEXT + "\n")
        )
    )
    host.cmd(
        "cd %s && nohup python3 -m http.server %s >/tmp/sdnmfa_control_http.log 2>&1 &"
        % (shlex.quote(CONTROL_DIR), CONTROL_PORT)
    )


def create_topology(
    topology_id: str = DEFAULT_TOPOLOGY,
    *,
    controller_ip: str = "127.0.0.1",
    controller_port: int = 6633,
    open_cli: bool = True,
) -> Mininet:
    profile = topology_spec(topology_id)
    try:
        MN_INFO_PATH.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError("Could not clear stale Mininet context: %s" % exc)
    setLogLevel("info")
    network = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
        build=False,
    )
    controller = network.addController(
        "c0", controller=RemoteController, ip=controller_ip, port=int(controller_port)
    )

    switches: Dict[str, Any] = {}
    switch_options = _switch_runtime_options(profile)
    for index, name in enumerate(profile["switches"], start=1):
        switches[name] = network.addSwitch(
            name,
            dpid="%016x" % index,
            **switch_options,
        )

    hosts: Dict[str, Any] = {}
    for row in profile["hosts"]:
        hosts[row["name"]] = network.addHost(row["name"], ip=row["ip"])
        network.addLink(
            hosts[row["name"]],
            switches[row["switch"]],
            cls=TCLink,
            bw=REFERENCE_LINK_CAPACITY_MBPS,
            delay="2ms",
            max_queue_size=1000,
            use_htb=True,
        )

    for left, right in profile["switch_links"]:
        network.addLink(
            switches[left],
            switches[right],
            cls=TCLink,
            bw=REFERENCE_LINK_CAPACITY_MBPS,
            delay="1ms",
            max_queue_size=1000,
            use_htb=True,
        )

    log.info("Starting topology %s (%s)", topology_id, profile["label"])
    network.build()
    controller.start()
    for switch in switches.values():
        switch.start([controller])
    if profile["stp"]:
        _enable_profile_stp(profile, switches)
        log.info(
            "STP is enabled; waiting %.0f seconds for spanning-tree convergence",
            STP_CONVERGENCE_SECONDS,
        )
        time.sleep(STP_CONVERGENCE_SECONDS)

    service_hosts = [row["name"] for row in profile["hosts"] if row["role"] == "protected_service"]
    _start_sensitive_service(hosts[service_hosts[0]])
    time.sleep(0.75)
    ping_loss = 100.0
    convergence_attempts = CONNECTIVITY_ATTEMPTS if profile["stp"] else 1
    for attempt in range(1, convergence_attempts + 1):
        ping_loss = float(
            network.pingAll(timeout=CONNECTIVITY_PING_TIMEOUT_SECONDS)
        )
        if ping_loss <= 0.0:
            break
        if attempt < convergence_attempts:
            log.info(
                "Connectivity loss is %.2f%%; waiting for STP (%s/%s)",
                ping_loss,
                attempt,
                convergence_attempts,
            )
            time.sleep(5.0)
    if ping_loss > 0.0:
        raise RuntimeError(
            "Topology readiness failed after %s attempt(s): pingAll loss is %.2f%%. "
            "The Mininet context was not published; do not start a campaign."
            % (convergence_attempts, ping_loss)
        )
    _write_mn_info(
        topology_id,
        profile,
        hosts,
        switches,
        initial_ping_loss_percent=ping_loss,
    )
    log.info("Context written to %s", MN_INFO_PATH)
    if open_cli:
        CLI(network)
    return network


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start an isolated SDN-MFA Mininet profile")
    parser.add_argument("--topology", choices=sorted(TOPOLOGY_PROFILES), default=DEFAULT_TOPOLOGY)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6633)
    parser.add_argument("--no-cli", action="store_true", help="Start without the interactive Mininet CLI")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    network: Optional[Mininet] = None
    try:
        network = create_topology(
            args.topology,
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            open_cli=not args.no_cli,
        )
    except KeyboardInterrupt:
        log.info("Topology interrupted")
    except Exception:
        log.exception("Topology startup failed")
        raise
    finally:
        if network is not None:
            network.stop()
        quietRun("mn -c")
        try:
            MN_INFO_PATH.unlink(missing_ok=True)
        except Exception:
            log.warning("Could not remove %s", MN_INFO_PATH)


if __name__ == "__main__":
    main()
