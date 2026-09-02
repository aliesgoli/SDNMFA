import importlib.util
import sys
import types
import unittest
from pathlib import Path

from config.topology_profiles import TOPOLOGY_PROFILES, topology_errors, topology_spec


def install_mininet_stubs():
    for name in (
        "mininet",
        "mininet.net",
        "mininet.node",
        "mininet.link",
        "mininet.cli",
        "mininet.log",
        "mininet.util",
    ):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["mininet.net"].Mininet = type("Mininet", (), {})
    sys.modules["mininet.node"].RemoteController = type("RemoteController", (), {})
    sys.modules["mininet.node"].OVSSwitch = type("OVSSwitch", (), {})
    sys.modules["mininet.link"].TCLink = type("TCLink", (), {})
    sys.modules["mininet.cli"].CLI = lambda *args, **kwargs: None
    sys.modules["mininet.log"].setLogLevel = lambda *args, **kwargs: None
    sys.modules["mininet.util"].quietRun = lambda *args, **kwargs: ""


install_mininet_stubs()
TOPOLOGY_PATH = Path(__file__).resolve().parents[1] / "config" / "topology.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_topology_test", TOPOLOGY_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Intf:
    def __init__(self, name):
        self.name = name


class Host:
    name = "h1"
    pid = 123

    def __init__(self, host_intf, switch_intf):
        self.connection = (host_intf, switch_intf)

    def connectionsTo(self, switch):
        return [self.connection]

    def IP(self):
        return "10.0.0.1"

    def MAC(self):
        return "00:00:00:00:00:01"


class Switch:
    name = "s1"
    dpid = "0000000000000001"

    def __init__(self, intf):
        self.ports = {intf: 7}


class OVSCommandSwitch:
    def __init__(self):
        self.commands = []

    def cmd(self, command):
        self.commands.append(command)
        return "true\n" if " get Bridge " in command else ""


class TopologyContextTests(unittest.TestCase):
    def test_host_attachment_is_taken_from_mininet_link(self):
        host_intf = Intf("h1-eth0")
        switch_intf = Intf("s1-eth7")
        context = MODULE._host_context(Host(host_intf, switch_intf), Switch(switch_intf))
        self.assertEqual(context["switch_dpid"], 1)
        self.assertEqual(context["in_port"], 7)
        self.assertEqual(context["interface"], "h1-eth0")

    def test_four_declared_profiles_cover_small_medium_star_tree_and_mesh(self):
        self.assertEqual(len(TOPOLOGY_PROFILES), 4)
        self.assertIn("star-small", TOPOLOGY_PROFILES)
        self.assertIn("star-medium", TOPOLOGY_PROFILES)
        self.assertIn("tree-medium", TOPOLOGY_PROFILES)
        self.assertIn("partial-mesh-medium", TOPOLOGY_PROFILES)
        self.assertLess(
            len(TOPOLOGY_PROFILES["star-small"]["hosts"]),
            len(TOPOLOGY_PROFILES["star-medium"]["hosts"]),
        )
        self.assertTrue(TOPOLOGY_PROFILES["partial-mesh-medium"]["stp"])

    def test_cyclic_profile_keeps_secure_fail_mode_and_enables_stp(self):
        mesh_options = MODULE._switch_runtime_options(
            topology_spec("partial-mesh-medium")
        )
        self.assertTrue(mesh_options["stp"])
        self.assertEqual(mesh_options["failMode"], "secure")
        self.assertEqual(mesh_options["protocols"], "OpenFlow13")

        switch = OVSCommandSwitch()
        MODULE._enable_profile_stp(
            topology_spec("partial-mesh-medium"), {"s1": switch}
        )
        self.assertEqual(
            switch.commands,
            [
                "ovs-vsctl set Bridge s1 stp_enable=true",
                "ovs-vsctl get Bridge s1 stp_enable",
            ],
        )

        tree_options = MODULE._switch_runtime_options(topology_spec("tree-medium"))
        self.assertFalse(tree_options["stp"])
        self.assertEqual(tree_options["failMode"], "secure")

    def test_every_profile_has_three_distinct_attack_hosts_and_valid_roles(self):
        for name in TOPOLOGY_PROFILES:
            spec = topology_spec(name)
            self.assertEqual(topology_errors(spec), [])
            attackers = [row["name"] for row in spec["hosts"] if row["role"] == "attack_source"]
            self.assertEqual(len(attackers), 3)
            self.assertEqual(len(attackers), len(set(attackers)))
            ips = [row["ip"] for row in spec["hosts"]]
            self.assertEqual(len(ips), len(set(ips)))

    def test_profile_copy_is_defensive(self):
        spec = topology_spec("star-small")
        spec["hosts"][0]["role"] = "changed"
        self.assertEqual(
            TOPOLOGY_PROFILES["star-small"]["hosts"][0]["role"],
            "authorized_user",
        )


if __name__ == "__main__":
    unittest.main()
