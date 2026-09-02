"""Declarative Mininet topology profiles used by the experiment protocol."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


def _hosts(count: int, attachments: Dict[str, str]) -> List[Dict[str, Any]]:
    roles = {
        "h1": "authorized_user",
        "h2": "protected_service",
        "h3": "attack_source",
        "h4": "attack_source",
        "h5": "attack_source",
    }
    rows: List[Dict[str, Any]] = []
    for number in range(1, count + 1):
        name = "h%s" % number
        rows.append(
            {
                "name": name,
                "ip": "10.0.0.%s/24" % number,
                "role": roles.get(name, "background_client"),
                "switch": attachments[name],
            }
        )
    return rows


TOPOLOGY_PROFILES: Dict[str, Dict[str, Any]] = {
    "star-small": {
        "label": "Small star",
        "stp": False,
        "switches": ["s1"],
        "switch_links": [],
        "hosts": _hosts(6, {"h%s" % n: "s1" for n in range(1, 7)}),
    },
    "star-medium": {
        "label": "Medium star",
        "stp": False,
        "switches": ["s1"],
        "switch_links": [],
        "hosts": _hosts(10, {"h%s" % n: "s1" for n in range(1, 11)}),
    },
    "tree-medium": {
        "label": "Medium tree",
        "stp": False,
        "switches": ["s1", "s2", "s3"],
        "switch_links": [("s1", "s2"), ("s1", "s3")],
        "hosts": _hosts(
            10,
            {
                "h1": "s2", "h2": "s3", "h3": "s2", "h4": "s3", "h5": "s2",
                "h6": "s3", "h7": "s2", "h8": "s3", "h9": "s2", "h10": "s3",
            },
        ),
    },
    "partial-mesh-medium": {
        "label": "Medium partial mesh",
        "stp": True,
        "switches": ["s1", "s2", "s3", "s4"],
        "switch_links": [("s1", "s2"), ("s1", "s3"), ("s2", "s4"), ("s3", "s4")],
        "hosts": _hosts(
            10,
            {
                "h1": "s1", "h2": "s4", "h3": "s2", "h4": "s3", "h5": "s4",
                "h6": "s1", "h7": "s2", "h8": "s3", "h9": "s4", "h10": "s1",
            },
        ),
    },
}

DEFAULT_TOPOLOGY = "tree-medium"


def topology_spec(name: str) -> Dict[str, Any]:
    """Return a defensive copy of a validated topology specification."""
    if name not in TOPOLOGY_PROFILES:
        raise KeyError("Unknown topology profile: %s" % name)
    spec = deepcopy(TOPOLOGY_PROFILES[name])
    errors = topology_errors(spec)
    if errors:
        raise ValueError("Invalid topology profile %s: %s" % (name, ", ".join(errors)))
    return spec


def topology_errors(spec: Dict[str, Any]) -> List[str]:
    """Check the role and connectivity contract without importing Mininet."""
    errors: List[str] = []
    switches = list(spec.get("switches") or [])
    hosts = list(spec.get("hosts") or [])
    names = [row.get("name") for row in hosts]
    roles = [row.get("role") for row in hosts]
    if len(switches) != len(set(switches)) or not switches:
        errors.append("invalid_switch_names")
    if len(names) != len(set(names)) or len(hosts) < 6:
        errors.append("invalid_host_names_or_count")
    if roles.count("authorized_user") != 1:
        errors.append("authorized_user_count")
    if roles.count("protected_service") != 1:
        errors.append("protected_service_count")
    if roles.count("attack_source") < 3:
        errors.append("insufficient_attack_sources")
    if any(row.get("switch") not in switches for row in hosts):
        errors.append("unknown_host_attachment")
    for link in spec.get("switch_links") or []:
        if len(link) != 2 or link[0] not in switches or link[1] not in switches or link[0] == link[1]:
            errors.append("invalid_switch_link")
            break
    return errors


def topology_summary_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name, raw in TOPOLOGY_PROFILES.items():
        roles = [host["role"] for host in raw["hosts"]]
        rows.append(
            {
                "topology_id": name,
                "label": raw["label"],
                "switch_count": len(raw["switches"]),
                "host_count": len(raw["hosts"]),
                "attack_source_count": roles.count("attack_source"),
                "stp": bool(raw["stp"]),
            }
        )
    return rows
