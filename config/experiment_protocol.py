"""Versioned, implementation-led experiment protocol for the SDN-MFA lab.

The protocol deliberately separates two independent variables:

* ``POLICY_SPECS`` describes authentication factors only.
* ``BINDING_SPECS`` describes SDN data-plane authorization constraints only.

Keeping them separate prevents a stronger network binding from being mistaken
for an effect of adding an authentication factor. Traffic values are sampled
from declared low, medium, and high ranges by :mod:`experiments.campaign` and
the seed and sampled values are persisted in the campaign manifest.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


PROTOCOL_ID = "sdnmfa-exp-v2-final"
PROTOCOL_SCHEMA_VERSION = 4
IMPLEMENTATION_REVISION = "sdnmfa-thesis-v2"

PROTECTED_HOST = "10.0.0.2"
PROTECTED_PORT = 18080
PROTECTED_RESOURCE_FILENAME = "sensitive.txt"
PROTECTED_RESOURCE_TEXT = "This is a sensitive resource."
CONTROL_PORT = 18081
CONTROL_RESOURCE_FILENAME = "health.txt"
CONTROL_RESOURCE_TEXT = "SDNMFA_CONTROL_OK"
AUTHORIZED_SOURCE_IP = "10.0.0.1"

# The same authorization window is used for every MFA policy. It is long
# enough for one scenario plus controls, but is not presented as a security
# property of an authentication factor.
AUTHORIZATION_TTL_SECONDS = 180
DEFAULT_BINDING_PROFILE = "ip_mac_port"
REFERENCE_LINK_CAPACITY_MBPS = 10.0
DEFAULT_REPETITIONS = 5
CONTROL_PROBE_COUNT = 5
MIN_CONTROL_AVAILABILITY = 0.80
AVAILABILITY_DEGRADATION_MARGIN = 0.10
MIN_RATE_ACHIEVEMENT_PERCENT = 75.0
MAX_RATE_ACHIEVEMENT_PERCENT = 125.0

POLICY_ORDER = [
    "password_only",
    "password_otp",
    "password_biometric",
    "password_otp_biometric",
]

POLICY_SPECS: Dict[str, Dict[str, Any]] = {
    "password_only": {
        "label": "Password only",
        "factors": "Password",
        "factor_keys": ("password",),
    },
    "password_otp": {
        "label": "Password + OTP",
        "factors": "Password + software-simulated OTP",
        "factor_keys": ("password", "otp"),
    },
    "password_biometric": {
        "label": "Password + biometric",
        "factors": "Password + software-simulated biometric sample",
        "factor_keys": ("password", "biometric"),
    },
    "password_otp_biometric": {
        "label": "Full MFA",
        "factors": "Password + software-simulated OTP + software-simulated biometric sample",
        "factor_keys": ("password", "otp", "biometric"),
    },
}

POLICY_SELECTION = {
    "1": "password_only",
    "2": "password_otp",
    "3": "password_biometric",
    "4": "password_otp_biometric",
}

BINDING_ORDER = ["ip_only", "ip_mac", "ip_port", "ip_mac_port"]
BINDING_SPECS: Dict[str, Dict[str, Any]] = {
    "ip_only": {
        "label": "IP address",
        "need_mac": False,
        "need_port": False,
    },
    "ip_mac": {
        "label": "IP + MAC address",
        "need_mac": True,
        "need_port": False,
    },
    "ip_port": {
        "label": "IP + ingress attachment",
        "need_mac": False,
        "need_port": True,
    },
    "ip_mac_port": {
        "label": "IP + MAC + ingress attachment",
        "need_mac": True,
        "need_port": True,
    },
}

# Network-control fields are derived from the common binding so authentication
# policy comparisons remain unconfounded.
for _policy_spec in POLICY_SPECS.values():
    _policy_spec["network_binding"] = BINDING_SPECS[DEFAULT_BINDING_PROFILE]["label"]
    _policy_spec["ttl_seconds"] = AUTHORIZATION_TTL_SECONDS
    _policy_spec["need_mac"] = BINDING_SPECS[DEFAULT_BINDING_PROFILE]["need_mac"]
    _policy_spec["need_port"] = BINDING_SPECS[DEFAULT_BINDING_PROFILE]["need_port"]

INTENSITY_ORDER = ["low", "medium", "high"]

# For access attempts, rate_pps denotes protected-resource requests per
# second. For UDP scenarios it denotes aggregate offered packet rate across
# all declared sources. Ranges are inclusive.
ACCESS_INTENSITY_RANGES: Dict[str, Dict[str, Any]] = {
    "low": {
        "duration_seconds": (4, 6),
        "rate_pps": (1, 2),
        "request_count": (4, 8),
    },
    "medium": {
        "duration_seconds": (7, 10),
        "rate_pps": (2, 4),
        "request_count": (12, 24),
    },
    "high": {
        "duration_seconds": (11, 15),
        "rate_pps": (4, 7),
        "request_count": (30, 60),
    },
}

# UDP load is expressed relative to the bottleneck link capacity. The packet
# rate is calculated after sampling the payload, so high remains a high load
# even when the payload changes.
FLOOD_INTENSITY_RANGES: Dict[str, Dict[str, Any]] = {
    "low": {
        "duration_seconds": (6, 8),
        "payload_size_bytes": (256, 512),
        "offered_load_ratio": (0.15, 0.30),
    },
    "medium": {
        "duration_seconds": (9, 12),
        "payload_size_bytes": (512, 768),
        "offered_load_ratio": (0.55, 0.80),
    },
    "high": {
        "duration_seconds": (13, 16),
        "payload_size_bytes": (768, 1200),
        "offered_load_ratio": (1.10, 1.50),
    },
}

MECHANISM_ORDER = ["direct_access", "ip_spoof", "ip_mac_spoof", "arp_mitm"]
MECHANISM_LABELS = {
    "direct_access": "Direct unauthorized access",
    "ip_spoof": "Source-IP spoofing",
    "ip_mac_spoof": "Source-IP and MAC spoofing",
    "arp_mitm": "ARP cache-poisoning / man-in-the-middle attempt",
    "udp_flood_single_source": "Single-source UDP flood",
    "udp_flood_multi_source": "Multi-source UDP flood",
}
AVAILABILITY_MECHANISM_ORDER = [
    "udp_flood_single_source",
    "udp_flood_multi_source",
]
AVAILABILITY_MECHANISMS = set(AVAILABILITY_MECHANISM_ORDER)

DISPLAY_SCENARIO_ORDER = [
    "unauthorized_access",
    "ip_spoofing",
    "ip_mac_spoofing",
    "arp_mitm",
    "dos_udp_flood",
    "ddos_udp_flood",
]

# Thesis-level design dimensions. Authentication policy and network binding
# are crossed instead of treating IP/MAC/port as MFA factors. With the default
# repetitions this produces 1,440 network runs (288 unique cells) per topology.
NETWORK_DESIGN_CELL_COUNT_PER_TOPOLOGY = (
    len(POLICY_ORDER)
    * len(BINDING_ORDER)
    * len(DISPLAY_SCENARIO_ORDER)
    * len(INTENSITY_ORDER)
)
NETWORK_RUN_COUNT_PER_TOPOLOGY = (
    NETWORK_DESIGN_CELL_COUNT_PER_TOPOLOGY * DEFAULT_REPETITIONS
)

SCENARIO_SPECS: Dict[str, Dict[str, Any]] = {
    "unauthorized_access": {
        "display_name": "Direct unauthorized access",
        "display_description": "Repeated HTTP requests from an unauthorized Mininet host",
        "mechanism": "direct_access",
        "analysis_group": "Access control",
        "parameter_family": "access",
        "source_count": 1,
    },
    "ip_spoofing": {
        "display_name": "Source-IP spoofing",
        "display_description": "The attack host assumes the authorized IPv4 address while retaining its own MAC address",
        "mechanism": "ip_spoof",
        "analysis_group": "Access control",
        "parameter_family": "access",
        "source_count": 1,
    },
    "ip_mac_spoofing": {
        "display_name": "Source-IP and MAC spoofing",
        "display_description": "The attack host assumes both authorized IP and MAC identities from another edge port",
        "mechanism": "ip_mac_spoof",
        "analysis_group": "Access control",
        "parameter_family": "access",
        "source_count": 1,
    },
    "arp_mitm": {
        "display_name": "ARP cache-poisoning / MITM attempt",
        "display_description": "Bidirectional forged ARP replies and IP forwarding inside the isolated Mininet network",
        "mechanism": "arp_mitm",
        "analysis_group": "Access control",
        "parameter_family": "access",
        "source_count": 1,
    },
    "dos_udp_flood": {
        "display_name": "Single-source UDP flood",
        "display_description": "Calibrated aggregate UDP load from one isolated Mininet source",
        "mechanism": "udp_flood_single_source",
        "analysis_group": "Availability",
        "parameter_family": "flood",
        "source_count": 1,
    },
    "ddos_udp_flood": {
        "display_name": "Multi-source UDP flood",
        "display_description": "Calibrated aggregate UDP load from three distinct Mininet hosts",
        "mechanism": "udp_flood_multi_source",
        "analysis_group": "Availability",
        "parameter_family": "flood",
        "source_count": 3,
    },
}

# Authentication-factor availability is evaluated separately from network
# traffic. These labels state exactly what is supplied to the real MFA
# verification code; none is described as a real-world credential-capture deployment.
AUTH_SCENARIO_ORDER = [
    "valid_factors",
    "password_compromised",
    "password_and_otp_compromised",
    "password_and_biometric_compromised",
    "all_factors_compromised",
]
AUTH_SCENARIO_SPECS: Dict[str, Dict[str, Any]] = {
    "valid_factors": {
        "label": "Legitimate factors",
        "available_factors": ("password", "otp", "biometric"),
        "control": "negative_attack_control",
    },
    "password_compromised": {
        "label": "Available factors: password only",
        "available_factors": ("password",),
        "control": "factor_compromise",
    },
    "password_and_otp_compromised": {
        "label": "Available factors: password and OTP",
        "available_factors": ("password", "otp"),
        "control": "factor_compromise",
    },
    "password_and_biometric_compromised": {
        "label": "Available factors: password and simulated biometric sample",
        "available_factors": ("password", "biometric"),
        "control": "factor_compromise",
    },
    "all_factors_compromised": {
        "label": "Available factors: all implemented factors",
        "available_factors": ("password", "otp", "biometric"),
        "control": "positive_attack_control",
    },
}


def scenario_spec(attack_type: str) -> Dict[str, Any]:
    """Return a defensive copy of a declared network scenario."""
    if attack_type not in SCENARIO_SPECS:
        raise KeyError("Unknown scenario: %s" % attack_type)
    return dict(SCENARIO_SPECS[attack_type])


def intensity_ranges(attack_type: str, intensity_level: str) -> Dict[str, Any]:
    """Return declared ranges for a scenario and intensity level."""
    spec = SCENARIO_SPECS.get(attack_type)
    if spec is None:
        raise KeyError("Unknown scenario: %s" % attack_type)
    if intensity_level not in INTENSITY_ORDER:
        raise KeyError("Unknown intensity: %s" % intensity_level)
    family = str(spec["parameter_family"])
    source = ACCESS_INTENSITY_RANGES if family == "access" else FLOOD_INTENSITY_RANGES
    return dict(source[intensity_level])


def offered_load_ratio(rate_pps: int, payload_size_bytes: int) -> float:
    """Estimate layer-3 offered load relative to the reference bottleneck.

    The calculation adds 28 bytes for IPv4 and UDP headers. Ethernet framing
    overhead is excluded and this definition is stored with each manifest.
    """
    bits_per_packet = (int(payload_size_bytes) + 28) * 8
    return (int(rate_pps) * bits_per_packet) / (REFERENCE_LINK_CAPACITY_MBPS * 1_000_000.0)


def _in_range(value: Any, bounds: Iterable[Any]) -> bool:
    try:
        lower, upper = list(bounds)
        numeric = float(value)
        return float(lower) <= numeric <= float(upper)
    except (TypeError, ValueError):
        return False


def protocol_parameter_errors(
    attack_type: str,
    *,
    duration_seconds: Any,
    rate_pps: Any,
    worker_count: Any,
    payload_size_bytes: Any,
    target_host: Any,
    target_port: Any,
    intensity_level: Optional[str] = None,
    request_count: Any = None,
    source_count: Any = None,
) -> List[str]:
    """Validate sampled runtime values against the versioned protocol."""
    spec = SCENARIO_SPECS.get(attack_type)
    if spec is None:
        return ["unknown_scenario"]
    if intensity_level not in INTENSITY_ORDER:
        return ["invalid_intensity_level"]

    ranges = intensity_ranges(attack_type, str(intensity_level))
    errors: List[str] = []
    if not _in_range(duration_seconds, ranges["duration_seconds"]):
        errors.append("duration_seconds_out_of_range")
    if str(target_host or "").strip() != PROTECTED_HOST:
        errors.append("target_host_mismatch")
    try:
        if int(target_port) != PROTECTED_PORT:
            errors.append("target_port_mismatch")
    except (TypeError, ValueError):
        errors.append("target_port_mismatch")

    expected_sources = int(spec["source_count"])
    try:
        observed_sources = int(source_count if source_count is not None else worker_count)
    except (TypeError, ValueError):
        observed_sources = -1
    if observed_sources != expected_sources:
        errors.append("source_count_mismatch")

    if spec["parameter_family"] == "access":
        if not _in_range(rate_pps, ranges["rate_pps"]):
            errors.append("request_rate_out_of_range")
        if not _in_range(request_count, ranges["request_count"]):
            errors.append("request_count_out_of_range")
        if payload_size_bytes not in (None, ""):
            errors.append("unexpected_payload_size")
    else:
        if not _in_range(payload_size_bytes, ranges["payload_size_bytes"]):
            errors.append("payload_size_out_of_range")
        try:
            ratio = offered_load_ratio(int(rate_pps), int(payload_size_bytes))
        except (TypeError, ValueError):
            ratio = -1.0
        if not _in_range(ratio, ranges["offered_load_ratio"]):
            errors.append("offered_load_ratio_out_of_range")
    return errors


def scenario_mapping_rows() -> List[Dict[str, Any]]:
    """Return transparent scenario-to-mechanism mappings for reports."""
    rows: List[Dict[str, Any]] = []
    for attack_type in DISPLAY_SCENARIO_ORDER:
        spec = SCENARIO_SPECS[attack_type]
        rows.append(
            {
                "attack_type": attack_type,
                "DisplayedScenario": spec["display_name"],
                "ExecutedMechanism": spec["mechanism"],
                "AnalysisGroup": spec["analysis_group"],
                "ParameterFamily": spec["parameter_family"],
                "SourceCount": spec["source_count"],
            }
        )
    return rows
