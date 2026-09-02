"""Shared data contracts for the controlled Mininet scenarios.

Scenario execution lives exclusively in :mod:`attacks.attack_manager`; this
module defines the shared configuration and observation contracts.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


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
    duration_s: int = 5
    rate_pps: int = 1
    threads: int = 1
    payload_size_bytes: Optional[int] = None
    attack_type: str = "base_attack"
    gateway_ip: Optional[str] = None
    mfa_mode: str = "password_only"
    run_id: Optional[str] = None
    attempt_id: Optional[str] = None
    authorization_context: Optional[Dict[str, Any]] = None
    campaign_id: Optional[str] = None
    task_id: Optional[str] = None
    sample_id: Optional[str] = None
    repetition: Optional[int] = None
    intensity_level: Optional[str] = None
    binding_profile: str = "ip_mac_port"
    topology_id: Optional[str] = None
    request_count: Optional[int] = None
    source_count: Optional[int] = None
