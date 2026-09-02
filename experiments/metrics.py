"""Resource, latency, and optional packet-capture evidence helpers."""

from __future__ import annotations

import hashlib
import shutil
import statistics
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import psutil
except ImportError:  # preflight reports this before a real campaign starts
    psutil = None


def percentile(values: Iterable[float], percentile_value: float) -> Optional[float]:
    rows = sorted(float(value) for value in values)
    if not rows:
        return None
    if len(rows) == 1:
        return rows[0]
    position = (len(rows) - 1) * float(percentile_value) / 100.0
    lower = int(position)
    upper = min(lower + 1, len(rows) - 1)
    fraction = position - lower
    return rows[lower] + (rows[upper] - rows[lower]) * fraction


def latency_summary_ms(values: Iterable[float]) -> Dict[str, Optional[float]]:
    rows = [float(value) for value in values if value is not None]
    return {
        "count": len(rows),
        "mean_ms": round(statistics.fmean(rows), 3) if rows else None,
        "p50_ms": round(percentile(rows, 50) or 0.0, 3) if rows else None,
        "p95_ms": round(percentile(rows, 95) or 0.0, 3) if rows else None,
        "max_ms": round(max(rows), 3) if rows else None,
    }


class ResourceSampler:
    """Sample controller-process and host-wide resource use in the background."""

    def __init__(
        self,
        interval_seconds: float = 0.2,
        pid: Optional[int] = None,
        process_label: str = "current_process",
    ):
        if psutil is None:
            raise RuntimeError("psutil is required for resource measurement")
        self.interval_seconds = max(0.05, float(interval_seconds))
        self.process = psutil.Process(pid) if pid is not None else psutil.Process()
        self.process_pid = int(self.process.pid)
        self.process_label = str(process_label)
        self.samples: List[Dict[str, float]] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "ResourceSampler":
        self.process.cpu_percent(None)
        psutil.cpu_percent(None)
        self._thread = threading.Thread(target=self._run, name="resource-sampler", daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        started = time.monotonic()
        while not self._stop.wait(self.interval_seconds):
            try:
                memory = self.process.memory_info()
                self.samples.append(
                    {
                        "elapsed_seconds": time.monotonic() - started,
                        "process_cpu_percent": self.process.cpu_percent(None),
                        "process_rss_bytes": float(memory.rss),
                        "system_cpu_percent": psutil.cpu_percent(None),
                        "system_memory_percent": psutil.virtual_memory().percent,
                    }
                )
            except (psutil.Error, OSError):
                break

    def stop(self) -> Dict[str, Any]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_seconds * 3))
        return self.summary()

    def summary(self) -> Dict[str, Any]:
        def describe(field: str) -> Dict[str, Optional[float]]:
            values = [float(row[field]) for row in self.samples]
            return {
                "mean": round(statistics.fmean(values), 3) if values else None,
                "p95": round(percentile(values, 95) or 0.0, 3) if values else None,
                "max": round(max(values), 3) if values else None,
            }

        raw_samples = [
            {
                "elapsed_seconds": round(float(row["elapsed_seconds"]), 6),
                "process_cpu_percent": round(float(row["process_cpu_percent"]), 3),
                "process_rss_bytes": int(round(float(row["process_rss_bytes"]))),
                "system_cpu_percent": round(float(row["system_cpu_percent"]), 3),
                "system_memory_percent": round(float(row["system_memory_percent"]), 3),
            }
            for row in self.samples
        ]
        return {
            "sample_count": len(self.samples),
            "interval_seconds": self.interval_seconds,
            "process_pid": self.process_pid,
            "process_label": self.process_label,
            "process_cpu_percent": describe("process_cpu_percent"),
            "process_rss_bytes": describe("process_rss_bytes"),
            "system_cpu_percent": describe("system_cpu_percent"),
            "system_memory_percent": describe("system_memory_percent"),
            # Retaining the time series lets an examiner reproduce summaries,
            # inspect transients, and apply a different aggregation method.
            "samples": raw_samples,
        }


class PacketCapture:
    """Optional tcpdump capture restricted to one Mininet namespace and target."""

    def __init__(self, host_pid: int, output_path: Path, target_host: str, target_port: int):
        self.host_pid = int(host_pid)
        self.output_path = Path(output_path)
        self.target_host = str(target_host)
        self.target_port = int(target_port)
        self.process: Optional[subprocess.Popen] = None

    @staticmethod
    def available() -> bool:
        return shutil.which("mnexec") is not None and shutil.which("tcpdump") is not None

    def start(self) -> "PacketCapture":
        if not self.available():
            raise RuntimeError("mnexec and tcpdump are required for packet capture")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(
            [
                "mnexec", "-a", str(self.host_pid), "tcpdump", "-i", "any", "-U", "-n",
                "-w", str(self.output_path), "host", self.target_host, "and", "port", str(self.target_port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.25)
        if self.process.poll() is not None:
            _, stderr = self.process.communicate()
            raise RuntimeError("tcpdump failed to start: %s" % (stderr or "unknown error"))
        return self

    def stop(self) -> Dict[str, Any]:
        stderr = ""
        if self.process is not None:
            self.process.terminate()
            try:
                _, stderr = self.process.communicate(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                _, stderr = self.process.communicate()
        exists = self.output_path.exists()
        digest = None
        size = None
        if exists:
            size = self.output_path.stat().st_size
            hasher = hashlib.sha256()
            with self.output_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        return {
            "enabled": True,
            "path": str(self.output_path) if exists else None,
            "size_bytes": size,
            "sha256": digest,
            "stderr": stderr[-500:] if stderr else None,
        }
