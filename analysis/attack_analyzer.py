#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SDN MFA - Attack Analyzer

Generates an HTML report that summarizes attack outcomes and compares
MFA policies (modes) based on data stored in Postgres.

This script is intentionally defensive against schema drift:
- It autodetects the best time column from: created_at, start_time, end_time
- It works even if optional columns (mfa_mode, detection_score, http_status, jsonb fields) are missing

Outputs:
- Comparison table for 4 MFA policies
- Bar chart for success rate per policy
- Auto "Research Findings" section

"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor

# matplotlib is used only for saving charts (no GUI requirement)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Ensure project root is importable when this file is executed as a script
# (e.g. python3 analysis/attack_analyzer.py).
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db_config import get_db_connection, release_db_connection


# -----------------------------
# DB helpers
# -----------------------------

def _connect():
    """Connect to PostgreSQL using database/db_config.py (reads .env)."""
    return get_db_connection()


def _get_columns(conn, table: str) -> List[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        return [r[0] for r in cur.fetchall()]


def _pick_time_col(cols: List[str]) -> str:
    for c in ("created_at", "start_time", "end_time"):
        if c in cols:
            return c
    raise RuntimeError("attack_logs has no recognized timestamp column")


# -----------------------------
# Analysis
# -----------------------------

MFA_ORDER = [
    ("password_only", "Password Only"),
    ("password_otp", "Password + OTP"),
    ("password_biometric", "Password + Biometric"),
    ("password_otp_biometric", "Password + OTP + Biometric"),
    ("unknown", "Unknown / Not Logged"),
]


@dataclass
class ModeRow:
    mode: str
    label: str
    total: int
    succeeded: int
    blocked: int
    success_rate: float
    avg_duration: Optional[float]
    avg_packets: Optional[float]
    avg_detection: Optional[float]


def _safe_float(x: Any) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except Exception:
        return None


def analyze(days: int = 7) -> Dict[str, Any]:
    conn = _connect()
    try:
        cols = _get_columns(conn, "attack_logs")
        tcol = _pick_time_col(cols)
        has_mode = "mfa_mode" in cols
        has_detection = "detection_score" in cols

        # Latest timestamp (helps explain empty windows)
        with conn.cursor() as cur:
            cur.execute(f"SELECT MAX({tcol}) FROM attack_logs")
            latest_ts = cur.fetchone()[0]

        # Overall stats in period
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN success THEN 1 ELSE 0 END) AS succeeded
                FROM attack_logs
                WHERE {tcol} >= NOW() - INTERVAL %s
                """,
                (f"{days} days",),
            )
            total, succeeded = cur.fetchone()
            total = int(total or 0)
            succeeded = int(succeeded or 0)

        # Attacks by type
        attacks_by_type: List[Tuple[str, int, int]] = []
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT attack_type,
                       COUNT(*) AS total,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) AS succeeded
                FROM attack_logs
                WHERE {tcol} >= NOW() - INTERVAL %s
                GROUP BY attack_type
                ORDER BY total DESC
                """,
                (f"{days} days",),
            )
            for r in cur.fetchall():
                attacks_by_type.append((r[0], int(r[1] or 0), int(r[2] or 0)))

        # Per-mode comparison
        mode_rows: List[ModeRow] = []
        if has_mode:
            # Build base query with optional aggregates
            det_expr = "AVG(detection_score)" if has_detection else "NULL"
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                        COALESCE(mfa_mode, 'unknown') AS mode,
                        COUNT(*) AS total,
                        SUM(CASE WHEN success THEN 1 ELSE 0 END) AS succeeded,
                        AVG(duration_seconds::float) AS avg_duration,
                        AVG(packets_sent::float) AS avg_packets,
                        {det_expr} AS avg_detection
                    FROM attack_logs
                    WHERE {tcol} >= NOW() - INTERVAL %s
                    GROUP BY COALESCE(mfa_mode, 'unknown')
                    """,
                    (f"{days} days",),
                )
                rows = cur.fetchall()

            by_mode: Dict[str, Dict[str, Any]] = {}
            for mode, tot, succ, avg_dur, avg_pkt, avg_det in rows:
                tot_i = int(tot or 0)
                succ_i = int(succ or 0)
                by_mode[str(mode)] = {
                    "total": tot_i,
                    "succeeded": succ_i,
                    "blocked": tot_i - succ_i,
                    "success_rate": (succ_i / tot_i) if tot_i else 0.0,
                    "avg_duration": _safe_float(avg_dur),
                    "avg_packets": _safe_float(avg_pkt),
                    "avg_detection": _safe_float(avg_det),
                }

            for key, label in MFA_ORDER:
                d = by_mode.get(key, {"total": 0, "succeeded": 0, "blocked": 0, "success_rate": 0.0,
                                      "avg_duration": None, "avg_packets": None, "avg_detection": None})
                mode_rows.append(
                    ModeRow(
                        mode=key,
                        label=label,
                        total=int(d["total"]),
                        succeeded=int(d["succeeded"]),
                        blocked=int(d["blocked"]),
                        success_rate=float(d["success_rate"]),
                        avg_duration=d["avg_duration"],
                        avg_packets=d["avg_packets"],
                        avg_detection=d["avg_detection"],
                    )
                )

        return {
            "days": days,
            "time_col": tcol,
            "latest_ts": latest_ts,
            "overall": {
                "total": total,
                "succeeded": succeeded,
                "blocked": total - succeeded,
                "success_rate": (succeeded / total) if total else 0.0,
            },
            "attacks_by_type": attacks_by_type,
            "mode_rows": mode_rows,
            "has_mode": has_mode,
            "has_detection": has_detection,
        }
    finally:
        release_db_connection(conn)


# -----------------------------
# Reporting
# -----------------------------

def _ensure_dirs() -> Tuple[str, str]:
    base_dir = os.path.join("reports_view", "attacks")
    charts_dir = os.path.join(base_dir, "charts")
    os.makedirs(charts_dir, exist_ok=True)
    return base_dir, charts_dir


def _save_success_rate_bar(mode_rows: List[ModeRow], charts_dir: str, ts: str) -> Optional[str]:
    if not mode_rows:
        return None

    labels = [m.label for m in mode_rows]
    values = [m.success_rate * 100.0 for m in mode_rows]

    plt.figure(figsize=(9, 4.5))
    plt.bar(labels, values)
    plt.ylim(0, 100)
    plt.ylabel("Success rate (%)")
    plt.title("Attack Success Rate by MFA Policy")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()

    out = os.path.join(charts_dir, f"success_rate_by_mfa_{ts}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    return out


def _research_findings(stats: Dict[str, Any]) -> str:
    overall = stats["overall"]
    days = stats["days"]

    findings: List[str] = []

    if overall["total"] == 0:
        latest = stats.get("latest_ts")
        if latest:
            findings.append(
                f"No attacks were recorded in the last {days} days. The latest recorded attack is at {latest}. "
                f"Increase the analysis window (e.g., 30/60/90 days) to include those results."
            )
        else:
            findings.append(
                f"No attacks were found in the database for the last {days} days."
            )
        return "<p>" + " ".join(findings) + "</p>"

    findings.append(
        f"Across the last {days} days, {overall['total']} attacks were logged; "
        f"{overall['succeeded']} succeeded and {overall['blocked']} were blocked/failed "
        f"(overall success rate: {overall['success_rate']*100:.1f}%)."
    )

    # Which attack types are most successful?
    by_type = stats.get("attacks_by_type", [])
    if by_type:
        best = max(by_type, key=lambda r: (r[2] / r[1]) if r[1] else 0.0)
        worst = min(by_type, key=lambda r: (r[2] / r[1]) if r[1] else 0.0)
        best_rate = (best[2] / best[1]) * 100 if best[1] else 0
        worst_rate = (worst[2] / worst[1]) * 100 if worst[1] else 0
        findings.append(
            f"The highest observed success rate by attack type was <b>{best[0]}</b> "
            f"({best_rate:.1f}%), while <b>{worst[0]}</b> had the lowest ({worst_rate:.1f}%)."
        )

    # MFA comparison
    mode_rows: List[ModeRow] = stats.get("mode_rows", [])
    if mode_rows:
        nonzero = [m for m in mode_rows if m.total > 0 and m.mode != "unknown"]
        unknown = next((m for m in mode_rows if m.mode == "unknown"), None)

        if nonzero:
            most_resistant = min(nonzero, key=lambda m: m.success_rate)
            least_resistant = max(nonzero, key=lambda m: m.success_rate)
            findings.append(
                f"Among the MFA policies, <b>{most_resistant.label}</b> achieved the lowest attack success rate "
                f"({most_resistant.success_rate*100:.1f}%), while <b>{least_resistant.label}</b> showed the highest "
                f"({least_resistant.success_rate*100:.1f}%)."
            )
        elif unknown and unknown.total > 0:
            findings.append(
                f"MFA policy-level analysis is limited because <b>mfa_mode</b> is not populated for the recorded attacks "
                f"({unknown.total} attack(s) are marked as \"{unknown.label}\"). "
                f"To compare the 4 MFA policies, ensure the authentication pipeline writes the active policy to the "
                f"attack_logs.mfa_mode column for each attack attempt."
            )

        # If detection score exists
        if stats.get("has_detection"):
            det_vals = [(m.label, m.avg_detection) for m in mode_rows if m.avg_detection is not None]
            if det_vals:
                best_det = max(det_vals, key=lambda x: x[1])
                findings.append(
                    f"Detection scores were highest on average under <b>{best_det[0]}</b> "
                    f"(avg detection score: {best_det[1]:.2f})."
                )

    return "<p>" + " ".join(findings) + "</p>"


def generate_html_report(stats: Dict[str, Any]) -> str:
    base_dir, charts_dir = _ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    chart_path = _save_success_rate_bar(stats.get("mode_rows", []), charts_dir, ts)

    # Build table rows
    table_html = ""
    if stats.get("mode_rows"):
        rows = []
        for m in stats["mode_rows"]:
            rows.append(
                "<tr>"
                f"<td>{m.label}</td>"
                f"<td style='text-align:right'>{m.total}</td>"
                f"<td style='text-align:right'>{m.succeeded}</td>"
                f"<td style='text-align:right'>{m.blocked}</td>"
                f"<td style='text-align:right'>{m.success_rate*100:.1f}%</td>"
                f"<td style='text-align:right'>{'' if m.avg_duration is None else f'{m.avg_duration:.2f}'}</td>"
                f"<td style='text-align:right'>{'' if m.avg_packets is None else f'{m.avg_packets:.0f}'}</td>"
                f"<td style='text-align:right'>{'' if m.avg_detection is None else f'{m.avg_detection:.2f}'}</td>"
                "</tr>"
            )
        table_html = """
        <p class="muted">🧷 Note: Rows are based on <code>attack_logs.mfa_mode</code>. If this column is not populated during attacks,
        results will appear under <b>Unknown / Not Logged</b>.</p>
        <table>
          <thead>
            <tr>
              <th>MFA Policy</th>
              <th>Total Attacks</th>
              <th>Succeeded</th>
              <th>Blocked/Failed</th>
              <th>Success Rate</th>
              <th>Avg Duration (s)</th>
              <th>Avg Packets</th>
              <th>Avg Detection Score</th>
            </tr>
          </thead>
          <tbody>
        """ + "\n".join(rows) + """
          </tbody>
        </table>
        <p class='note'>Note: Avg Detection Score is shown only if the <code>detection_score</code> column exists and is populated.</p>
        """

    # Attacks by type
    type_rows = []
    for atype, total, succ in stats.get("attacks_by_type", []):
        sr = (succ / total) * 100 if total else 0
        type_rows.append(
            f"<tr><td>{atype}</td><td style='text-align:right'>{total}</td>"
            f"<td style='text-align:right'>{succ}</td><td style='text-align:right'>{sr:.1f}%</td></tr>"
        )

    type_table = ""
    if type_rows:
        type_table = """
        <p class="muted">🧭 Breakdown by attack scenario (from <code>attack_logs.attack_type</code>).</p>
        <table>
          <thead>
            <tr>
              <th>Attack Type</th>
              <th>Total</th>
              <th>Succeeded</th>
              <th>Success Rate</th>
            </tr>
          </thead>
          <tbody>
        """ + "\n".join(type_rows) + """
          </tbody>
        </table>
        """

    findings_html = _research_findings(stats)

    chart_html = ""
    if chart_path:
        rel = os.path.relpath(chart_path, base_dir)
        chart_html = f"""
        <div class="muted">📌 Success rate by MFA policy (from <code>attack_logs</code>).</div>
        <div class="chart-wrap"><img src="{rel}" alt="Success rate by MFA policy" /></div>
        """

    overall = stats["overall"]

    # Use the same light, readable visual language as system_evaluator
    # (white cards on a purple gradient background).
    css = """
* {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        .action-buttons {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 10px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            text-decoration: none;
            transition: all 0.3s;
            font-size: 0.9em;
            cursor: pointer;
            font-family: inherit;
        }
        .btn:hover {
            background: #764ba2;
            transform: translateY(-2px);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        .section {
            padding: 30px;
        
            overflow: hidden;
        }
        .section-title {
            font-size: 1.6em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
.chart-wrap {
    margin: 20px 0;
    text-align: center;
    overflow: hidden;
}
.chart-wrap img {
    width: min(720px, 100%);
    max-width: 100%;
    height: auto;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    display: block;
    margin: 0 auto;
}
@media (max-width: 768px) {
    .chart-wrap img, .chart-container img {
        width: 100%;
    }
}

.chart-container {
            margin: 20px 0;
            text-align: center;
        }
        .chart-container img {
            width: min(720px, 100%);
            max-width: 100%;
            height: auto;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.3s;
            display: block;
            margin: 0 auto;
        }
        .chart-container img:hover {
            transform: scale(1.02);
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .data-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        .data-table td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        .data-table tr:hover {
            background: #f5f5f5;
        }
        .excellent-badge {
            background: #2ecc71;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }
        .good-badge {
            background: #3498db;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }
        .average-badge {
            background: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }
        .poor-badge {
            background: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal img {
            max-width: 90%;
            max-height: 90%;
            border-radius: 10px;
        }
        /* Attack analyzer extras */
        .chip { display:inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; background: rgba(102,126,234,0.12); color:#3f51b5; }
        .chip.red { background: rgba(231,76,60,0.12); color:#c0392b; }
        .chip.green { background: rgba(46,204,113,0.14); color:#1e874b; }
    """

    # Wrap dynamic sections into the same table/card styling
    if table_html:
        table_html = table_html.replace("<table>", "<table class='data-table'>")
    if type_table:
        type_table = type_table.replace("<table>", "<table class='data-table'>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🧪 SDN MFA Attack Analysis Report</title>
  <style>{css}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🧪 SDN MFA – Attack Analysis Report</h1>
      <div class="meta">
        🕒 Generated: <b>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</b> &nbsp;|&nbsp;
        🗓️ Window: last <b>{stats['days']}</b> day(s) &nbsp;|&nbsp;
        🧷 Time column: <code>{stats['time_col']}</code>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">🧨 Total attacks</div><div class="stat-value">{overall['total']:,}</div></div>
      <div class="stat-card"><div class="stat-label">✅ Succeeded</div><div class="stat-value">{overall['succeeded']:,}</div></div>
      <div class="stat-card"><div class="stat-label">🛡️ Blocked / failed</div><div class="stat-value">{overall['blocked']:,}</div></div>
      <div class="stat-card"><div class="stat-label">📈 Success rate</div><div class="stat-value">{overall['success_rate']*100:.1f}%</div></div>
    </div>

    <div class="section">
      <div class="section-title">🧠 Research Findings (Auto)</div>
      <div class="muted">Summary of what the data suggests for the selected time window.</div>
      {findings_html}
    </div>

    <div class="section">
      <div class="section-title">🧩 MFA Policy Comparison</div>
      {table_html if table_html else "<div class='muted'>⚠️ No <code>mfa_mode</code> data found in this window (or the column does not exist). Run attacks via the MFA CLI and ensure the logger writes <code>mfa_mode</code>.</div>"}
    </div>

    <div class="section">
      <div class="section-title">📊 Visual Summary</div>
      {chart_html if chart_html else "<div class='muted'>No chart generated (insufficient data).</div>"}
    </div>

    <div class="section">
      <div class="section-title">🎯 Attack Types Summary</div>
      {type_table if type_table else "<div class='muted'>No attacks found in this window.</div>"}
    </div>

    <p class="note">💡 Tip: If you get “No attacks in last 7 days”, check the latest attack timestamp in DB and increase the window.</p>
  </div>
</body>
</html>
"""

    out_path = os.path.join(base_dir, f"attack_analysis_{ts}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path


def main() -> None:
    print("\n" + "=" * 70)
    print("🧪====================== Attack Analysis System ======================🧪")
    print("=" * 70 + "\n")

    try:
        raw = input("📅 Enter analysis period in days [7]: ").strip()
        days = int(raw) if raw else 7
    except Exception:
        days = 7

    print("\nAnalyzing attack data...\n")

    try:
        stats = analyze(days)
    except Exception as e:
        print(f"Error analyzing data: {e}")
        sys.exit(1)

    if stats["overall"]["total"] == 0:
        # Explain the most common reason (window doesn't include latest records)
        latest = stats.get("latest_ts")
        if latest:
            print(f"No attack data found for the last {days} days.")
            print(f"Latest recorded attack in DB: {latest}")
            print("Try a larger window (e.g., 30/60/90 days).\n")
        else:
            print(f"No attack data found for the last {days} days.\n")

    report_path = generate_html_report(stats)

    print("\n✅ Report generated:")
    print(f"   {report_path}")


if __name__ == "__main__":
    main()