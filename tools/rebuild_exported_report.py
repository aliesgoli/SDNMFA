#!/usr/bin/env python3
"""Rebuild an exported aggregate dashboard without querying PostgreSQL."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.aggregate_charts import save_aggregate_charts
from analysis.aggregate_dashboard import render_aggregate_dashboard
from analysis.scientific_report import factor_compromise_resistance_rows


FACTOR_FIELDS = (
    "policy",
    "policy_label",
    "compromise_state_n",
    "fully_resisted_state_n",
    "exposed_state_n",
    "observation_n",
    "blocked_authentication_n",
    "successful_authentication_n",
    "resistance_percent",
    "resistance_ci95_low",
    "resistance_ci95_high",
    "evidence_scope",
)


def rebuild(source: Path, output: Path, *, persian: bool) -> Path:
    source = source.resolve()
    output = output.resolve()
    if output.exists():
        raise RuntimeError("Output already exists: %s" % output)
    summary_path = source / "data" / "aggregate_summary.json"
    if not summary_path.is_file():
        raise RuntimeError("Aggregate summary not found: %s" % summary_path)

    shutil.copytree(source, output)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["release_label"] = "v2"
    summary["factor_compromise_resistance_rows"] = (
        factor_compromise_resistance_rows(
            list(summary.get("software_verifier_conformance_rows") or [])
        )
    )

    data_dir = output / "data"
    factor_csv = data_dir / "aggregate_factor_compromise_resistance.csv"
    with factor_csv.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FACTOR_FIELDS)
        writer.writeheader()
        writer.writerows(summary["factor_compromise_resistance_rows"])

    chart_index, _ = save_aggregate_charts(
        summary,
        output / "assets" / "charts",
        data_dir,
        persian=persian,
    )
    (output / "index.html").write_text(
        render_aggregate_dashboard(summary, persian=persian, charts=chart_index),
        encoding="utf-8",
    )
    (data_dir / "aggregate_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output / "index.html"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--P", action="store_true", dest="persian")
    args = parser.parse_args()
    print(rebuild(args.source, args.output, persian=args.persian))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
