"""Primary bilingual single- and multi-campaign report entry point."""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)

from analysis.scientific_report import (
    generate_aggregate_report,
    generate_report,
    main,
    summarize_aggregate,
)

__all__ = [
    "generate_aggregate_report",
    "generate_report",
    "main",
    "summarize_aggregate",
]


if __name__ == "__main__":
    raise SystemExit(main())
