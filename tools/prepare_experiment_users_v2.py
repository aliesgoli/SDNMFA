#!/usr/bin/env python3
"""Create the isolated 500-user thesis cohort without touching normal users."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
while str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.synthetic_users import (
    DEFAULT_COHORT,
    DEFAULT_USER_COUNT,
    provision_experiment_users,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=DEFAULT_USER_COUNT)
    parser.add_argument("--cohort", default=DEFAULT_COHORT)
    parser.add_argument(
        "--replace-cohort",
        action="store_true",
        help="Replace only prior synthetic users in this cohort.",
    )
    args = parser.parse_args(argv)
    result = provision_experiment_users(
        count=args.count,
        cohort=args.cohort,
        replace_cohort=args.replace_cohort,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
