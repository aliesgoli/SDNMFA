# Running the experiments

[فارسی](USAGE.fa.md) | [Project overview](../README.md)

## Preparation

Create the Python environment, populate `.env`, apply the schema migration and prepare an active non-experiment account. The account used to open a campaign must have the factors required by Full MFA.

```bash
python3.9 -m venv --system-site-packages venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install setuptools==67.8.0 wheel==0.45.1 pbr==5.11.1
./venv/bin/pip install --no-build-isolation -r requirements.txt
cp .env.example .env
chmod 600 .env
./venv/bin/python database/auto_migrator.py
./venv/bin/python admin/user_management.py
./venv/bin/python tools/preflight_check.py
```

Preflight must finish with zero failures. Placeholder, repeated or short secrets are rejected.

## Inspecting the plan

`--dry-run` prints the study size and does not touch PostgreSQL or Mininet:

```bash
./venv/bin/python run_thesis_v2.py \
  --topology star-small --seed 20260822 --repetitions 5 \
  --phase complete --dry-run
```

With five repetitions, the full three-topology study contains 840 authentication observations, 4,320 independent network observations and 34,560 chained observations.

## Complete run

Run the following commands from the repository root. Keep the seed, repetition count and `.env` unchanged between topologies.

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology star-small --seed 20260822 --repetitions 5 \
  --phase complete
```

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology tree-medium --seed 20260822 --repetitions 5 \
  --phase complete
```

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase complete
```

The runner handles migration, preflight, the synthetic cohort, Ryu, Mininet, checkpoints, cleanup and report refresh. The independent phase asks for one successful Full-MFA login before starting its tasks. Planned work is non-interactive after that point.

## Running one phase

Independent matrix only:

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase factorial
```

Chained matrix only:

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase chained
```

The chained phase is normally started after the independent matrix for that topology is valid.

## Resume and cleanup

The original command is also the resume command. Valid completed tasks are skipped; unfinished tasks and tasks recorded with `technical_error` are attempted again.

If Mininet was stopped outside the runner, clean stale namespaces before resuming:

```bash
sudo mn -c
```

Exit status `0` means the requested work completed without a remaining technical error. Status `2` means observations were recorded but at least one technical error remains. Status `130` means the run was interrupted.

Security outcomes and technical states must not be combined. `attack_success`, `attack_blocked`, `blocked_at_authentication`, `availability_preserved` and `availability_degraded` are observations; `not_evaluable` is a technical exclusion.

## Reports

The study identifier printed by the runner is stable for the protocol, seed, repetition count and topology set.

```bash
./venv/bin/python analysis/article_report_v2.py --study-id STUDY_UUID
```

Strict generation requires complete valid data and zero technical errors. During a run, an incomplete diagnostic report can be generated explicitly:

```bash
./venv/bin/python analysis/article_report_v2.py \
  --study-id STUDY_UUID --partial
```

Open `reports/STUDY_UUID/index.html` for the bilingual dashboard and download links. Local `.env`, logs, database files, packet captures and measured reports are ignored by Git.

## Verification before a release

```bash
./venv/bin/python -m unittest discover -s tests -v
./venv/bin/python tools/preflight_check.py
```

The final report should show 4,320 valid network observations, 840 valid authentication observations, 34,560 valid chained observations, all three topology identifiers and zero technical errors. Packet capture is optional and can be enabled with `--capture-pcap`; it substantially increases runtime and storage use.
