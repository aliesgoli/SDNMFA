# SDN-MFA-V2

[نسخه فارسی](README.fa.md) | [Running the experiments](docs/USAGE.md)

SDN-MFA-V2 is the research implementation I developed to study multi-factor authentication in a software-defined network. The project measures authentication and network authorization separately, then joins them in an end-to-end experiment from an attempted login to the resulting network action.

The laboratory runs entirely inside Mininet. It uses a Ryu/OpenFlow 1.3 controller, PostgreSQL for checkpoints and audit data, and a report generator for Persian thesis material and English publication material.

## What is measured

The study has two independent controls:

- the authentication policy decides which factors are required before a session is admitted;
- the network binding decides which source and attachment attributes must remain consistent after admission.

This distinction is important: IP address, MAC address and ingress port are network attributes, not substitutes for a password, OTP or biometric factor.

Four authentication policies are included:

| Policy | Required factors |
|---|---|
| Password | Password |
| Password + OTP | Password and software OTP |
| Password + Biometric | Password and a software-simulated biometric probe |
| Full MFA | Password, software OTP and a software-simulated biometric probe |

Each policy is crossed with four network bindings: IP, IP+MAC, IP+port, and IP+MAC+port. The network scenarios are unauthorized access, IP spoofing, IP+MAC spoofing, ARP/MITM, single-source UDP flooding, and three-source UDP flooding. Every scenario is run at low, medium and high intensity on three Mininet topologies.

At five repetitions, the complete design contains:

| Study component | Observations |
|---|---:|
| Authentication verifier | 840 |
| Independent network matrix | 4,320 |
| End-to-end chained matrix | 34,560 |
| Total | 39,720 |

The independent matrix is used to compare policy, binding, attack intensity and topology without mixing the authentication result into the network result. The chained matrix follows the complete path: authentication attack, admission decision, SDN authorization and network outcome.

## Authentication model

Passwords are stored with salted scrypt hashes. The software OTP is random, short-lived, single-use and bound to the user and authentication attempt. OTP values are stored as peppered HMAC digests.

The biometric component is deliberately a software simulation, as defined by the research scope. It uses encrypted 64-dimensional templates, genuine and impostor probes, a similarity score and a decision threshold. The report calculates ROC, FAR, FRR and EER for this model. It does not claim to evaluate a physical sensor or liveness detection; replay without liveness remains an explicit limitation.

## Environment

The reference environment is Linux with Python 3.9, PostgreSQL/`pgcrypto`, Mininet, Open vSwitch and Ryu 4.34. The command-line checks also expect `curl`, `ip`, `ping`, `psql` and `tcpdump`.

Create the virtual environment from the repository root:

```bash
python3.9 -m venv --system-site-packages venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install setuptools==67.8.0 wheel==0.45.1 pbr==5.11.1
./venv/bin/pip install --no-build-isolation -r requirements.txt
```

Copy the configuration template and restrict its permissions:

```bash
cp .env.example .env
chmod 600 .env
```

The database fields and all four independent secrets in `.env` are required. A convenient way to generate each secret is:

```bash
./venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run the migration and create at least one active, non-experiment account with the factors needed for Full MFA:

```bash
./venv/bin/python database/auto_migrator.py
./venv/bin/python admin/user_management.py
./venv/bin/python tools/preflight_check.py
```

The runner creates a separate 500-user synthetic cohort when it is needed. Existing ordinary accounts are not included in that cohort and are not deleted by cohort replacement.

## Running a study

The same seed and repetition count must be used for all three topologies:

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

`complete` runs or resumes the independent and chained phases. `factorial` runs only the independent matrix, while `chained` runs only the end-to-end matrix. A dry run prints the deterministic plan without changing the database or starting Mininet:

```bash
./venv/bin/python run_thesis_v2.py \
  --topology star-small --seed 20260822 --repetitions 5 \
  --phase complete --dry-run
```

Completed task identifiers are checkpointed in PostgreSQL. Repeating an interrupted command skips valid completed tasks and retries unfinished or technically invalid tasks. More detail is available in [docs/USAGE.md](docs/USAGE.md).

## Reports

The runner refreshes a partial report while the study is in progress. A strict final report is generated only when all planned observations are valid and no technical error remains:

```bash
./venv/bin/python analysis/article_report_v2.py --study-id STUDY_UUID
```

For an explicitly incomplete diagnostic report:

```bash
./venv/bin/python analysis/article_report_v2.py \
  --study-id STUDY_UUID --partial
```

The report directory contains Persian and English PDFs, a bilingual HTML dashboard, raw CSV files, a statistical JSON summary, and figures in PNG, SVG and PDF formats. The figures cover policy and binding comparisons, intensity curves, availability and recovery, latency ECDF, biometric ROC/FAR/FRR and the end-to-end chain.

Only technically valid observations enter security-rate denominators. A transport failure, incomplete restoration or failed control probe is recorded as `technical_error`, not as a blocked attack.

## Repository map

| Path | Contents |
|---|---|
| `config/` | protocol, topology profiles and Ryu application |
| `controller/` | authentication gate, authorization and campaign execution |
| `attacks/` | isolated Mininet scenarios and measurements |
| `experiments/` | factorial, authentication and chained designs |
| `security/`, `otp/` | password, OTP and simulated-biometric services |
| `database/` | schema, migration and audit persistence |
| `analysis/` | statistics, charts, PDF and HTML reports |
| `tests/` | unit, protocol, security and report checks |

## Reproducibility and scope

Study, campaign, task and chain identifiers are deterministic for a fixed protocol, seed and repetition count. Policy order is randomized inside paired comparison blocks, while sampled inputs are held constant within each block. Manifests and exported evidence include integrity metadata.

The results describe this implementation, its declared threat model, the selected topologies and the software factor models. They do not by themselves establish production readiness, physical-biometric accuracy or protection from every real-world attack. In particular, MFA is not treated as a volumetric DoS control.

## License

This project is released under the MIT License.
