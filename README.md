# SDNMFA

SDNMFA is a Software-Defined Network (SDN) security framework that enforces Multi-Factor Authentication (MFA) and provides attack simulation and evaluation tools.

This guide explains exactly how to install, configure, run the system, execute tests, and generate reports.

---

## 1) System Requirements

### Operating System
Linux environment recommended (Ubuntu preferred for Mininet compatibility)

### Required Software (System-Level)

These must be installed manually on the system:

- Python 3.9
- PostgreSQL (server running)
- Mininet
- Ryu SDN Controller

Mininet and Ryu are required for the SDN experiment scenario.

---

## 2) Python Dependencies

After cloning the project, create a virtual environment and install dependencies:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

The `requirements.txt` file already includes all required Python libraries.

---

## 3) Environment Configuration (.env)

After installation, the first mandatory step is configuring environment variables.

1) Rename the template file:

.env.example  →  .env

The system reads configuration only from `.env`.

2) Edit `.env` and configure:

- DB_NAME
- DB_USER
- DB_PASSWORD
- DB_HOST
- DB_PORT
- BIOMETRIC_PEPPER

### What is BIOMETRIC_PEPPER?

BIOMETRIC_PEPPER is a secret constant used to strengthen biometric hashing operations.

It must:
- Be random and long
- Remain private
- Never be committed publicly

Generate one using:

python3 -c "import secrets; print(secrets.token_hex(32))"

Copy the generated value into `.env`.

Once the system is deployed, avoid changing this value.

---

## 4) Database Setup

Ensure PostgreSQL is running.

Apply the database schema:

psql -U <db_user> -d <db_name> -f database/sql/tables.sql

---

## 5) Create Users

Before running the SDN scenario, create at least one user:

python3.9 admin/user_management.py

Use the CLI menu to create a test user.

---

## 6) Run the SDN + MFA Scenario (Three Terminals)

Open three separate terminals and execute the following in order.

Terminal 1 – Start Ryu Security Controller:

ryu-manager config/security_controller.py --observe-links

Terminal 2 – Start Mininet Topology:

sudo python3.9 config/topology.py

Terminal 3 – Start MFA Controller:

sudo -E python3.9 controller/mfa_controller.py

The -E flag ensures environment variables from `.env` remain available when using sudo.

---

## 7) View Attack Results and System Evaluation

After running tests and generating logs, execute:

Attack Analyzer:

python3.9 analysis/attack_analyzer.py

System Evaluator:

python3.9 analysis/system_evaluator.py

Both scripts generate reports and print the output path when finished.

---

## Notes

- If database errors occur, verify DB_* values and ensure PostgreSQL is running.
- The `.env` file must remain private.
- Do not publish encryption keys or secret values.
