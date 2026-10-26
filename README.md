# Safeguard Pro+

**An AI-assisted defensive security toolkit in one Flask dashboard.**

Phishing detection · Password auditing · Cryptography · File triage · Log monitoring · Network assessment

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Kali-4B5563)](#installation)
[![Use](https://img.shields.io/badge/use-defensive%20%26%20authorised-43E3A4)](#security-and-responsible-use)

> **Made by Er-Suzen Kumar Mohanty** · **IBM Cyber Security Project**

Safeguard Pro+ combines six defensive-security tools behind a single web interface. It is designed for students, SOC beginners, system administrators, and anyone who wants an explainable second opinion on a suspicious URL, email, password, file, log, or authorised network target.

All analysis happens locally on your machine. Nothing is uploaded to a third-party analysis service.

> [!WARNING]
> **Defensive and authorised use only.** The network assessment tool must only be used against systems you own or have explicit written permission to test. It is deliberately non-exploitative: no exploit payloads, brute force, credential attacks, or changes to the target.

---

## Table of contents

- [Overview](#overview)
- [Tools](#tools)
- [Requirements](#requirements)
- [Installation on Windows](#installation-on-windows)
- [Installation on Linux / Kali](#installation-on-linux--kali)
- [Run the application](#run-the-application)
- [Using the toolkit](#using-the-toolkit)
- [Network assessment](#network-assessment)
- [Command-line interface](#command-line-interface)
- [Reports](#reports)
- [Project structure](#project-structure)
- [Web API](#web-api)
- [Testing](#testing)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Security and responsible use](#security-and-responsible-use)
- [Limitations](#limitations)
- [Credits](#credits)
- [Detailed documentation](#detailed-documentation)

---

## Overview

Safeguard Pro+ is a Python and Flask application with one dashboard and one server:

```text
http://127.0.0.1:5000/            Main dashboard
http://127.0.0.1:5000/network/    Network assessment workspace
```

It provides:

- Six tools in one interface
- Explainable findings instead of unexplained scores
- Local processing and local scan history
- A machine-learning phishing engine
- Static file and log analysis
- An authorisation-gated network assessment workspace
- HTML, PDF, DOCX, CSV, and JSON network reports
- Windows and Linux launchers

The network assessment engine was originally developed as VulnScope and is now integrated into Safeguard Pro+ as **Safeguard Pro+ Network**.

---

## Tools

| Tool | What it does |
|---|---|
| **Phishing** | Analyses URLs and raw emails using lexical rules, header checks, content signals, and two scikit-learn models. |
| **Password** | Scores password strength, detects weak patterns, estimates crack time, and generates passwords, passphrases, or PINs. |
| **Crypto** | Hashes, encodes/decodes, applies classical ciphers, calculates HMACs, and supports AES-256-GCM when `cryptography` is installed. |
| **File triage** | Performs static malware triage: magic-byte detection, extension mismatch checks, entropy, PE headers, signatures, embedded URLs/IPs, and hashes. |
| **Logs** | Parses Apache/Nginx access logs and Linux `auth.log` files for web attacks, brute force, sensitive-file probes, and abnormal traffic. |
| **Network** | Runs authorised, non-exploitative TCP connect discovery, port mapping, service fingerprinting, and TLS/HTTP configuration checks. |

### Network assessment highlights

- Explicit authorisation confirmation before every scan
- IPv4 hosts, CIDR ranges, ranges, and hostnames
- Bounded target expansion
- TCP connect scanning — no raw sockets or SYN crafting
- Service and banner fingerprinting
- TLS certificate and protocol checks
- HTTP security-header and cookie review
- CVSS scores, CVE references, evidence, and remediation guidance
- Local posture checks kept separate from remote findings
- Live progress with Server-Sent Events and cancellation
- SQLite scan history
- HTML, PDF, DOCX, CSV, and JSON reports

---

## Requirements

### Minimum

- **Python 3.10 or newer** (tested with Python 3.14)
- **pip** and **venv**
- A modern browser
- Windows 10/11, Kali Linux, Ubuntu, Debian, or another mainstream Linux distribution

### Python packages

All required packages are listed in [`requirements.txt`](requirements.txt):

- Flask
- scikit-learn
- NumPy
- SciPy
- joblib
- psutil
- python-docx
- reportlab

Optional:

```bash
pip install cryptography
```

This enables AES-256-GCM in the Crypto tab. Every other feature works without it.

> You do **not** need `nmap` for the network assessment tool.

---

## Installation on Windows

### Option A — Recommended: one-click launcher

1. Install **Python 3.10 or newer** from [python.org](https://www.python.org/downloads/windows/).
2. During installation, tick **Add python.exe to PATH**.
3. Clone or download this repository:

   ```powershell
   git clone https://github.com/suzenkumar/IBM-CYBERSECURITY-PROJECT.git
   cd IBM-CYBERSECURITY-PROJECT
   ```

   If you downloaded a ZIP, extract it and open a terminal in the extracted project folder.

4. Double-click **`run.bat`**, or run it from PowerShell:

   ```powershell
   .\run.bat
   ```

`run.bat` will:

- Detect the available Python installation
- Install missing dependencies from `requirements.txt`
- Train the phishing models on first run
- Start the Flask application

5. Open:

   ```text
   http://127.0.0.1:5000
   ```

   Network workspace:

   ```text
   http://127.0.0.1:5000/network/
   ```

6. Press `Ctrl + C` in the terminal to stop the server.

### Option B — Manual PowerShell setup

Use this for a clean virtual environment:

```powershell
cd "C:\path\to\IBM-CYBERSECURITY-PROJECT"

py -3 -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python train_model.py
python SUZENKUMARMOHANTYPHISHINGGUARD.py
```

If PowerShell blocks script activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again:

```powershell
.\venv\Scripts\Activate.ps1
```

If you use Command Prompt instead of PowerShell:

```bat
cd /d "C:\path\to\IBM-CYBERSECURITY-PROJECT"
py -3 -m venv venv
venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python train_model.py
python SUZENKUMARMOHANTYPHISHINGGUARD.py
```

### Windows quick reference

| Task | Command |
|---|---|
| Activate environment | `.\venv\Scripts\Activate.ps1` |
| Install dependencies | `python -m pip install -r requirements.txt` |
| Train models | `python train_model.py` |
| Start app | `python SUZENKUMARMOHANTYPHISHINGGUARD.py` |
| Start on another port | `$env:PORT=5005; python SUZENKUMARMOHANTYPHISHINGGUARD.py` |

---

## Installation on Linux / Kali

The following instructions work on Kali Linux, Ubuntu, Debian, and most Debian-based systems.

### Option A — Recommended: `run.sh`

1. Install the prerequisites:

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv git
   ```

2. Clone the repository:

   ```bash
   git clone https://github.com/suzenkumar/IBM-CYBERSECURITY-PROJECT.git
   cd IBM-CYBERSECURITY-PROJECT
   ```

   If you are using a ZIP file:

   ```bash
   unzip IBM-CYBERSECURITY-PROJECT.zip
   cd IBM-CYBERSECURITY-PROJECT
   ```

3. Make the launcher executable and start it:

   ```bash
   chmod +x run.sh
   ./run.sh
   ```

`run.sh` automatically:

- Creates a local `venv`
- Activates it
- Installs `requirements.txt`
- Trains the models if they are missing
- Starts the Flask application on port 5000

4. Open Firefox or another browser:

   ```text
   http://127.0.0.1:5000
   ```

   Network workspace:

   ```text
   http://127.0.0.1:5000/network/
   ```

5. Press `Ctrl + C` to stop.

### Option B — Manual setup

```bash
cd ~/IBM-CYBERSECURITY-PROJECT

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python train_model.py
python SUZENKUMARMOHANTYPHISHINGGUARD.py
```

Kali marks its system Python as externally managed, so **always install dependencies inside the virtual environment**, not with `sudo pip`.

### Fix Windows line endings on `run.sh`

If the project was copied from Windows and `run.sh` fails with a `\r` or bad-interpreter error:

```bash
dos2unix run.sh
chmod +x run.sh
./run.sh
```

Or without `dos2unix`:

```bash
sed -i 's/\r$//' run.sh
chmod +x run.sh
./run.sh
```

### Linux quick reference

| Task | Command |
|---|---|
| Create environment | `python3 -m venv venv` |
| Activate environment | `source venv/bin/activate` |
| Install dependencies | `python -m pip install -r requirements.txt` |
| Train models | `python train_model.py` |
| Start app | `python SUZENKUMARMOHANTYPHISHINGGUARD.py` |
| Start on another port | `PORT=5005 python SUZENKUMARMOHANTYPHISHINGGUARD.py` |

### Accessing the app from a Kali VM

By default, Safeguard Pro+ binds to `127.0.0.1`, so it is available only inside the machine or VM where it is running. Open the URL in Kali's own browser.

To reach it from a Windows host, use an SSH tunnel:

```bash
ssh -L 5000:127.0.0.1:5000 kali@<kali-ip-address>
```

Then open `http://127.0.0.1:5000` on the Windows machine.

---

## Run the application

After installation, the normal start commands are:

**Windows**

```powershell
.\run.bat
```

**Linux / Kali**

```bash
./run.sh
```

Or, with the virtual environment activated:

```bash
python SUZENKUMARMOHANTYPHISHINGGUARD.py
```

The application starts at:

| Page | URL |
|---|---|
| Main dashboard | `http://127.0.0.1:5000/` |
| Network assessment | `http://127.0.0.1:5000/network/` |
| Health check | `http://127.0.0.1:5000/api/health` |

Use `Ctrl + C` to stop the development server.

---

## Using the toolkit

Open the main dashboard and select a tool from the tab bar:

1. **Phishing** — paste a URL or raw email and run the analysis.
2. **Password** — audit an existing password or generate a new one.
3. **Crypto** — hash, encode, decode, cipher, or calculate an HMAC.
4. **File** — upload or paste a sample for static triage. The file is never executed.
5. **Logs** — paste or upload an access log or `auth.log`.
6. **Network** — open the authorised network assessment workspace.

Every result includes a severity, a short explanation, supporting evidence, and recommended next steps where applicable.

### Demo data

The network workspace includes a demo assessment with realistic findings, so you can explore the interface without scanning anything. Use the **Load Demo Report** action on the network page.

---

## Network assessment

Open:

```text
http://127.0.0.1:5000/network/
```

### Workflow

1. Click **New assessment**.
2. Enter an IPv4 host, CIDR range, address range, or hostname.
3. Choose a port profile and assessment options.
4. Confirm that you own the target or have explicit authorisation to test it.
5. Start the scan and follow the live progress page.
6. Review findings, evidence, CVSS/CVE details, and remediation advice.
7. Export the result as HTML, PDF, DOCX, CSV, or JSON.

### Safety model

The scanner:

- Uses TCP connect checks
- Does not send exploit payloads
- Does not perform brute force
- Does not attempt authenticated attacks
- Does not write to the target
- Expands and bounds the target scope before scanning
- Requires explicit consent for each assessment

> A TCP connect scan does not require root by default. Some enriched local process details may be limited for processes owned by other users.

---

## Command-line interface

The main dashboard has a CLI companion for quick checks.

Activate the virtual environment first:

```bash
# Linux / Kali
source venv/bin/activate

# Windows PowerShell
.\venv\Scripts\Activate.ps1
```

Examples:

```bash
python cli.py --help
python cli.py demo
python cli.py url "https://paypal.com@secure-login-verify.tk/account"
python cli.py url urls.txt
python cli.py email email.txt
python cli.py email --subject "Verify now" --body "Click https://x.tk/login"
python cli.py password "Summer2024!"
python cli.py password --generate 20
python cli.py hash "hello world"
python cli.py hash --file setup.exe
python cli.py encode "hello" --method base64
python cli.py file suspicious.pdf.exe
python cli.py log /var/log/nginx/access.log
```

The CLI never executes uploaded or supplied files.

---

## Reports

Network assessments can be exported in five formats:

| Format | Best for |
|---|---|
| **HTML** | Interactive review and sharing in a browser |
| **PDF** | Print-ready professional reports |
| **DOCX** | Editing and adding organisational notes |
| **CSV** | Importing findings into a spreadsheet |
| **JSON** | Automation and further processing |

Reports are generated locally and branded **Safeguard Pro+ Network**.

Download route:

```text
/network/reports/<scan-id>/<format>
```

Example:

```text
http://127.0.0.1:5000/network/reports/scan-20261026-050102-5df81c/html
```

---

## Project structure

```text
phishing-detector/
├── SUZENKUMARMOHANTYPHISHINGGUARD.py   Main Flask application
├── cli.py                              Command-line interface
├── train_model.py                      Trains the phishing models
├── requirements.txt                    Required Python packages
├── run.bat                             Windows launcher
├── run.sh                              Linux/Kali launcher
│
├── phishing_detector/                  Phishing, password, crypto, file and log engines
│   ├── url_analyzer.py
│   ├── email_analyzer.py
│   ├── features.py
│   ├── model.py
│   ├── explainer.py
│   ├── password_tool.py
│   ├── crypto_tool.py
│   ├── file_analyzer.py
│   ├── log_monitor.py
│   └── ...
│
├── network_app/                        Integrated Safeguard Pro+ Network workspace
│   ├── webapp.py
│   ├── scanner/
│   │   ├── engine.py
│   │   ├── portscan.py
│   │   ├── services.py
│   │   ├── tls_probe.py
│   │   ├── http_probe.py
│   │   ├── findings.py
│   │   ├── report.py
│   │   └── store.py
│   ├── templates/
│   ├── static/
│   └── data/                           Generated history, reports and SQLite database
│
├── templates/
├── static/
├── models/                             Generated model files
├── tests/
└── docs/
    └── README_DETAILED.md              Long-form reference documentation
```

The `models/` files and `network_app/data/` folder are generated at runtime and are excluded by `.gitignore`.

---

## Web API

### Main API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/analyze-url` | Analyse a URL |
| `POST` | `/api/analyze-email` | Analyse a raw email or subject/body pair |
| `POST` | `/api/password/check` | Audit a password |
| `POST` | `/api/password/generate` | Generate a password, passphrase, or PIN |
| `POST` | `/api/crypto/hash` | Hash text or a file |
| `POST` | `/api/crypto/encode` | Encode or decode text |
| `POST` | `/api/crypto/cipher` | Apply a classical cipher |
| `POST` | `/api/crypto/hmac` | Calculate an HMAC |
| `POST` | `/api/file/analyze` | Static file triage |
| `POST` | `/api/log/analyze` | Analyse a log |
| `GET` | `/api/health` | Model and module status |
| `GET` | `/api/examples` | Built-in demo samples |

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://paypal.com@secure-login-verify.tk/account"}'
```

### Network API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/network/api/whoami` | Client and local discovery information |
| `GET` | `/network/api/resolve?target=...` | Validate and expand a target scope |
| `GET` | `/network/api/local` | Local posture and listeners |
| `POST` | `/network/api/scan/start` | Start an authorised scan |
| `GET` | `/network/scan/<scan-id>/json` | Scan status and stored result |
| `GET` | `/network/scan/<scan-id>/stream` | Server-Sent Events progress stream |
| `POST` | `/network/scan/<scan-id>/cancel` | Cancel a running scan |
| `GET` | `/network/history` | Scan history |
| `GET` | `/network/results/<scan-id>` | Results dashboard |
| `GET` | `/network/reports/<scan-id>/<format>` | Download a report |

A scan request requires `consent: true`:

```json
{
  "target": "192.168.1.10",
  "profile": "standard",
  "ports": "common",
  "consent": true
}
```

---

## Testing

Run the test suite from the project root:

```bash
python -m unittest discover -s tests -v
```

Run the static UI checks:

```bash
python tests/smoke_ui.py
```

At the time of writing, the suite contains **58 unit/integration tests** plus the dashboard smoke checks.

The tests cover:

- Phishing URL and email analysis
- Model loading and fallback behaviour
- Password scoring and generation
- Hashing, encoding, ciphers, and HMACs
- File triage
- Log parsing
- API routes
- Network assessment integration
- Health metadata
- Authorisation consent enforcement

You can also check the running server manually:

```bash
curl http://127.0.0.1:5000/api/health
```

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | HTTP port |
| `FLASK_DEBUG` | off | Set to `1` to enable Flask debug mode |
| `VULNSCOPE_DATA_DIR` | `network_app/data` | Override the network history/report directory |

Examples:

**Windows PowerShell**

```powershell
$env:PORT=5005
python SUZENKUMARMOHANTYPHISHINGGUARD.py
```

**Linux / Kali**

```bash
PORT=5005 python3 SUZENKUMARMOHANTYPHISHINGGUARD.py
```

To reset the network scan history, stop the server and remove:

```text
network_app/data/scans.db
```

The application recreates the database on the next start.

---

## Troubleshooting

| Problem | Platform | Fix |
|---|---|---|
| `python: command not found` | Windows | Use `py -3`, or reinstall Python with **Add python.exe to PATH** enabled. |
| PowerShell blocks `Activate.ps1` | Windows | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then activate again. |
| `python3-venv` is missing | Kali/Linux | `sudo apt install -y python3-venv` |
| `error: externally-managed-environment` | Kali/Linux | Create and activate a virtual environment; do not use `sudo pip`. |
| `run.sh: bad interpreter` | Linux | Fix CRLF line endings with `dos2unix run.sh` or `sed -i 's/\r$//' run.sh`. |
| Port 5000 is already in use | Both | Stop the other process, or start with `PORT=5005`. |
| Model files are missing | Both | Run `python train_model.py`. |
| `scikit-learn`/`scipy` build error | Linux | `sudo apt install -y build-essential python3-dev`, then retry inside the venv. |
| PDF reports fail | Both | `python -m pip install reportlab` |
| DOCX reports fail | Both | `python -m pip install python-docx` |
| AES-GCM is unavailable | Both | `python -m pip install cryptography` (optional feature). |
| Browser shows old CSS | Both | Hard-refresh with `Ctrl + F5`. |

If you are using Kali inside a VM and cannot reach the app from the host, open it inside Kali or use the SSH tunnel described above.

---

## Security and responsible use

Safeguard Pro+ is built for defensive learning and authorised assessment.

- Use the network scanner only on systems you own or have explicit permission to test.
- The scanner is non-exploitative. It does not exploit vulnerabilities, brute-force credentials, or bypass authentication.
- Findings are configuration and exposure indicators, not proof that a system is exploitable.
- The application binds to `127.0.0.1` by default and should not be exposed directly to the public internet.
- It uses Flask's development server. For anything beyond local use, deploy behind a production WSGI server and add authentication, TLS, rate limiting, and access controls.
- Scan history and generated reports are stored locally under `network_app/data/`.
- Analysis data is not uploaded to a third-party analysis service. The optional public-IP lookup on the network page is user-triggered; the main dashboard may fetch web fonts from Google Fonts.

If you discover a security issue in this project, report it privately to the author rather than opening a public exploit report.

---

## Limitations

- The phishing engine is a learning aid, not a replacement for email security gateways or professional threat intelligence.
- Password scoring is heuristic and cannot know whether a password has appeared in a breach without an external service.
- File triage is static only. It does not execute or detonate samples.
- Log detection uses patterns tuned for common Apache/Nginx and Linux SSH formats.
- Network OS/service detection is best effort and can be affected by firewalls, proxies, and filtered ports.
- CVSS scores and CVE references are advisory and should be verified independently.
- The application is not hardened for multi-tenant or internet-facing production use.

---

## Credits

**Author:** Er-Suzen Kumar Mohanty  
**Programme:** IBM Cyber Security Project  
**Stack:** Python · Flask · scikit-learn · SQLite · HTML · CSS · JavaScript

The network assessment workspace is based on the VulnScope scanning engine and is integrated into Safeguard Pro+ as **Safeguard Pro+ Network**.

---

## Detailed documentation

The original long-form reference — including detection internals, API examples, model training notes, and legacy platform notes — is preserved at:

[`docs/README_DETAILED.md`](docs/README_DETAILED.md)

For the current setup and run instructions, use this README.
