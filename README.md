# Quantum-Proof Systems Scanner

Real-time TLS cryptographic assessment platform — CBOM generation, PQC readiness scoring, CRQC attack simulation, and migration roadmap.

**PSB Hackathon 2026**

---

## Setup Instructions

### Prerequisites

- **Python 3.10+** — [Download here](https://www.python.org/downloads/)
- **Git** — [Download here](https://git-scm.com/downloads)

### Step 1: Clone the repository

```bash
git clone https://github.com/VJakharDev/pnb_hackathon.git
cd pnb_hackathon
```

### Step 2: Set up the backend

#### 🐧 Kali Linux / Ubuntu / Debian

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

#### 🍎 macOS

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

> **Note:** If `python3` is not found, install it via Homebrew: `brew install python`

#### 🪟 Windows (PowerShell)

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

> **Note:** If you get a script execution error, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` first.

#### 🪟 Windows (CMD)

```cmd
cd backend
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

### Step 3: Open the frontend

Open `pnb_ui.html` in any browser — Chrome, Firefox, Edge, Safari.

- **Linux:** `xdg-open pnb_ui.html`
- **macOS:** `open pnb_ui.html`
- **Windows:** Double-click the file, or `start pnb_ui.html`

### Step 4: Scan

Type any domain (e.g. `google.com`, `pnbindia.in`, `amazon.com`) and click **Scan target**.

---

## Verify It's Working

Open http://localhost:8000/health in your browser. You should see:
```json
{"status": "ok", "service": "quantum-proof-scanner"}
```

---

## Features

- **Real TLS scanning** — live handshake via `ssl` + `socket` + `cryptography`
- **CBOM** — Cryptographic Bill of Materials (CERT-In Annexure-A schema)
- **Risk scoring** — weighted 8-factor model (0–100)
- **PQC readiness** — detects ML-KEM, ML-DSA, Falcon, SLH-DSA
- **CRQC simulation** — Shor's & Grover's attack modelling
- **Migration roadmap** — prioritised recommendations with NIST standards
- **Raw evidence panel** — view actual scan data JSON

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML / CSS / JavaScript |
| Backend | Python FastAPI |
| Scanner | `ssl`, `socket`, `cryptography` |
| Server | Uvicorn |

## API

```
GET /scan?domain=example.com    → Full scan results (JSON)
GET /health                     → Health check
```
