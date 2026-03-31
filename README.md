# Quantum-Proof Systems Scanner

Real-time TLS cryptographic assessment platform — CBOM generation, PQC readiness scoring, CRQC attack simulation, and migration roadmap.

**PSB Hackathon 2026**

## Quick Start

```bash
# 1. Set up Python environment
cd backend
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the backend
uvicorn api:app --host 0.0.0.0 --port 8000
```

Then open `pnb_ui.html` in your browser and scan any domain.

## Features

- **Real TLS scanning** — live handshake via `ssl` + `socket` + `cryptography`
- **CBOM** — Cryptographic Bill of Materials (CERT-In Annexure-A schema)
- **Risk scoring** — weighted 8-factor model (0–100)
- **PQC readiness** — detects ML-KEM, ML-DSA, Falcon, SLH-DSA
- **CRQC simulation** — Shor's & Grover's attack modelling
- **Migration roadmap** — prioritised recommendations with NIST standards

## Tech Stack

- **Frontend:** HTML/CSS/JS (standalone file)
- **Backend:** Python FastAPI
- **Scanner:** `ssl`, `socket`, `cryptography`
