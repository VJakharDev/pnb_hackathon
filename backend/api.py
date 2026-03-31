"""
Quantum-Proof Systems Scanner — FastAPI Server
================================================
Exposes a /scan endpoint that performs live TLS scanning
and returns structured results for the frontend dashboard.
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import scanner

app = FastAPI(
    title="Quantum-Proof Systems Scanner API",
    version="1.0.0",
    description="Real-time TLS cryptographic assessment, CBOM generation, and PQC readiness scoring",
)

# Allow frontend (served from file:// or any dev server) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/scan")
async def scan_domain(domain: str = Query(..., description="Domain to scan, e.g. google.com")):
    """
    Perform a full TLS scan on the given domain.
    Returns CBOM, risk score, algorithm analysis, and migration recommendations.
    """
    # Sanitise input — strip protocol prefixes and trailing slashes/paths
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split(":")[0]  # remove path and port

    if not domain or "." not in domain:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid domain: '{domain}'. Please provide a valid domain like example.com"}
        )

    try:
        result = scanner.full_scan(domain)
        return result
    except Exception as e:
        # Provide actionable error messages
        err_msg = str(e)
        if "getaddrinfo" in err_msg or "Name or service not known" in err_msg:
            detail = f"DNS resolution failed for '{domain}' — domain may not exist or DNS is unreachable"
        elif "timed out" in err_msg or "Connection timed out" in err_msg:
            detail = f"Connection timed out for '{domain}' — host may be down or blocking port 443"
        elif "Connection refused" in err_msg:
            detail = f"Connection refused by '{domain}' — port 443 may not be open"
        elif "CERTIFICATE_VERIFY_FAILED" in err_msg or "certificate verify failed" in err_msg:
            detail = f"TLS certificate verification failed for '{domain}' — {err_msg}"
        elif "SSL" in err_msg or "ssl" in err_msg:
            detail = f"TLS handshake error for '{domain}' — {err_msg}"
        else:
            detail = f"Scan failed for '{domain}' — {err_msg}"

        return JSONResponse(
            status_code=502,
            content={"error": detail}
        )


@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "service": "quantum-proof-scanner"}
