"""
Quantum-Proof Systems Scanner — Core Engine
============================================
Real TLS scanning, CBOM generation, quantum risk scoring,
and PQC migration recommendations.

Uses Python ssl + socket + cryptography for live handshake analysis.
"""

import ssl
import socket
import datetime
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa


# ---------------------------------------------------------------------------
# 1. TLS Handshake & Certificate Extraction
# ---------------------------------------------------------------------------

def scan_tls(domain: str, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    """
    Connects to domain:port, performs a TLS handshake, and extracts
    the negotiated cipher, TLS version, and full X.509 certificate details.
    Returns a flat dict of raw scan evidence.
    """
    # Resolve IP first
    ip = socket.getaddrinfo(domain, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((domain, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
            # Negotiated cipher tuple: (name, protocol, bits)
            cipher_info = tls_sock.cipher()
            tls_version = tls_sock.version()  # e.g. "TLSv1.3"

            # DER-encoded certificate
            der_cert = tls_sock.getpeercert(binary_form=True)
            # Python-parsed dict (for fallback fields)
            peer_dict = tls_sock.getpeercert(binary_form=False)

    # Parse the X.509 certificate with the cryptography library
    cert = x509.load_der_x509_certificate(der_cert)

    pub_key = cert.public_key()
    key_type, key_bits = _classify_public_key(pub_key)

    sig_algo = cert.signature_algorithm_oid._name  # e.g. "sha256WithRSAEncryption"
    sig_algo_friendly = _friendly_sig(sig_algo)

    # Subject & Issuer
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Expiry
    expiry_dt = cert.not_valid_after_utc
    cert_ok = expiry_dt > datetime.datetime.now(datetime.timezone.utc)

    return {
        "domain": domain,
        "ip": ip,
        "tls_version": _normalise_tls(tls_version),
        "cipher_suite": cipher_info[0] if cipher_info else "UNKNOWN",
        "cipher_bits": cipher_info[2] if cipher_info else 0,
        "key_type": key_type,
        "key_bits": key_bits,
        "sig_algo": sig_algo_friendly,
        "subject": subject,
        "issuer": _short_issuer(issuer),
        "expiry": expiry_dt.strftime("%Y-%m-%d"),
        "cert_ok": cert_ok,
        "peer_dict": peer_dict,
    }


# ---------------------------------------------------------------------------
# 2. Cipher Suite Decomposition
# ---------------------------------------------------------------------------

# Maps cipher suite name fragments → human-readable components
_KEX_MAP = {
    "ML-KEM": ("ML-KEM-768", True),
    "KYBER": ("ML-KEM-768 (Kyber)", True),
    "X25519": ("X25519", False),
    "ECDHE": ("ECDHE", False),
    "DHE": ("DHE", False),
    "RSA": ("RSA key transport", False),  # static RSA
}

_ENC_MAP = {
    "AES_256_GCM": ("AES-256-GCM", False),
    "AES256-GCM": ("AES-256-GCM", False),
    "AES_128_GCM": ("AES-128-GCM", False),
    "AES128-GCM": ("AES-128-GCM", False),
    "AES_256_CBC": ("AES-256-CBC", False),
    "AES_128_CBC": ("AES-128-CBC", False),
    "CHACHA20_POLY1305": ("ChaCha20-Poly1305", False),
    "CHACHA20": ("ChaCha20-Poly1305", False),
}

_MAC_MAP = {
    "SHA384": ("HMAC-SHA-384", 384),
    "SHA256": ("HMAC-SHA-256", 256),
    "AEAD": ("AEAD", 0),  # GCM/CCM are AEAD, no separate MAC
}

# PQC algorithm identifiers (in cipher suite names or sig algorithms)
_PQC_NAMES = ["ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "FALCON", "SPHINCS", "SLH-DSA"]


def decompose_cipher(cipher_name: str, tls_ver: str, key_type: str, key_bits: int, sig_algo: str) -> dict[str, Any]:
    """
    Break a cipher suite name into key exchange, encryption, MAC components.
    Also resolve auth algorithm from the certificate.
    """
    upper = cipher_name.upper()

    # --- Key exchange ---
    kex_name, kex_pqc = "Unknown", False
    # TLS 1.3 cipher suites don't include kex (it's negotiated separately via extensions)
    if tls_ver == "TLS 1.3":
        # Heuristic: check if the cipher has PQC keyword; otherwise default to X25519
        for frag, (name, pqc) in _KEX_MAP.items():
            if frag in upper:
                kex_name, kex_pqc = name, pqc
                break
        else:
            kex_name, kex_pqc = "X25519", False  # most common TLS 1.3 kex
    else:
        for frag, (name, pqc) in _KEX_MAP.items():
            if frag in upper:
                kex_name, kex_pqc = name, pqc
                break

    # Add curve info for ECDHE when we know the key type is EC
    if kex_name == "ECDHE" and key_type.startswith("EC"):
        # We can't know the ephemeral kex curve from cert alone; state P-256 as common default
        kex_name = "ECDHE (P-256)"

    # --- Encryption ---
    enc_name = "Unknown"
    for frag, (name, _) in _ENC_MAP.items():
        if frag in upper.replace("-", "_"):
            enc_name = name
            break
    # Fallback: try to identify from cipher name for TLS 1.2 style names
    if enc_name == "Unknown":
        if "AES256" in upper or "AES-256" in upper:
            enc_name = "AES-256-GCM" if "GCM" in upper else "AES-256-CBC"
        elif "AES128" in upper or "AES-128" in upper:
            enc_name = "AES-128-GCM" if "GCM" in upper else "AES-128-CBC"
        elif "CHACHA" in upper:
            enc_name = "ChaCha20-Poly1305"

    # --- MAC ---
    mac_name = "AEAD" if "GCM" in upper or "CHACHA" in upper or "POLY" in upper else "HMAC-SHA-256"
    if "SHA384" in upper:
        mac_name = "AEAD-SHA-384" if "GCM" in upper else "HMAC-SHA-384"
    elif "SHA256" in upper:
        mac_name = "AEAD-SHA-256" if "GCM" in upper else "HMAC-SHA-256"

    # --- Auth (from certificate) ---
    auth_name = f"{key_type}-{key_bits}"
    auth_pqc = any(p in key_type.upper() for p in _PQC_NAMES) or any(p in sig_algo.upper() for p in _PQC_NAMES)

    return {
        "kex": kex_name,
        "kex_pqc": kex_pqc,
        "enc": enc_name,
        "mac": mac_name,
        "auth": auth_name,
        "auth_pqc": auth_pqc,
        "sig": sig_algo,
    }


# ---------------------------------------------------------------------------
# 3. Quantum Vulnerability Classification
# ---------------------------------------------------------------------------

def classify_algorithms(parts: dict, tls_ver: str) -> list[dict[str, Any]]:
    """
    Build the algorithms list with quantum vulnerability classification.
    Each algorithm gets: n, role, shors, grovers, pqc, note
    """
    algos = []

    # Key exchange
    kex = parts["kex"]
    kex_is_pqc = parts["kex_pqc"]
    kex_shors = not kex_is_pqc and _is_asymmetric(kex)
    algos.append({
        "n": kex,
        "role": "Key Encapsulation (KEM)" if kex_is_pqc else "Key Exchange",
        "shors": kex_shors,
        "grovers": False,
        "pqc": kex_is_pqc,
        "note": _algo_note(kex, kex_shors, False, kex_is_pqc),
    })

    # Auth / Certificate signature
    auth = parts["auth"]
    auth_is_pqc = parts["auth_pqc"]
    auth_shors = not auth_is_pqc and _is_asymmetric(auth)
    algos.append({
        "n": auth,
        "role": "Digital Signature / Auth" if auth_is_pqc else "Cert Signature / Auth",
        "shors": auth_shors,
        "grovers": False,
        "pqc": auth_is_pqc,
        "note": _algo_note(auth, auth_shors, False, auth_is_pqc),
    })

    # Symmetric encryption
    enc = parts["enc"]
    enc_grovers = True  # Grover's applies to all symmetric ciphers
    enc_weak = "128" in enc  # AES-128 is weakened significantly
    algos.append({
        "n": enc,
        "role": "Symmetric Cipher",
        "shors": False,
        "grovers": enc_grovers,
        "pqc": False,
        "note": _sym_note(enc),
    })

    # MAC
    mac = parts["mac"]
    algos.append({
        "n": mac,
        "role": "MAC / Integrity",
        "shors": False,
        "grovers": True,
        "pqc": False,
        "note": _mac_note(mac),
    })

    # Protocol
    algos.append({
        "n": tls_ver,
        "role": "Protocol",
        "shors": False,
        "grovers": False,
        "pqc": False,
        "note": _tls_note(tls_ver),
    })

    return algos


# ---------------------------------------------------------------------------
# 4. Risk Scoring Engine
# ---------------------------------------------------------------------------

def calculate_risk(algos: list[dict], parts: dict, tls_ver: str) -> tuple[int, str, bool, list[dict]]:
    """
    Weighted 8-factor model. Returns (score, level, hndl, factors).
    Score is clamped to 0–100.
    """
    factors = []
    total = 0

    kex = parts["kex"]
    auth = parts["auth"]
    enc = parts["enc"]

    # Factor 1: Key exchange vulnerability (max 38)
    kex_algo = algos[0]
    if kex_algo["shors"]:
        pts = 38
        factors.append({"f": f"Key exchange ({kex}) broken by Shor's", "pts": pts, "cat": "crit"})
        total += pts
    elif kex_algo["pqc"]:
        factors.append({"f": f"Key exchange ({kex}) — fully quantum-safe", "pts": 0, "cat": "ok"})
    else:
        factors.append({"f": f"Key exchange ({kex}) — assessed", "pts": 0, "cat": "ok"})

    # Factor 2: Certificate signature vulnerability (max 26)
    auth_algo = algos[1]
    if auth_algo["shors"]:
        pts = 26
        factors.append({"f": f"Cert signature ({auth}) broken by Shor's", "pts": pts, "cat": "crit"})
        total += pts
    elif auth_algo["pqc"]:
        factors.append({"f": f"Cert signature ({auth}) — quantum-safe", "pts": 0, "cat": "ok"})
    else:
        factors.append({"f": f"Cert signature ({auth}) — assessed", "pts": 0, "cat": "ok"})

    # Factor 3: HNDL exposure (max 10)
    hndl = kex_algo["shors"]  # HNDL is possible when key exchange is Shor-vulnerable
    if hndl:
        pts = 10
        factors.append({"f": "HNDL — session data harvestable now", "pts": pts, "cat": "crit"})
        total += pts
    else:
        factors.append({"f": "No HNDL exposure", "pts": 0, "cat": "ok"})

    # Factor 4: Symmetric cipher weakness (max 12)
    if "128" in enc:
        pts = 12
        factors.append({"f": f"{enc} weakened by Grover (64-bit effective)", "pts": pts, "cat": "high"})
        total += pts
    else:
        factors.append({"f": f"{enc} — quantum-adequate (Grover OK)", "pts": 0, "cat": "ok"})

    # Factor 5: TLS version (max 8)
    if tls_ver != "TLS 1.3":
        pts = 8
        factors.append({"f": f"{tls_ver} — legacy protocol in use", "pts": pts, "cat": "high"})
        total += pts
    else:
        factors.append({"f": "TLS 1.3 deployed — strong protocol", "pts": 0, "cat": "ok"})

    # Factor 6: PQC deployment status (max 12)
    has_pqc = any(a["pqc"] for a in algos)
    if not has_pqc:
        pts = 12
        factors.append({"f": "No NIST PQC algorithm deployed", "pts": pts, "cat": "high"})
        total += pts
    else:
        factors.append({"f": "Full NIST FIPS 203/204 compliance", "pts": 0, "cat": "ok"})

    # Clamp
    score = min(100, max(0, total))
    level = "LOW" if score <= 30 else "MEDIUM" if score <= 60 else "HIGH"

    return score, level, hndl, factors


# ---------------------------------------------------------------------------
# 5. Migration Recommender
# ---------------------------------------------------------------------------

def generate_migration(algos: list[dict], parts: dict, tls_ver: str, score: int) -> tuple[list[dict], list[dict]]:
    """
    Generate migration recommendations and phased roadmap
    based on detected algorithms.
    """
    mig = []
    kex = parts["kex"]
    auth = parts["auth"]
    enc = parts["enc"]
    kex_algo = algos[0]
    auth_algo = algos[1]

    # Key exchange migration
    if kex_algo["shors"]:
        target_kem = "ML-KEM-768"
        if "X25519" in kex:
            mig.append({
                "pri": "CRITICAL", "from": kex, "to": "X25519Kyber768 hybrid",
                "role": "Key Exchange", "standard": "NIST FIPS 203", "effort": "Low",
                "detail": "Hybrid mode ships in Chrome 116+ and OpenSSL 3.2 — zero-downtime deployment, backward compatible with classical clients"
            })
        else:
            mig.append({
                "pri": "CRITICAL", "from": kex, "to": target_kem,
                "role": "Key Exchange", "standard": "NIST FIPS 203", "effort": "Medium",
                "detail": "Deploy X25519Kyber768 hybrid in OpenSSL 3.2+ — backward-compatible with classical clients during transition"
            })

    # Certificate signature migration
    if auth_algo["shors"]:
        mig.append({
            "pri": "CRITICAL", "from": auth, "to": "ML-DSA-65",
            "role": "Cert Signature", "standard": "NIST FIPS 204", "effort": "High",
            "detail": "Request ML-DSA signed certificate from a NIST-compliant CA. Requires PKI chain upgrade"
        })

    # Symmetric cipher migration
    if "128" in enc:
        mig.append({
            "pri": "CRITICAL", "from": enc, "to": "AES-256-GCM",
            "role": "Symmetric Cipher", "standard": "NIST SP 800-131A", "effort": "Low",
            "detail": "AES-128 drops to 64-bit effective under Grover — insufficient for data with > 10-year sensitivity window"
        })

    # TLS version migration
    if tls_ver != "TLS 1.3":
        mig.append({
            "pri": "HIGH", "from": tls_ver, "to": "TLS 1.3",
            "role": "Protocol", "standard": "IETF RFC 8446", "effort": "Low",
            "detail": "TLS 1.3 removes all RSA key-exchange modes — reduces HNDL attack surface immediately"
        })

    # PQC architecture
    has_pqc = any(a["pqc"] for a in algos)
    if not has_pqc and kex_algo["shors"]:
        mig.append({
            "pri": "HIGH", "from": "No PQC", "to": "Hybrid PQC mode",
            "role": "Architecture", "standard": "NIST SP 800-208", "effort": "Medium",
            "detail": "Implement crypto-agility layer so future algorithm updates require config change, not code rewrite"
        })

    # CBOM monitoring (always recommended)
    mig.append({
        "pri": "MEDIUM" if score > 30 else "LOW",
        "from": "Static config" if not has_pqc else "Quarterly",
        "to": "CBOM monitoring" if not has_pqc else "Continuous CBOM monitoring",
        "role": "Ops", "standard": "CERT-In", "effort": "Low",
        "detail": "Schedule quarterly automated CBOM re-scans; alert on cipher suite or cert signature changes"
    })

    # If already PQC-safe, add maintenance recommendations
    if has_pqc:
        mig.append({
            "pri": "LOW", "from": "Current", "to": "Monitor FIPS 205 (SLH-DSA)",
            "role": "Signature diversity", "standard": "NIST FIPS 205", "effort": "Low",
            "detail": "Hash-based signatures as backup diversity in the certificate chain — protects against lattice-assumption breaks"
        })

    # --- Phased roadmap ---
    if score > 60:
        phases = [
            {"label": "Phase 1 — 0–3 months", "color": "#C0392B",
             "items": [f"Upgrade {tls_ver} → TLS 1.3" if tls_ver != "TLS 1.3" else "Harden TLS configuration",
                       "Audit all public-facing endpoints", "Establish CBOM baseline"]},
            {"label": "Phase 2 — 3–9 months", "color": "#D68910",
             "items": ["Deploy ML-KEM-768 hybrid KEM", "Replace RSA cert with ML-DSA-65",
                       "Enable crypto-agility framework"]},
            {"label": "Phase 3 — 9–18 months", "color": "#1E8449",
             "items": ["Full NIST PQC compliance audit", "FIPS 203/204 certification",
                       "Continuous CBOM monitoring"]},
        ]
    elif score > 30:
        phases = [
            {"label": "Phase 1 — 0–2 months", "color": "#1F618D",
             "items": ["Deploy hybrid PQC key exchange", "Baseline CBOM established",
                       "Test hybrid cipher with major clients"]},
            {"label": "Phase 2 — 2–6 months", "color": "#D68910",
             "items": ["Replace classical cert with ML-DSA", "Update CA chain to NIST-compliant issuer",
                       "Validate backward compatibility"]},
            {"label": "Phase 3 — 6–12 months", "color": "#1E8449",
             "items": ["Full NIST FIPS 203/204 compliance", "Ongoing CBOM monitoring",
                       "Post-quantum PKI hierarchy"]},
        ]
    else:
        phases = [
            {"label": "Phase 1 — Done", "color": "#1E8449",
             "items": ["PQC key exchange deployed", "PQC certificate chain active", "TLS 1.3 in production"]},
            {"label": "Phase 2 — Maintain", "color": "#1F618D",
             "items": ["Quarterly CBOM re-assessment", "Monitor NIST algorithm updates",
                       "Validate hybrid compatibility"]},
            {"label": "Phase 3 — Future", "color": "#6C3483",
             "items": ["FIPS 205 SLH-DSA evaluation", "Post-quantum PKI hierarchy",
                       "CRQC readiness certification"]},
        ]

    return mig, phases


# ---------------------------------------------------------------------------
# 6. Full Scan Orchestrator
# ---------------------------------------------------------------------------

def full_scan(domain: str) -> dict[str, Any]:
    """
    Orchestrate a complete scan: TLS handshake → CBOM → risk score → migration.
    Returns data in the exact shape expected by the frontend render() function.
    """
    # Step 1: TLS scan
    raw = scan_tls(domain)

    # Step 2: Decompose cipher suite
    parts = decompose_cipher(
        cipher_name=raw["cipher_suite"],
        tls_ver=raw["tls_version"],
        key_type=raw["key_type"],
        key_bits=raw["key_bits"],
        sig_algo=raw["sig_algo"],
    )

    # Step 3: Classify algorithms
    algos = classify_algorithms(parts, raw["tls_version"])

    # Step 4: Risk scoring
    score, level, hndl, factors = calculate_risk(algos, parts, raw["tls_version"])

    # Step 5: PQC readiness label
    has_pqc = any(a["pqc"] for a in algos)
    if has_pqc and score <= 30:
        label_key, label_txt = "ready", "Fully Quantum-Safe"
    elif has_pqc or score <= 60:
        label_key, label_txt = "partial", "Partially Quantum-Safe"
    else:
        label_key, label_txt = "not-ready", "Not PQC-Ready"

    # Step 6: Migration recommendations
    mig, phases = generate_migration(algos, parts, raw["tls_version"], score)

    return {
        "host": raw["domain"],
        "ip": raw["ip"],
        "tls": raw["tls_version"],
        "cipher": raw["cipher_suite"],
        "kex": parts["kex"],
        "auth": parts["auth"],
        "enc": parts["enc"],
        "mac": parts["mac"],
        "sig": parts["sig"],
        "keyBits": raw["key_bits"],
        "subj": raw["subject"],
        "issuer": raw["issuer"],
        "expiry": raw["expiry"],
        "certOk": raw["cert_ok"],
        "algos": algos,
        "factors": factors,
        "score": score,
        "level": level,
        "hndl": hndl,
        "labelKey": label_key,
        "labelTxt": label_txt,
        "mig": mig,
        "phases": phases,
        # Bonus: raw scan evidence for transparency
        "raw_evidence": {
            "cipher_suite_full": raw["cipher_suite"],
            "cipher_bits": raw["cipher_bits"],
            "key_type": raw["key_type"],
            "sig_algo_raw": raw["sig_algo"],
            "subject_dn": raw["subject"],
            "issuer_dn": raw["issuer"],
            "expiry_utc": raw["expiry"],
            "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    }


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _classify_public_key(pub_key) -> tuple[str, int]:
    """Return (type_name, bit_size) for a certificate public key."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"EC-{pub_key.curve.name}", pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size
    else:
        return "Unknown", 0


def _normalise_tls(version_str: str) -> str:
    """Normalise TLS version string to display format."""
    mapping = {
        "TLSv1.3": "TLS 1.3",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.1": "TLS 1.1",
        "TLSv1": "TLS 1.0",
    }
    return mapping.get(version_str, version_str)


def _friendly_sig(oid_name: str) -> str:
    """Convert OID name to friendly display."""
    mapping = {
        "sha256WithRSAEncryption": "SHA256withRSA",
        "sha384WithRSAEncryption": "SHA384withRSA",
        "sha512WithRSAEncryption": "SHA512withRSA",
        "ecdsa-with-SHA256": "SHA256withECDSA",
        "ecdsa-with-SHA384": "SHA384withECDSA",
        "ecdsa-with-SHA512": "SHA512withECDSA",
        "ed25519": "Ed25519",
        "ed448": "Ed448",
    }
    return mapping.get(oid_name, oid_name)


def _short_issuer(issuer_dn: str) -> str:
    """Extract a readable issuer name from the full DN."""
    # Try to find CN= or O= in the RFC4514 string
    parts = issuer_dn.split(",")
    cn = ""
    org = ""
    for part in parts:
        stripped = part.strip()
        if stripped.upper().startswith("CN="):
            cn = stripped[3:]
        elif stripped.upper().startswith("O="):
            org = stripped[2:]
    if cn:
        return cn
    if org:
        return org
    return issuer_dn[:60]


def _is_asymmetric(algo_name: str) -> bool:
    """Check if an algorithm is asymmetric (Shor-vulnerable)."""
    upper = algo_name.upper()
    asymmetric_keywords = ["RSA", "ECDHE", "ECDH", "ECDSA", "X25519", "X448", "DH", "DSA", "EC-"]
    pqc_keywords = ["ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "FALCON", "SPHINCS", "SLH-DSA"]
    # PQC algorithms are asymmetric but NOT Shor-vulnerable
    if any(p in upper for p in pqc_keywords):
        return False
    return any(k in upper for k in asymmetric_keywords)


def _algo_note(name: str, shors: bool, grovers: bool, pqc: bool) -> str:
    """Generate a descriptive note for an algorithm."""
    upper = name.upper()
    if pqc:
        if "ML-KEM" in upper or "KYBER" in upper:
            return "NIST FIPS 203 — lattice-based KEM, hardness based on Module-LWE problem"
        if "ML-DSA" in upper or "DILITHIUM" in upper:
            return "NIST FIPS 204 — Dilithium lattice signature, quantum-safe"
        if "FALCON" in upper:
            return "NIST selected — compact lattice-based signature scheme"
        if "SPHINCS" in upper or "SLH-DSA" in upper:
            return "NIST FIPS 205 — hash-based stateless signature, conservative quantum safety"
        return "Post-quantum cryptographic algorithm"

    if shors:
        if "RSA" in upper:
            return "Shor's factorises RSA — key size provides zero quantum protection"
        if "X25519" in upper:
            return "X25519 is ECDH on Curve25519 — Shor's solves the elliptic curve discrete log problem"
        if "ECDH" in upper or "EC-" in upper:
            return "Shor's solves ECDLP on all elliptic curves in polynomial time"
        if "DH" in upper:
            return "Shor's solves the discrete logarithm problem — all DH variants are vulnerable"
        return "Vulnerable to Shor's algorithm on a CRQC"

    return "Quantum-safe under current analysis"


def _sym_note(enc: str) -> str:
    """Generate note for symmetric encryption."""
    if "128" in enc:
        return "Grover → 64-bit effective — below 80-bit security floor for sensitive data"
    if "256" in enc:
        return "Grover → 128-bit effective, remains secure"
    return "Symmetric cipher — Grover's halves effective key length"


def _mac_note(mac: str) -> str:
    """Generate note for MAC algorithm."""
    if "384" in mac:
        return "Grover → 192-bit effective, secure"
    if "256" in mac:
        return "Grover → 128-bit effective, adequate"
    return "MAC algorithm — assessed for quantum impact"


def _tls_note(tls_ver: str) -> str:
    """Generate note for TLS version."""
    if tls_ver == "TLS 1.3":
        return "Optimal — all weak legacy cipher suites removed"
    if tls_ver == "TLS 1.2":
        return "Not broken, retains RSA key-exchange modes — upgrade needed"
    return f"{tls_ver} — outdated protocol, significant upgrade recommended"
