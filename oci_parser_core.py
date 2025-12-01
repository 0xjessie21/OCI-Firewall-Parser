#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core analyzer untuk OCI WAF JSON log:

- Deteksi pola serangan berbasis URI → MITRE ATT&CK Technique ID
- Mapping ke OWASP Top 10 kategori
- Ringkasan per teknik:
  {
    "T1190": {
        "count": 12,
        "uris": [...],
        "entries": [...],
    },
    ...
  }
"""

import re
from collections import defaultdict
from urllib.parse import urlparse

# ============================================================
#  MITRE URI PATTERNS (FALSE NEGATIVE / WAF BYPASS STYLE)
# ============================================================

MITRE_FALSE_NEGATIVE_URI_PATTERNS = {
    # RCE / exploit
    "T1059.004": r"(?i)shellshock|;\s*echo\s+shellshock|/cgi-bin/|User-Agent:.*\(\)\s*{",  # Shellshock
    "T1505.003": r"(?i)phpunit|eval-stdin\.php",
    "T1059.001": r"(?i)(cmd|command|exec|system|passthru|shell_exec)\s*=",
    "T1190": r"(?i)(\bUNION\b|\bSELECT\b|\bUPDATE\b|\bDELETE\b|\bINSERT\b).*(\bFROM\b|\bWHERE\b)|(\bOR\b\s+1=1)",

    # File disclosure / traversal / LFI/RFI
    "T1203": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|/etc/passwd|boot.ini|/windows/win.ini)",
    "T1592.004": r"(?i)\.env\b|/\.git\b|/config(\.php|\.json|\.ini)?\b|/backup\b|/dump\b|/db\b|phpinfo\.php",

    # Web shell / debugging
    "T1505": r"(?i)(wso\.php|r57\.php|c99\.php|webshell)",
    "T1595.003": r"(?i)XDEBUG_SESSION_START=phpstorm",

    # XSS
    "T1055": r"(?i)(<script|%3Cscript%3E|onerror=|onload=|javascript:)",

    # Brute force / auth
    "T1110.001": r"(?i)/login|/signin|/mtos/login/login\.mtos|/wp-login\.php|/xmlrpc\.php",

    # Recon / scanning
    "T1595.001": r"(?i)/admin\b|/panel\b|/dashboard\b|/config\b|/test\b|/dev\b|/setup\b",
    "T1595.002": r"(?i)/login\b|/signin\b|/auth\b",

    # Sensitive file listing / misconfig
    "T1083": r"(?i)index\.of/|dirlisting|directory listing",
}

# ============================================================
#  MITRE ATT&CK TYPE LABELS (untuk tabel / dashboard)
# ============================================================

MITRE_ATTACK_TYPES = {
    "T1190": "Exploit Public-Facing Application (SQLi / RFI / LFI)",
    "T1203": "Directory Traversal / File Disclosure",
    "T1059.004": "Shellshock Bash RCE",
    "T1505.003": "PHPUnit RCE",
    "T1505": "Web Shell / Malicious Web Component",
    "T1059.001": "Command Injection",
    "T1055": "Cross-Site Scripting (XSS)",
    "T1110.001": "Bruteforce / Credential Stuffing",
    "T1595.001": "Web Directory Brute Force / Recon",
    "T1595.002": "Login Page Discovery",
    "T1595.003": "Debug Interface Scanning (Xdebug / PhpStorm)",
    "T1592.004": "Sensitive File Enumeration (.env / .git / config)",
    "T1083": "File & Directory Discovery",
}

# ============================================================
#  OWASP TOP 10 MAPPING
# ============================================================

OWASP_TOP10_MAP = {
    # A01 Broken Access Control
    "T1592.004": "A01 Broken Access Control (Sensitive Files)",
    "T1203": "A01 Broken Access Control (Directory Traversal)",
    "T1083": "A01 Broken Access Control (Directory Listing)",
    "T1595.001": "A01 Broken Access Control (Recon / Admin Pages)",

    # A02 Cryptographic Failures – (bisa diperluas jika ada pattern cert/crypto)
    # ...

    # A03 Injection
    "T1190": "A03 Injection (SQLi / Exploit App)",
    "T1059.001": "A03 Injection (Command Injection)",
    "T1059.004": "A03 Injection (RCE / Shellshock)",
    "T1505.003": "A03 Injection (PHPUnit RCE)",
    "T1055": "A03 Injection (XSS)",

    # A07 Identification and Authentication Failures
    "T1110.001": "A07 Authentication Failure (Bruteforce)",
    "T1595.002": "A07 Authentication Failure (Login Page Discovery)",

    # A05 Security Misconfiguration / A06 Vulnerable Components
    "T1505": "A05 Security Misconfiguration (Web Shell / Web Component)",

    # A08 Software and Data Integrity Failures
    # A09 Security Logging and Monitoring Failures
    # (bisa di-expand kemudian)
}

# ============================================================
#  HOSTNAME → IDENTITY (untuk dashboard multi-tenant)
# ============================================================

HOSTNAME_IDENTITY_MAP = {
    # Contoh dari requirement awal
    "tos-nusantara.pelindo.co.id": "Terminal Operating System Nusantara Cluster 2 - Palapa",
    "praya.pelindo.co.id": "Terminal Operating System Nusantara Cluster 2 - Praya",
    "parama.pelindo.co.id": "Terminal Operating System Nusantara Parama",
    "phinnisi.pelindo.co.id": "Vessel Management System",
    "ptosc.pelindo.co.id": "Pelindo Terminal Operating System Car",
    "ptosr.pelindo.co.id": "Pelindo Terminal Operating System Roro",

    # Hostname yang muncul di sampel Anda:
    "tos-nusantara.ilcs.co.id": "Terminal Operating System Nusantara (ILCS)",
}

# ============================================================
#  ANALYZER: dari list entries → summary per MITRE ID
# ============================================================

def _get_uri(entry: dict) -> str:
    """
    Ambil URI dari berbagai kemungkinan field.
    OCI WAF: 'URI'
    """
    if "URI" in entry and entry["URI"]:
        return str(entry["URI"])
    if "uri" in entry and entry["uri"]:
        return str(entry["uri"])
    # fallback dari request line kalau ada
    req = entry.get("request") or entry.get("Request")
    if isinstance(req, str):
        # mis: "GET /path HTTP/1.1"
        parts = req.split()
        if len(parts) >= 2:
            return parts[1]
    return ""


def analyze_uris(entries: list[dict]) -> dict:
    """
    Menganalisis list log entries (JSON) dan mengembalikan summary:
    {
      "T1190": {
          "count": 10,
          "uris": [...],
          "entries": [...],
      },
      ...
    }
    """
    summary = defaultdict(lambda: {"count": 0, "uris": [], "entries": []})

    for e in entries:
        uri = _get_uri(e)
        if not uri:
            continue

        for mitre_id, pattern in MITRE_FALSE_NEGATIVE_URI_PATTERNS.items():
            try:
                if re.search(pattern, uri, re.IGNORECASE):
                    summary[mitre_id]["count"] += 1
                    if uri not in summary[mitre_id]["uris"]:
                        summary[mitre_id]["uris"].append(uri)
                    summary[mitre_id]["entries"].append(e)
            except re.error:
                # kalau regex invalid, jangan sampai script mati
                continue

    return summary
