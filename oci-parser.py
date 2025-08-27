import json
import argparse
import os
import re
import time
from collections import defaultdict, Counter
import functools
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from taxii2client.v20 import Server
from stix2 import Filter

console = Console()

PROXIES = {
    "http": os.environ.get("HTTP_PROXY"),
    "https": os.environ.get("HTTPS_PROXY")
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("ee09cab9-e48f-48b3-9815-604f951bdef1")

# =========================
#  REGEX (deteksi teknik)
# =========================
MITRE_FALSE_NEGATIVE_URI_PATTERNS = {
    "T1505.003": r"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php",
    "T1059.004": r"User-Agent:.*\(\) { :; };",  # Shellshock
    "T1595.001": r"/admin|/login|/wp-login\.php|/panel|/dashboard|/config|/setup|/dev|/test",
    "T1592.004": r"/\.git|/\.env|/config\.php|/config\.json|/backup|/dump|/db|/phpinfo\.php",
    "T1210": r"/vpn|/remote|/ssl-vpn|/global-protect|/clientless",
    "T1059.001": r"(cmd|command|exec|system)=.*",      # command injection
    "T1203": r"(?:\.\./|\.\.\\)",                      # directory traversal
    "T1190": r"(?:select|union|from|where)=.*",        # SQL injection
    "T1055": r"<script>|onerror=|javascript:",         # XSS
    "T1110.003": r"/wp-login\.php|/xmlrpc\.php",       # WP brute force
}

# Nama teknik (untuk tabel)
MITRE_ATTACK_TYPES = {
    "T1190": "Exploit Public-Facing Application (SQL Injection, File Inclusion)",
    "T1203": "Directory Traversal (File Disclosure)",
    "T1059.004": "Shellshock Bash Remote Code Execution (CVE-2014-6271)",
    "T1505.003": "PHPUnit Remote Code Execution",
    "T1059.001": "Command Injection",
    "T1055": "Cross Site Scripting (XSS)",
    "T1110.003": "WordPress Admin Brute Force Attack",
    "T1552.001": "Credential Dump (.env)",
    "T1552.002": "Git Exposure",
    "T1592.004": "Gather Victim Host Information: Web Directory Structure",
    "T1595": "Network Service Scanning",
    "T1595.001": "Web Directory Brute Force",
    "T1595.002": "Login Page Discovery",
    "T1040": "Network Sniffing",
    "T1083": "File and Directory Discovery",
    "T1110.001": "Generic Login Bruteforce Attempt"
}

# =========================
#  SEVERITY utils
# =========================
SEVERITY_RANK = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def sev_index(level: str) -> int:
    return SEVERITY_RANK.index(level.upper()) if level and level.upper() in SEVERITY_RANK else 0

def bump_severity(level: str, steps: int = 1) -> str:
    return SEVERITY_RANK[min(len(SEVERITY_RANK)-1, sev_index(level) + steps)]

def max_severity(a: str, b: str) -> str:
    return a if sev_index(a) >= sev_index(b) else b

def get_severity_style(severity: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "cyan"
    }.get(severity.upper(), "white")

# =========================
#  Dynamic baseline (fallback)
# =========================
# Hardcode baseline per teknik (aman untuk fallback & profile "dynamic")
TECHNIQUE_HARDCODE_BASE = {
    # RCE / eksploit publik
    "T1059.004": "CRITICAL",   # Shellshock
    "T1505.003": "CRITICAL",   # PHPUnit RCE
    "T1190":     "CRITICAL",   # SQLi / Exploit Public-Facing App
    "T1203":     "HIGH",       # Directory Traversal (file disclosure)
    "T1210":     "HIGH",       # Exploitation of Remote Services

    # Credential/secret exposure
    "T1552.001": "CRITICAL",   # .env
    "T1552.002": "HIGH",       # Git exposure
    "T1003":     "HIGH",       # Credential Dumping

    # Brute force / scanning / discovery baseline
    "T1110.001": "MEDIUM",
    "T1110.003": "MEDIUM",     # WordPress brute force
    "T1595":     "LOW",
    "T1595.001": "LOW",
    "T1595.002": "LOW",
    "T1592.004": "LOW",
    "T1083":     "MEDIUM",
    "T1040":     "HIGH",
    "T1055":     "MEDIUM",
    "T1566":     "INFO",
}

# Baseline severity by ATT&CK tactics (untuk fallback jika tidak ada hardcode)
TACTIC_BASELINE = {
    "initial-access":       "HIGH",
    "execution":            "HIGH",
    "persistence":          "MEDIUM",
    "privilege-escalation": "HIGH",
    "defense-evasion":      "MEDIUM",
    "credential-access":    "HIGH",
    "discovery":            "LOW",
    "lateral-movement":     "HIGH",
    "collection":           "MEDIUM",
    "command-and-control":  "HIGH",
    "exfiltration":         "HIGH",
    "impact":               "CRITICAL",
    "reconnaissance":       "INFO",
    "resource-development": "INFO",
}

# Host penting → bias eskalasi (fallback default kalau mapping tidak ada)
CRITICAL_HOST_KEYWORDS_FALLBACK = [
    "terminal operating system", "tos", "vessel management", "roro"
]

HOSTNAME_IDENTITY_MAP = {
    "tos-nusantara.pelindo.co.id": "Terminal Operating System Nusantara Cluster 2 - Palapa",
    "praya.pelindo.co.id": "Terminal Operating System Nusantara Cluster 2 - Praya",
    "parama.pelindo.co.id": "Terminal Operating System Nusantara Parama",
    "phinnisi.pelindo.co.id": "Vessel Management System",
    "ptosc.pelindo.co.id": "Pelindo Terminal Operating System Car",
    "ptosr.pelindo.co.id": "Pelindo Terminal Operating System Roro",
}

# =========================
#  CVSS (NVD)
# =========================
def _requests_get(url, params):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return requests.get(url, params=params, headers=headers, timeout=20)

@functools.lru_cache(maxsize=512)
def fetch_cvss_from_nvd(cve_id: str) -> str | None:
    try:
        r = _requests_get(NVD_API, {"cveId": cve_id})
        if r.status_code != 200:
            return None
        data = r.json()
        vulns = data.get("vulnerabilities")
        if not vulns:
            return None
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                m = arr[0]
                sev = (m.get("cvssData") or m).get("baseSeverity")
                if sev:
                    return "INFO" if sev.upper() == "NONE" else sev.upper()
                score = (m.get("cvssData") or m).get("baseScore")
                if score is not None:
                    s = float(score)
                    if s == 0.0: return "INFO"
                    if s >= 9.0: return "CRITICAL"
                    if s >= 7.0: return "HIGH"
                    if s >= 4.0: return "MEDIUM"
                    return "LOW"
    except Exception:
        return None
    return None

# =========================
#  TAXII/STIX
# =========================
@functools.lru_cache(maxsize=128)
def get_mitre_technique_by_id_lazy(mitre_id: str) -> dict:
    try:
        server = Server("https://cti-taxii.mitre.org/taxii/", proxies=PROXIES if any(PROXIES.values()) else None)
        api_root = server.api_roots[0]
        collection = next((c for c in api_root.collections if "enterprise" in c.title.lower()), None)
        if not collection:
            return {"name": "Unknown", "tactics": []}
        for obj in collection.query([Filter("type", "=", "attack-pattern")]):
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == mitre_id:
                    tactics = [kp["phase_name"].lower() for kp in obj.get("kill_chain_phases", [])
                               if kp.get("kill_chain_name") == "mitre-attack"]
                    return {"name": obj.get("name", "Unknown"), "tactics": tactics}
    except Exception:
        return {"name": "N/A", "tactics": []}
    return {"name": "N/A", "tactics": []}

# =========================
#  Mapping loader (by profile)
# =========================
def load_mapping_file(path, profile: str) -> dict:
    """
    Membaca severity_mapping.json dan mengembalikan section sesuai profile:
    - jika file berisi { "acunetix": {...}, "cvss": {...} }, maka pilih mapping = data[profile]
    - jika file berisi flat mapping (tanpa section), kembalikan seluruh isi (legacy support)
    - jika file tidak ada/invalid, kembalikan {}
    """
    if not path:
        return {}
    if not os.path.exists(path):
        console.print(f"[red]Mapping file tidak ditemukan:[/red] {path}")
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and profile in data and isinstance(data[profile], dict):
            return data[profile]  # ambil section sesuai profile
        return data if isinstance(data, dict) else {}
    except Exception as e:
        console.print(f"[red]Gagal baca mapping file:[/red] {e}")
        return {}

# =========================
#  Severity baseline chooser
# =========================
def dynamic_fallback_severity(mitre_id: str) -> str:
    """Fallback dynamic: hardcode per teknik → kalau tidak ada, pakai baseline taktik ATT&CK dari STIX."""
    # 1) Hardcode per teknik
    if mitre_id in TECHNIQUE_HARDCODE_BASE:
        return TECHNIQUE_HARDCODE_BASE[mitre_id]

    # 2) Baseline dari taktik ATT&CK
    stix = get_mitre_technique_by_id_lazy(mitre_id)
    tactics = stix.get("tactics", [])
    base = "INFO"
    for t in tactics:
        base = max_severity(base, TACTIC_BASELINE.get(t, "INFO"))
    return base

def baseline_severity_for(mitre_id: str, identity: str, profile: str, entry: dict | None, mapping: dict) -> str:
    """
    Urutan keputusan:
    1) profile == cvss dan ada CVE → pakai NVD CVSS (baseSeverity)
    2) mapping.mitre_overrides → pakai override
    3) mapping.mitre_to_category + mapping.category_to_severity → pakai baseline
    4) Fallback dynamic (hardcode → STIX tactics)
    """
    profile = (profile or "dynamic").lower()

    # 1) CVSS based
    if profile == "cvss" and entry:
        cve_id = entry.get("cve_id") or entry.get("CVE") or entry.get("cve")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            sev = fetch_cvss_from_nvd(cve_id.upper())
            if sev:
                return sev

    # 2) overrides dari mapping (jika ada)
    mitre_overrides = (mapping or {}).get("mitre_overrides", {})
    if mitre_id in mitre_overrides:
        return mitre_overrides[mitre_id]

    # 3) category baseline dari mapping (jika ada)
    cat = (mapping or {}).get("mitre_to_category", {}).get(mitre_id)
    if cat:
        sev = (mapping or {}).get("category_to_severity", {}).get(cat)
        if sev:
            return sev

    # 4) fallback dynamic always available
    return dynamic_fallback_severity(mitre_id)

def compute_severity(mitre_id: str, data: dict, identity: str, profile: str, sample_entry: dict | None, mapping: dict) -> str:
    count = int(data.get("count", 0))
    requests = int(data.get("requests", 0))
    sev = baseline_severity_for(mitre_id, identity, profile, sample_entry, mapping).upper()

    # thresholds (bisa diset di mapping.escalation; kalau tidak ada → default)
    esc = (mapping or {}).get("escalation", {})
    count_high = int(esc.get("count_high", 20))
    count_crit = int(esc.get("count_critical", 200))
    req_high = int(esc.get("requests_high", 1000))
    req_crit = int(esc.get("requests_critical", 10000))

    if requests > req_high or count > count_high:
        sev = bump_severity(sev, 1)
    if requests > req_crit or count > count_crit:
        sev = bump_severity(sev, 2)

    # asset bias (pakai keyword dari mapping kalau ada; kalau tidak ada, fallback default)
    critical_words = set((mapping or {}).get("critical_asset_keywords", [])) or set(CRITICAL_HOST_KEYWORDS_FALLBACK)
    if any(k in (identity or "").lower() for k in critical_words):
        sev = bump_severity(sev, 1)

    return sev

# =========================
#  Analyzer
# =========================
def analyze_uris(entries: list[dict]) -> dict:
    mitre_summary = defaultdict(lambda: {"count": 0, "requests": 0, "uris": [], "entries": []})
    for entry in entries:
        uri = entry.get("URI", "")
        request_count = int(entry.get("request_count", 0))
        for mitre_id, pattern in MITRE_FALSE_NEGATIVE_URI_PATTERNS.items():
            if re.search(pattern, uri, re.IGNORECASE):
                mitre_summary[mitre_id]["count"] += 1
                mitre_summary[mitre_id]["requests"] += request_count
                mitre_summary[mitre_id]["uris"].append(uri)
                mitre_summary[mitre_id]["entries"].append(entry)
    return mitre_summary

def fetch_all_techniques(mitre_ids):
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as progress:
        task = progress.add_task("🔍 Mengambil data teknik MITRE...", total=len(mitre_ids))
        for mid in mitre_ids:
            get_mitre_technique_by_id_lazy(mid)
            time.sleep(0.03)
            progress.advance(task)

# =========================
#  Hostname helpers
# =========================
FQDN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
BAD_HOST_TOKENS = {"feed", "unknown", "-", "localhost", "127.0.0.1", "0.0.0.0"}

def is_valid_hostname(h: str) -> bool:
    if not h: return False
    h = h.strip().lower()
    if h in BAD_HOST_TOKENS: return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h): return h not in {"127.0.0.1","0.0.0.0"}
    return bool(FQDN_REGEX.match(h))

def extract_hostname_from_entry(entry: dict) -> str | None:
    for key in ("Host Name (Server)", "hostname", "host", "Host", "server"):
        val = entry.get(key)
        if val and is_valid_hostname(str(val).strip()):
            return str(val).strip().lower()
    uri = entry.get("URI", "")
    if uri:
        try:
            parsed = urlparse(uri)
            if parsed.hostname and is_valid_hostname(parsed.hostname):
                return parsed.hostname.lower()
        except Exception:
            pass
    return None

def choose_best_hostname(entries: list[dict]) -> str:
    counts = Counter()
    for e in entries:
        h = extract_hostname_from_entry(e)
        if h and is_valid_hostname(h):
            counts[h] += 1
    if not counts:
        return "-"
    for h, _ in counts.most_common():
        if h in HOSTNAME_IDENTITY_MAP:
            return h
    return counts.most_common(1)[0][0]

# =========================
#  Output
# =========================
def display_summary(mitre_summary: dict, entries: list[dict], profile: str, mapping: dict):
    total_uri = sum(item["count"] for item in mitre_summary.values())
    total_requests = sum(item["requests"] for item in mitre_summary.values())
    unique_uris = len(set(uri for item in mitre_summary.values() for uri in item["uris"]))
    total_attacks = total_uri

    hostname = choose_best_hostname(entries)
    identity = HOSTNAME_IDENTITY_MAP.get(hostname, "Unknown")

    severity_counter = Counter()
    per_id_severity = {}
    for mitre_id, data in mitre_summary.items():
        example_entry = data["entries"][0] if data["entries"] else None
        sev = compute_severity(mitre_id, data, identity, profile, example_entry, mapping)
        per_id_severity[mitre_id] = sev
        severity_counter[sev] += data["count"]

    ordered = [lvl for lvl in reversed(SEVERITY_RANK) if lvl in severity_counter]
    severity_summary = "\n".join(
        f"• {level:<9}: [{get_severity_style(level)}]{severity_counter[level]}[/{get_severity_style(level)}]"
        for level in ordered
    )

    console.print(Panel.fit(
        f"[bold]🌐 Hostname :[/bold] [cyan]{hostname}[/cyan]\n"
        f"[bold]🏷️ Identity :[/bold] [green]{identity}[/green]\n"
        f"[bold]⚙️ Profile :[/bold] [magenta]{profile.upper()}[/magenta]",
        title="🎯 Target Informasi", border_style="magenta"
    ))

    console.print(Panel.fit(
        f"[bold cyan]📊 Ringkasan[/bold cyan]\n"
        f"• Total URI mencurigakan : [yellow]{total_uri}[/yellow]\n"
        f"• Total Requests         : [yellow]{total_requests}[/yellow]\n"
        f"• URI Unik               : [magenta]{unique_uris}[/magenta]\n"
        f"• Total Serangan         : [bold red]{total_attacks}[/bold red]\n"
        f"\n[bold]📍 Rekap Severity:[/bold]\n{severity_summary}",
        title="🛡️ False Negative Detected", border_style="cyan"
    ))

    table = Table(title="📌 Top 10 Teknik MITRE", show_lines=True)
    table.add_column("MITRE ID", style="bold red")
    table.add_column("Kategori", style="magenta")
    table.add_column("Severity")
    table.add_column("Jumlah URI", justify="right")
    table.add_column("Total Requests", justify="right")
    table.add_column("Contoh URI", style="green", overflow="fold")

    top_10 = sorted(mitre_summary.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    for mitre_id, data in top_10:
        sev = per_id_severity[mitre_id]
        severity_colored = Text(sev, style=get_severity_style(sev))
        table.add_row(
            mitre_id,
            MITRE_ATTACK_TYPES.get(mitre_id, "Unknown"),
            severity_colored,
            str(data["count"]),
            str(data["requests"]),
            ", ".join(data["uris"][:2])
        )

    console.print(table, width=console.width)

# =========================
#  I/O
# =========================
def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

# =========================
#  Main
# =========================
def main():
    parser = argparse.ArgumentParser(description="🔍 URI Summary + MITRE ATT&CK + Severity Mapping (per profile) ")
    parser.add_argument("json_file", help="Path ke file JSON dari OCI Firewall")
    parser.add_argument("--severity-profile", choices=["dynamic","acunetix","cvss"], default="dynamic",
                        help="Pilih baseline severity: dynamic/acunetix/cvss")
    parser.add_argument("--severity-mapping", help="Path ke severity_mapping.json (gabungan section)", default=None)
    args = parser.parse_args()

    # load mapping sesuai profile (boleh kosong → fallback dynamic aktif)
    mapping_raw = load_mapping_file(args.severity_mapping, args.severity_profile)
    mapping = mapping_raw if isinstance(mapping_raw, dict) else {}

    data = load_json(args.json_file)
    mitre_summary = analyze_uris(data)
    fetch_all_techniques(mitre_summary.keys())
    display_summary(mitre_summary, data, args.severity_profile, mapping)

if __name__ == "__main__":
    main()
