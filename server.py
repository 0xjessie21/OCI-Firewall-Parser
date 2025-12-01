#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import os
from datetime import datetime
from collections import Counter

from flask import Flask, jsonify, render_template
from flask_cors import CORS

# Core logic dari oci_parser_core.py
from oci_parser_core import (
    analyze_uris,
    OWASP_TOP10_MAP,
    MITRE_ATTACK_TYPES,
    HOSTNAME_IDENTITY_MAP,
)

# Severity automode engine
from severity_engine import SeverityEngine


# ============================================================
#  TENANT WHITELIST YANG DIDUKUNG DASHBOARD
# ============================================================
WHITELIST_TENANTS = {
    "tos-nusantara.pelindo.co.id",
    "praya.pelindo.co.id",
    "parama.pelindo.co.id",
    "phinnisi.pelindo.co.id",
    "ptosc.pelindo.co.id",
    "ptosr.pelindo.co.id",
}


# ============================================================
#  SEVERITY ENGINE (AUTOMODE ACUNETIX + CVSS + ESCALATION)
# ============================================================
SEVERITY_ENGINE = SeverityEngine(
    mapping_path="severity_mapping.json",
    mode="auto"
)


# ============================================================
#  LOG LOADER
# ============================================================
def resolve_log_files(spec: str) -> list[str]:
    """Resolve path file (file/dir/pattern) ke list JSON files."""
    if os.path.isfile(spec):
        return [spec]
    if "*" in spec:
        return sorted(glob.glob(spec))
    if os.path.isdir(spec):
        return sorted(glob.glob(os.path.join(spec, "*.json")))
    return []


def safe_load_json(path: str) -> list[dict]:
    """Load JSON list atau {"items": [...]}."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data["items"]
        return []
    except Exception as e:
        print(f"[ERROR] gagal membaca {path}: {e}")
        return []


def load_all_entries(log_files: list[str]) -> list[dict]:
    """Gabungkan semua log JSON ke dalam satu list entries."""
    entries = []
    for f in log_files:
        entries.extend(safe_load_json(f))
    return entries


# ============================================================
#  HELPERS
# ============================================================
def extract_hostname(e: dict) -> str | None:
    """Ambil hostname dari berbagai kemungkinan field."""
    if "Host Name (Server)" in e and e["Host Name (Server)"]:
        return str(e["Host Name (Server)"]).strip().lower()

    for key in ("hostname", "host", "server", "Host"):
        if key in e and e[key]:
            return str(e[key]).strip().lower()

    return None


def parse_oci_time(t: str | None) -> int | None:
    """Parse waktu OCI menjadi epoch timestamp."""
    if not t:
        return None

    formats = [
        "%b %d, %Y %I:%M:%S.%f %p",
        "%b %d, %Y %I:%M:%S %p",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(t, fmt)
            return int(dt.timestamp())
        except Exception:
            pass
    return None


def choose_primary_tenant(entries: list[dict]) -> str:
    """Ambil hostname paling dominan dari whitelist."""
    c = Counter()
    for e in entries:
        h = extract_hostname(e)
        if h in WHITELIST_TENANTS:
            c[h] += 1
    if not c:
        return "-"
    return c.most_common(1)[0][0]


# ============================================================
#  BUILD JSON UNTUK /api/data
# ============================================================
def build_api_data(entries: list[dict]) -> dict:
    """Bangun payload JSON untuk dashboard front-end."""
    filtered = [e for e in entries if extract_hostname(e) in WHITELIST_TENANTS]

    # Jika tidak ada data, return kosong
    if not filtered:
        return {
            "hostname": "-",
            "identity": "-",
            "total_attacks": 0,
            "owasp": {"labels": [], "values": []},
            "severity": {"labels": [], "values": []},
            "timeline": {"labels": [], "values": []},
            "tenants": [],
            "mitre": [],
        }

    # Ringkasan MITRE
    summary = analyze_uris(filtered)
    total_attacks = sum(v["count"] for v in summary.values())

    hostname = choose_primary_tenant(filtered)
    identity = HOSTNAME_IDENTITY_MAP.get(hostname, "-")

    # ---------------------------------------------------------
    # OWASP Aggregation
    # ---------------------------------------------------------
    owasp_counter = Counter()
    for mid, d in summary.items():
        cat = OWASP_TOP10_MAP.get(mid)
        if cat:
            owasp_counter[cat] += d["count"]

    # ---------------------------------------------------------
    # Severity Distribution (pakai SeverityEngine)
    # ---------------------------------------------------------
    severity_dist = Counter()
    mitre_rows = []

    for mid, d in summary.items():
        count = d["count"]

        # category hint opsional
        mitre_cat_label = MITRE_ATTACK_TYPES.get(mid, "-")

        sev = SEVERITY_ENGINE.classify(
            mitre_id=mid,
            count=count,
            hostname=hostname,
            identity=identity,
            category_hint=None,
        )

        severity_dist[sev] += count

        mitre_rows.append({
            "mitre_id": mid,
            "category": mitre_cat_label,
            "owasp": OWASP_TOP10_MAP.get(mid, "-"),
            "severity": sev,
            "count": count,
        })

    # ---------------------------------------------------------
    # Tenant Summary
    # ---------------------------------------------------------
    tenants_counter = Counter()
    for e in filtered:
        h = extract_hostname(e)
        tenants_counter[h] += 1

    tenants_list = []
    for h in WHITELIST_TENANTS:
        tenants_list.append({
            "hostname": h,
            "identity": HOSTNAME_IDENTITY_MAP.get(h, "-"),
            "events": tenants_counter.get(h, 0),
        })

    tenants_list.sort(key=lambda x: x["events"], reverse=True)

    # ---------------------------------------------------------
    # Timeline graph (hour bucket)
    # ---------------------------------------------------------
    timeline_counter = Counter()
    for e in filtered:
        ts = None
        if "timestamp" in e and e["timestamp"]:
            try:
                ts = int(e["timestamp"])
            except Exception:
                ts = None

        if ts is None and "Time" in e:
            ts = parse_oci_time(e.get("Time"))

        if ts is None:
            continue

        dt = datetime.fromtimestamp(ts)
        key = dt.strftime("%Y-%m-%d %H:00")
        timeline_counter[key] += 1

    # ---------------------------------------------------------
    # Final payload
    # ---------------------------------------------------------
    return {
        "hostname": hostname,
        "identity": identity,
        "total_attacks": total_attacks,
        "owasp": {
            "labels": list(owasp_counter.keys()),
            "values": list(owasp_counter.values()),
        },
        "severity": {
            "labels": list(severity_dist.keys()),
            "values": list(severity_dist.values()),
        },
        "timeline": {
            "labels": list(timeline_counter.keys()),
            "values": list(timeline_counter.values()),
        },
        "tenants": tenants_list,
        "mitre": mitre_rows,
    }


# ============================================================
#  FLASK FACTORY
# ============================================================
def create_app(log_files: list[str]) -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    @app.get("/")
    def root():
        return render_template("dashboard_bod.html")

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard_bod.html")

    @app.get("/api/data")
    def api_data():
        entries = load_all_entries(log_files)
        data = build_api_data(entries)
        return jsonify(data)

    return app


# ============================================================
#  CLI ENTRYPOINT
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="OCI WAF BOD Dashboard")
    parser.add_argument("--log", default="logs/*.json")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    log_files = resolve_log_files(args.log)

    if not log_files:
        print(f"[WARN] Tidak ada log ditemukan dari: {args.log}")
    else:
        print(f"[INFO] Log ditemukan ({len(log_files)}):")
        for p in log_files:
            print("  -", p)

    app = create_app(log_files)
    print(f"[INFO] Dashboard berjalan di http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
