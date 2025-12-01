#!/usr/bin/env python3

import json
import argparse
from collections import Counter

from oci_parser_core import (
    analyze_uris,
    choose_best_hostname,
    HOSTNAME_IDENTITY_MAP,
    MITRE_ATTACK_TYPES,
    OWASP_TOP10_MAP,
)

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ========== EXPORT PDF ========== #
def export_pdf_elegant(logo, host, identity, summary, owasp, sev, out="Executive_Report.pdf"):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out, pagesize=A4)
    story = []

    story.append(Spacer(1, 150))
    story.append(Paragraph("<b><font size=24>Security Executive Report</font></b>", styles["Title"]))
    story.append(Spacer(1, 40))

    if logo:
        story.append(Image(logo, width=300, height=120))
        story.append(Spacer(1, 40))

    story.append(Paragraph(f"<font size=14><b>Hostname:</b> {host}</font>", styles["Normal"]))
    story.append(Paragraph(f"<font size=14><b>Identity:</b> {identity}</font>", styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("<b><font size=18>1. OWASP Top 10 Summary</font></b>", styles["Heading2"]))
    for cat, cnt in owasp.items():
        story.append(Paragraph(f"• {cat}: {cnt}", styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("<b><font size=18>2. Severity Distribution</font></b>", styles["Heading2"]))
    for sev_key, sev_cnt in sev.items():
        story.append(Paragraph(f"• {sev_key}: {sev_cnt}", styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("<b><font size=18>3. MITRE ATT&CK Details</font></b>", styles["Heading2"]))
    for mid, d in summary.items():
        desc = MITRE_ATTACK_TYPES.get(mid, "-")
        story.append(Paragraph(f"{mid} - {desc}: {d['count']} temuan", styles["Normal"]))

    doc.build(story)
    return out

# ========== EXPORT DASHBOARD STATIC ========== #
def export_dashboard(data_json, template_path="templates/dashboard_pro.html", output="dashboard.html"):
    with open(template_path, "r") as f:
        template = f.read()
    html = template.replace("{{DATA_JSON}}", json.dumps(data_json))
    with open(output, "w") as f:
        f.write(html)
    return output

# ========== MAIN CLI ========== #
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file")
    parser.add_argument("--export-dashboard", action="store_true")
    parser.add_argument("--export-pdf-elegant", action="store_true")
    parser.add_argument("--logo-path", default=None)
    args = parser.parse_args()

    entries = json.load(open(args.json_file))
    summary = analyze_uris(entries)

    host = choose_best_hostname(entries)
    identity = HOSTNAME_IDENTITY_MAP.get(host, "Unknown")

    # OWASP SUMMARY
    owasp_counter = Counter()
    for mid, d in summary.items():
        owasp = OWASP_TOP10_MAP.get(mid)
        if owasp:
            owasp_counter[owasp] += d["count"]

    # Severity (simple)
    sev_counter = Counter({"HIGH": sum(d["count"] for d in summary.values())})

    # Output console summary
    console.print(Panel.fit(
        f"[bold]Hostname:[/bold] [cyan]{host}\n"
        f"[bold]Identity:[/bold] [green]{identity}",
        title="🎯 Target", border_style="yellow"
    ))

    # Generate Dashboard
    if args.export_dashboard:
        total_attacks = sum(d["count"] for d in summary.values())
        data_json = {
            "hostname": host,
            "identity": identity,
            "total_attacks": total_attacks,
            "owasp": {
                "labels": list(owasp_counter.keys()),
                "values": list(owasp_counter.values()),
            },
            "severity": {
                "labels": list(sev_counter.keys()),
                "values": list(sev_counter.values()),
            },
            "mitre": [
                {
                    "mitre_id": mid,
                    "category": MITRE_ATTACK_TYPES.get(mid, "-"),
                    "owasp": OWASP_TOP10_MAP.get(mid, "-"),
                    "severity": "HIGH",
                    "count": d["count"],
                }
                for mid, d in summary.items()
            ],
            "timeline": {
                "labels": ["00", "01", "02"],
                "values": [10, 4, 7]
            }
        }

        out = export_dashboard(data_json)
        console.print(f"[green]Dashboard PRO created: {out}[/green]")

    if args.export_pdf_elegant:
        out = export_pdf_elegant(args.logo_path, host, identity, summary, owasp_counter, sev_counter)
        console.print(f"[green]PDF Elegan created: {out}[/green]")

if __name__ == "__main__":
    main()
