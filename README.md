# 🔐 OCI Threat Monitoring Dashboard  
**Threat Monitoring Intelligence • MITRE ATT&CK Insights • Risk-Based Severity Engine**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Backend-black?style=for-the-badge&logo=flask)
![OCI](https://img.shields.io/badge/Oracle%20Cloud-WAF-red?style=for-the-badge&logo=oracle)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Threat%20Mapping-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

Dashboard ini dirancang sebagai **platform visualisasi keamanan siber modern** untuk menganalisis serangan terhadap aplikasi Anda di **Oracle Cloud Infrastructure (OCI)**.  

Menggunakan data dari **OCI Web Application Firewall (WAF)** serta, dashboard ini menyediakan pemantauan analisis risiko otomatis, serta mapping langsung ke **MITRE ATT&CK** dan **OWASP Top 10**.

---

## ✨ Features

### 🧠 1. Risk-Based Severity Engine  
Severity ditentukan oleh:
- MITRE ATT&CK technique  
- CVSS score  
- Asset criticality  
- Frequency spike detection  
- Critical keyword detection  

Output: **Low, Medium, High, Critical** (bukan sekedar hitungan volume).

### 🛰️ 2. Executive Summary  
- Total serangan  
- Attack velocity  
- Peak hour analytics  
- Risk highlight automation  
- Cyber Map visualization

### 🏢 3. Tenant Analytics  
- Menampilkan aktivitas serangan berdasarkan hostname  
- Mendukung multi-tenant  
- Bubble-wall visual untuk melihat tenant paling sering diserang

### 📊 4. OWASP & MITRE ATT&CK Breakdown  
- Chart top OWASP category  
- MITRE technique breakdown  
- Tabel detail serangan  
- Timeline per jam  

---

## ⏳ 5. Realtime Monitoring (COMING SOON)  
> Fitur **Realtime Attack Feed** sedang dalam tahap pengembangan.  
> Dashboard akan mendukung:
> - Query otomatis dari **OCI Logging Search API**  
> - Deteksi serangan 60-detik terbaru  
> - Auto-severity via Risk Engine  
> - Live feed style SIEM  
> 
> Fitur ini akan hadir pada rilis berikutnya.

---

## 📸 Screenshots

### 🟦 Executive Summary  
![Executive Summary](assets/screenshots/executive.png)

### 🟦 Multi-Tenant Overview  
![Tenant Overview](assets/screenshots/tenants.png)

---

## 📁 Structure

```bash
OCI-Firewall-Parser/
├── LICENSE
├── oci-parser.py
├── oci_parser_core.py
├── oci_realtime_fetcher.py
├── README.md
├── requirements.txt
├── server.py
├── severity_engine.py
├── severity_mapping.json
│
├── assets/
│   └── screenshots/
│       ├── executive.png
│       └── tenants.png
│
├── keys/
│   └── your_oci_key.pem
│
├── logs/
│   └── your_log.json
│
├── static/
│   ├── css/
│   │   ├── dashboard.css
│   │   └── warroom.css
│   │
│   └── js/
│       ├── cyber_map.js
│       ├── dashboard.js
│       ├── executive.js
│       ├── kpi.js
│       ├── realtime.js
│       ├── tenants.js
│       └── utils.js
│
└── templates/
    ├── base.html
    ├── dashboard_bod.html
    │
    └── partials/
        ├── executive.html
        ├── kpi.html
        └── tenants.html
```

---
## 🚀 Installation & Setup

### 1️⃣ Install dependencies
```bash
git clone https://github.com/0xjessie21/OCI-Firewall-Parser.git oci-dashboard
cd oci-dashboard/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --break-system-packages
```
### 2️⃣ Save OCI logs to the logs/ folder (MANDATORY)
```yaml
logs/
    ├── waf_log_2025-11-24.json
    ├── waf_export_2025-11-25.json
    └── ...
```
### 3️⃣ Run dashboard
```bash
python3 server.py --log logs/*.json --debug
```
### 4️⃣ UI Access
```bash
http://localhost:8080
```

---

## 🛠️ Roadmap

- [x] Risk-Based Severity Engine  
- [x] Executive Summary Dashboard  
- [x] OWASP & MITRE Analytics  
- [x] Multi-Tenant Attack Profiling  
- [ ] **Realtime Monitoring (OCI Logging Search Integration)**  
- [ ] MITRE ATT&CK Matrix Heatmap  
- [ ] Threat Correlation Engine  
- [ ] Export PDF Security Report  
- [ ] WebSocket Live Streaming Mode  

## 📜 License

MIT License