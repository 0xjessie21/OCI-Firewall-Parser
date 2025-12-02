# 🔐 OCI WAF Cyber Defense Dashboard  
**Real-time Threat Intelligence • MITRE ATT&CK Insights • Risk-Based Severity Engine**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Backend-black?style=for-the-badge&logo=flask)
![OCI](https://img.shields.io/badge/Oracle%20Cloud-WAF-red?style=for-the-badge&logo=oracle)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Threat%20Mapping-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

Dashboard ini dirancang sebagai **platform visualisasi keamanan siber modern** untuk menganalisis serangan terhadap aplikasi Anda di **Oracle Cloud Infrastructure (OCI)**.  
Menggunakan data dari **OCI Web Application Firewall (WAF)** serta **Logging Search API**, dashboard ini menyediakan pemantauan **real-time**, analisis risiko otomatis, serta mapping langsung ke **MITRE ATT&CK** dan **OWASP Top 10**.

---

## ✨ Fitur Utama

### 🔥 1. Realtime Attack Feed (OCI WAF Logging Search)
- Menampilkan serangan dalam **60 detik terakhir**.  
- Terhubung langsung ke OCI Logging Search API (SDK resmi).  
- Menampilkan informasi: IP, Host, URI, MITRE ID, rule, severity.

### 🧠 2. Risk-Based Severity Engine  
Severity ditentukan oleh:
- MITRE ATT&CK technique  
- CVSS score  
- Asset criticality  
- Frequency spike detection  
- Critical keyword detection  

Output: **Low, Medium, High, Critical** (bukan sekadar hitungan volume).

### 🛰️ 3. Executive Summary  
- Total serangan  
- Attack velocity  
- Peak hour  
- Risk highlight automation  
- Cyber Map (grid attack visualization)

### 🏢 4. Tenant Analytics  
- Menampilkan aktivitas serangan berdasarkan hostname  
- Mendukung multi-tenant (TOS, Phinnisi, Parama, Praya, dll.)  
- Bubble-wall untuk memvisualisasikan tenant paling sering diserang

### 📊 5. OWASP & MITRE ATT&CK Breakdown  
- Chart top OWASP category  
- MITRE technique breakdown  
- Tabel detail serangan  
- Timeline serangan per jam  

---

## 📸 Screenshots

> (Tambahkan file PNG ke folder `screenshots/` setelah upload ke GitHub)

### 🟦 Executive Summary  
![Executive Summary](screenshots/executive_summary.png)

### 🟦 Multi-Tenant Overview  
![Tenant Overview](screenshots/tenants.png)

### 🟦 OWASP / MITRE Attack Breakdown  
![OWASP / MITRE](screenshots/owasp_mitre.png)

### 🟦 Realtime Attack Feed  
![Realtime Feed](screenshots/realtime.png)

---

## 🧩 Arsitektur Sistem

![Architecture](architecture.svg)

---

## 🚀 Installation & Setup

### 1️⃣ Install dependencies
```bash
pip install -r requirements.txt --break-system-packages
