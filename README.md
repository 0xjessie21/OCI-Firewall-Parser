[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)

Oracle Cloud Infrastructure (OCI) Firewall log Threat Analyzer adalah tools terminal interaktif berbasis Python yang dirancang untuk membantu tim SOC dan analis keamanan dalam mengidentifikasi pola serangan berdasarkan URI log firewall dan memetakan tekniknya ke dalam framework MITRE ATT&CK.

# Screenshot
![OCI Parser](https://github.com/0xjessie21/OCI-Firewall-Parser/blob/master/oci-parser.png)

# 🚀 Features
* 🔍 False Negative URI Detection: Analisis URI mencurigakan yang lolos dari deteksi tradisional menggunakan pattern mapping ke teknik MITRE.
* 📚 Integrasi Resmi MITRE ATT&CK (TAXII / STIX2): Sinkronisasi otomatis dengan server resmi MITRE untuk mendapatkan data TTP (tactics, techniques, procedures) terbaru.
* 🧠 Severity Mapping Otomatis: Mengkategorikan setiap teknik ke dalam tingkat keparahan (CRITICAL, HIGH, MEDIUM, LOW, INFORMATION) berdasarkan kill chain phase secara cerdas.
* 📊 Statistik Serangan Real-Time: Tampilkan ringkasan eksplisit jumlah URI mencurigakan, request terlibat, teknik teratas, dan rekap berdasarkan severity.
* 🎛️ Interface Terminal Stylish & Interaktif: Dibangun dengan rich, menyajikan tabel warna-warni, progress spinner, dan ringkasan interaktif yang membuat analisis lebih menyenangkan.
* 🔐 Support Proxy / VPN Environment: Bisa berjalan di lingkungan terbatas atau korporat dengan dukungan proxy environment variable.

# Installation
```yaml
git clone https://github.com/0xjessie21/OCI-Firewall-Parser.git
cd OCI-Firewall-Parser/
pip3 install -r requirements.txt --break-system-packages
```

# Usage
Dynamic Baseline
```yaml
python oci-parser.py YOUR_OCI_LOG.json
```
Acunetix Baseline
```yaml
python oci-parser.py YOUR_OCI_LOG.json --severity-profile acunetix --severity-mapping severity_mapping.json
```
CVSS Baseline
```yaml
python oci-parser.py YOUR_OCI_LOG.json --severity-profile cvss --severity-mapping severity_mapping.json
```

## Credits
ILCS Security Operations Center Team


## 📜 License

This project is licensed under the `MIT License`
