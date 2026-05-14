# AURA (AI Unified Recon & Attack-Surface Mapper)

AURA is an AI-powered cybersecurity reconnaissance and attack-surface mapping framework built for ethical hacking, penetration testing, and security research.

It combines:

- Passive reconnaissance
- Active scanning
- Risk analysis
- AI-assisted threat insights
- Live dashboard visualization

into a single unified platform.

---

# Features

## Passive Reconnaissance
- Subdomain enumeration
  - crt.sh integration
  - HackerTarget integration
- WHOIS lookup
- DNS/IP resolution
- OSINT-ready architecture

---

## Active Scanning
- Multi-threaded Nmap scanning
- Fast scan mode
- Full scan mode
- Vulnerability scan mode
- Open port detection
- Service identification
- Host discovery

---

## Advanced Detection
- Banner grabbing
- HTTP/HTTPS detection
- Website title extraction
- Server fingerprinting
- Web service analysis

---

## Risk Analysis
Ports are classified automatically:

| Risk Level | Examples |
|---|---|
| HIGH | SSH, FTP, RDP, Telnet |
| MEDIUM | HTTP, HTTPS, MySQL |
| LOW | Other informational ports |

---

## AI Security Dashboard
The dashboard provides:

- Live scan visualization
- Risk analytics
- Port/service monitoring
- AI-powered threat analysis
- JSON report importing
- Interactive charts

---

# Dashboard Features

| Feature | Description |
|---|---|
| Live target info | Shows scan target and mode |
| Subdomain overview | Lists discovered subdomains |
| Open port tracking | Displays open ports/services |
| Risk summary | High / Medium / Low classification |
| Risk chart | Donut-based risk visualization |
| AI Analyze | AI-generated threat assessment |
| Upload JSON | Load external reports |
| Flask backend support | Fetch latest report dynamically |

---

# Project Structure

```text
AURA/
│
├── docs/
│   └── architecture.md
│
├── examples/
│   ├── passive_output.json
│   └── passive_recon_output.json
│
├── modules/
│   ├── __init__.py
│   ├── active_scan.py
│   └── passive_recon.py
│
├── dashboard.html
├── final_report.json
├── main.py
├── README.md
├── requirements.txt
├── server.py
├── test_nmap.py
└── .gitignore
