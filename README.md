# CYber-core
A collection of cybersecurity utilities and scripts for ethical hacking and penetration testing.

## Features
- Passive reconnaissance (passive_recon.py)
	- subdomain enumeration (crt.sh + HackerTarget)
	- WHOIS lookup
	- IP resolution
- Active Scanning 
	- Multi-threaded Nmap scanning
	- Fast / Full / Vulnerability scan modes
	- Open port detection
	- Service identification
- Advanced Detection
	- Banner grabbing 
	- HTPP/HTTPS detection
	- Website title & server info extraction
- Risk Analysis
	- Ports classified as:
		- HIGH (SSH, FTP, RDP, etc..)
		- MEDIUM (HTTP, HTTPS, DB)
		- LOW
- JSON-based reporting for dashboard integration
## Output
- Structured JSON report ('final_report.json')
- Includes:
	- passive data
	- active scan data
	- summary
	- risk summary

## Installation
git clone https://github.com/BhargavaKrishna97/CYber-core.git
cd CYber-core
pip install -r requirements.txt

## Usage
-- Basic Scan
	python main.py  example.com
-- Full Scan
	python main.py example.com full
-- Vulnerability Scan
	python main.py example.com vuln

## Structure
CYber-core/
│
├── modules/
│   ├── passive_recon.py
│   ├── active_scan.py
│
├── main.py
├── requirements.txt
└── README.md

##  Sample Output

```bash
$ python main.py github.com

[+] Starting full recon on github.com
[+] Scan mode: fast
[+] Total targets for scanning: 10
[+] Scanning api.github.com (fast)...
[+] Scanning camo.github.com (fast)...
[+] Full report saved to final_report.json


##  JSON Output (Example)

```json
{
  "target": "github.com",
  "scan_type": "fast",
  "summary": {
    "total_subdomains": 10,
    "scan_mode": "fast"
  },
  "risk_summary": {
    "high": 2,
    "medium": 5,
    "low": 8
  },
  "status": "success"
}

## Contributing
- Fork the repo
- Create a branch (feature/---)
- Commit changes
- Open a pull request

## License
MIT License
