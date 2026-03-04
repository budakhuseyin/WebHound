# WebHound Recon Tool

WebHound is a fast, Flask-based web reconnaissance tool designed for information gathering.

Here is the link if you want to try it:
https://webhound.huseyinbudak.com.tr/

*Note: This project is currently under development and is continuously being upgraded.*

## Features
- **Domain Identity (WHOIS):** Extracts registrar, creation/expiration dates, country, and contact emails.
- **DNS Records (Architectural Mapping):** Maps out A, AAAA, MX, NS, and TXT (SPF/DMARC) records.
- **Technology Stack Detection:** Identifies web servers, backend languages, frameworks, CMS, and frontend libraries.
- **Subdomain Discovery:** Identifies subdomains passively using crt.sh.
- **Smart Directory Scanning:** Discovers hidden files and sensitive folders using common paths and robots.txt.
- **Open Port Scanner:** Scans common network ports to check for availability and potential entry points.
- **Security Headers Check:** Analyzes HTTP response to report present/missing common security headers (like CSP, HSTS).
- **Multi-threading Engine:** Performs all tasks in parallel (asynchronously) for immediate results without freezing the UI.

## Quick Start
1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the tool:
   ```bash
   python main.py
   ```
3. Usage: Navigate to `http://127.0.0.1:5000` in your browser, enter a target URL, and click send.

## Disclaimer
This tool is for educational and ethical testing purposes only. Unauthorized use against targets without prior consent is illegal. The developer is not responsible for any misuse or damage caused by this program.
