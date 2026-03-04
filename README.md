# WebHound Recon Tool

WebHound is a blazing fast, Flask-based open-source Web Reconnaissance (OSINT) and Pentesting tool. It performs deep, multi-threaded intelligence gathering on target domains in seconds.

**Live Demo:** [webhound.huseyinbudak.com.tr](https://webhound.huseyinbudak.com.tr/)

*Note: This project is actively being developed and is continuously upgraded.*

## Key Features

The scanner operates asynchronously, executing all modules in parallel so the UI never freezes. It performs a comprehensive "outside-in" pentest analysis in the following flow:

- **Domain Identity (WHOIS):** Extracts registrar, creation/expiration dates, country, and contact emails.
- **DNS Records (Architectural Mapping):** Maps out IPv4 (A), IPv6 (AAAA), Mail (MX), Name Servers (NS), and Text (TXT / SPF / DMARC) records.
- **Subdomain Discovery:** Identifies subdomains passively using `crt.sh` to map the target's external footprint.
- **Open Port & Banner Grabbing:** Scans critical server ports (e.g. 21, 22, 80, 443) and extracts service banners (like `OpenSSH 8.2` or `nginx/1.18.0`).
- **Technology Stack & WAF Detection:** Deeply analyzes HTTP headers, cookies, and DOM to detect the Web Server, Framework, Backend Language, CMS, Frontend libraries, and whether the site is protected by a Web Application Firewall (WAF) such as Cloudflare, Akamai, or Imperva.
- **SSL/TLS Configuration Analysis:** Connects directly to port 443 to extract the Certificate Issuer, protocol version, and remaining valid days. Instantly flags expired or insecure (MITM vulnerable) certificates.
- **Smart Directory Scanning:** Searches for hidden administrative panels, `.git` configurations, databases, and `.env` files using common paths and `robots.txt` traversal.
- **Security Headers Check:** Analyzes the HTTP response to report present or dangerously missing security headers (like CSP, HSTS, X-Frame-Options).

## Performance Optimization
- **Fault-Tolerant Engine:** Uses a concurrent ThreadPoolExecutor wrapper with an absolute `30-second timeout` kill-switch for hanging requests.
- **Optimized Threads:** Spawns up to 40 threads for directory and port scanning, dropping individual connection timeouts to `0.8 - 3s` to blast through load-balancers without sacrificing Gunicorn/Nginx server stability.

---

## Quick Start

**1. Clone & Install Dependencies:**
```bash
git clone https://github.com/budakhuseyin/WebHound.git
cd WebHound
pip install -r requirements.txt
```

**2. Run the Tool:**
```bash
python main.py
```

**3. Usage:** 
Navigate to `http://127.0.0.1:5000` in your browser, enter a target URL (e.g. `https://example.com`), and click "Scan Target".

---

## Planned Updates (Roadmap)
- [ ] Direct Subdomain Takeover Vulnerability checks.
- [ ] Vulnerability (CVE) matching based on the extracted Tech Stack / Port Banners.
- [ ] Exporting full scan results as a PDF or JSON report.
- [ ] ... and more updates coming soon!

## Legal Disclaimer
This tool is for educational and ethical testing (authorized pentesting) purposes only. Unauthorized use against targets without prior, mutual, and written consent is illegal. The developer is not responsible for any misuse, damage, or legal consequences caused by this program.
