<div align="center">

# webxray

**Offensive web scanner: crawling, XSS, SQLi, headers and WAF bypass**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ██████╗ ███████╗ ██████╗  ██╗ ██████╗  █████╗ ██╗  │
│  ██╔══██╗██╔════╝ ██╔══██╗██║██╔══██╗██╔══██╗██║  │
│  ██████╔╝█████╗  ██████╔╝██║██║  ██║███████║██║  │
│  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║╚═╝  │
│  ██║     ███████╗██████╔╝██║██████╔╝██║  ██║██╗  │
│  ╚═╝     ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  │
│                                                      │
│  offensive web scanner  v1.1.0  ·  by theoffsecgirl  │
└──────────────────────────────────────────────────────┘
```

---

## What does it do?

Offensive web scanner written in Python that combines crawling, XSS detection, SQL injection, security header analysis and WAF detection with provider-based bypass. Built for bug bounty and web pentesting.

---

## Features

- Application crawling
- Reflected XSS detection (GET and forms)
- SQLi detection via GET and POST forms
- Security header analysis (6 headers)
- WAF detection and provider-based bypass (`--waf-xss`)
- JSON export of results

---

## Installation

**From source (recommended)**
```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
pip install -e .
webxray --help
```

**With virtual environment (clean setup)**
```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
python3 -m venv venv
source venv/bin/activate
pip install -e .
webxray --help
```

**Requirements**
- Python 3.8+
- Optional: `wafw00f` for `--waf-xss` mode (`pip install wafw00f`)

---

## Usage

```bash
# Basic scan
webxray -u https://example.com

# Crawling depth
webxray -u https://example.com -d 2

# With WAF bypass
webxray -u https://example.com --waf-xss

# Export results
webxray -u https://example.com --json-output results.json

# Show version
webxray --version
```

---

## Output example

```text
[*] Starting scan → https://example.com
[*] Crawling depth: 2 | Timeout: 10s

[+] URLs found: 47
[+] Forms found: 8

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 XSS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[!] Reflected XSS → https://example.com/search?q=<script>alert(1)</script>
    Parameter: q | Type: GET

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SQLi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[!] Possible SQLi → https://example.com/product?id=1'
    Parameter: id | Error: MySQL syntax

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Headers
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[!] Missing: Content-Security-Policy
[!] Missing: X-Frame-Options
[+] Present: Strict-Transport-Security
[+] Present: X-Content-Type-Options

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WAF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[*] WAF detected: Cloudflare
[*] Applying bypass payloads...
[!] Possible bypass → https://example.com/search?q=<img src=x onerror=alert(1)>

[+] Results saved → results.json
[*] Scan completed in 12.4s
```

---

## When to use it

- Initial recon on a new target — get a quick surface overview
- Form hunting before manual testing
- Quick header audit during triage
- WAF fingerprinting before payload crafting
- Complement to Burp Suite for automated first-pass

---

## Workflow integration

```bash
# 1. Quick triage on a new target
webxray -u https://target.com -d 2 --json-output target-recon.json

# 2. Focused XSS hunt with WAF bypass
webxray -u https://target.com --waf-xss --no-sqli --no-headers

# 3. Headers-only audit (fast)
webxray -u https://target.com --no-xss --no-sqli

# 4. Pipe output to jq for triage
webxray -u https://target.com --json-output - | jq '.xss[]'
```

---

## Parameters

```text
-u, --url          Target URL
-d, --depth        Crawling depth (default: 1)
--no-xss           Skip XSS detection
--no-sqli          Skip SQLi detection
--no-headers       Skip header analysis
--waf-xss          Advanced WAF + XSS mode (requires wafw00f)
-t, --timeout      Timeout in seconds (default: 10)
--json-output      Save results to JSON
    --version      Show version
```

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## Contributing

PRs welcome. If you find a bypass technique that works and isn't covered, open an issue with:
- Target WAF provider
- Payload used
- Expected vs actual behavior

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
