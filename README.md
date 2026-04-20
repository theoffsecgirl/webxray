# webxray

Offensive web scanner: crawling, XSS, SQLi, headers and WAF bypass.

> 🇪🇸 [Versión en español](README.es.md)

---

## What does it do?

Offensive web scanner written in Python that combines crawling, XSS detection, SQL injection, security header analysis and WAF detection.

---

## Features

- Application crawling
- Reflected XSS detection (GET and forms)
- SQLi detection via GET and POST forms
- Security header analysis
- WAF detection and bypass (`--waf-xss`)
- JSON / JSONL output

---

## Installation

```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
pip install -e .
```

---

## Usage

```bash
webxray -u https://example.com
```

### Pipeline

```bash
webxray -u https://target.com --format jsonl --stdout | bbcopilot ingest webxray -
```

---

## Notes

- Findings are candidates, not confirmed vulnerabilities
- Designed for bug bounty recon and pipeline integration

---

## License

MIT
