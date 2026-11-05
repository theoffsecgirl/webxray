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
- Custom headers (`-H`), cookies (`-c`), proxy (`-x`, Burp), `-k` and `--rate` req/s limit
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

# Bug bounty: identifying header, authenticated session, rate limit
webxray -u https://target.com -H "X-Bugbounty: myuser" -c "session=..." --rate 5

# Through Burp
webxray -u https://target.com -x http://127.0.0.1:8080 -k
```

### Pipeline

```bash
webxray -u https://target.com --format jsonl --stdout | jq 'select(.severity=="high")'
```

> `-H`, `-c`, `-x`, `-k` and `--rate` apply to every request webxray sends (crawler included). In `--waf-xss` mode, WAF detection is done by `wafw00f`, which does not receive them.

---

## Notes

- Findings are candidates, not confirmed vulnerabilities
- Designed for bug bounty recon and pipeline integration

---

## License

MIT
