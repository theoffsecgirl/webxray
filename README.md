<div align="center">

# webxray

**Offensive web scanner: crawling, XSS, SQLi, headers and WAF bypass**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.2.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

</div>

---

## Features

- Crawling
- XSS / SQLi candidates
- Header analysis
- WAF-aware XSS
- JSON + JSONL output
- stdout pipeline mode

---

## New workflow

```bash
webxray -u https://target.com --format jsonl --stdout \
| bbcopilot ingest webxray -
```

---

## Output

Normalized findings ready for pipeline ingestion.

---

## Params

```text
--format json|jsonl
--stdout
--json-output
```

---

Use only on authorized targets.
