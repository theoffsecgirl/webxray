#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "1.2.0"

import argparse
import json
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


# ─── Logging → stderr ────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ─── Normalization ──────────────────────────────────────────────────────────

def normalize_finding(f: dict) -> dict:
    host = urlparse(f.get("url", "")).netloc

    vector_map = {
        "xss": "xss",
        "sqli_get": "sqli",
        "sqli_post": "sqli",
        "missing_header": "misconfig",
        "waf_xss": "xss",
        "waf_xss_form": "xss",
    }

    severity_map = {
        "xss": "high",
        "sqli": "high",
        "misconfig": "low",
    }

    vector = vector_map.get(f.get("type"), "unknown")

    return {
        "type": "candidate",
        "vector": vector,
        "target": f.get("url"),
        "host": host,
        "method": "GET",
        "param": f.get("parameter"),
        "severity": severity_map.get(vector, "medium"),
        "confidence": "medium",
        "reason": f.get("type"),
        "evidence": [str(f.get("payload", ""))],
        "tags": [vector],
        "raw": f,
    }


def serialize(findings: List[dict], fmt: str) -> str:
    if fmt == "jsonl":
        return "\n".join(json.dumps(f, ensure_ascii=False) for f in findings)
    return json.dumps(findings, indent=2, ensure_ascii=False)


# ─── Scanner mínimo (mantengo core simple) ──────────────────────────────────

def scan(url: str, timeout: int) -> List[dict]:
    findings = []

    try:
        r = requests.get(url, timeout=timeout)
    except Exception:
        return findings

    # reflección simple (heurística)
    if "<script>" in r.text:
        findings.append({
            "type": "xss",
            "url": url,
            "parameter": "unknown",
            "payload": "<script>",
        })

    return findings


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="webxray")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--format", choices=["json", "jsonl"], default="json")
    p.add_argument("--stdout", action="store_true")
    p.add_argument("--json-output")
    return p.parse_args()


def main():
    args = parse_args()

    raw = scan(args.url, args.timeout)
    normalized = [normalize_finding(f) for f in raw]

    output = serialize(normalized, args.format)

    if args.stdout:
        print(output)

    if args.json_output:
        with open(args.json_output, "w") as f:
            f.write(output)
        log(f"saved: {args.json_output}")


if __name__ == "__main__":
    main()
