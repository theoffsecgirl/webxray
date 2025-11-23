#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""tool-webflow – escáner básico de vulnerabilidades web.

- Descubre URLs internas a partir de una URL inicial.
- Realiza pruebas sencillas de XSS y SQLi sobre parámetros.
- Revisa cabeceras de seguridad HTTP.
- Opcionalmente genera salida en JSON.

Pensado para recon / bug bounty como primer filtro rápido,
no como sustituto de un pentest manual completo.
"""

import argparse
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests
from lxml import html
from termcolor import colored
from tqdm import tqdm


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; tool-webflow by TheOffSecGirl)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1-- -",
    """' UNION SELECT NULL-- -""".strip(),
]


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
]


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
            full = urljoin(current, href)
            full = full.split("#", 1)[0]
            if full not in seen and same_host(start_url, full):
                seen.add(full)
                queue.append((full, depth + 1))

    return discovered


def mutate_url_with_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    qs[param] = payload
    new_qs = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_qs)
    return urlunparse(new_parsed)


def extract_params(url: str):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return list(qs.keys())


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
                findings.append(
                    {
                        "type": "xss",
                        "url": url,
                        "parameter": p,
                        "payload": payload,
                        "status": r.status_code,
                    }
                )
                break  # no seguimos probando más payloads para ese parámetro
    return findings


def check_sqli(session, url: str, timeout: int):
    params = extract_params(url)
    findings = []

    baseline = None
    try:
        baseline_resp = session.get(url, timeout=timeout, verify=True)
        baseline = (baseline_resp.status_code, len(baseline_resp.text))
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

            if baseline:
                code_differs = r.status_code != baseline[0]
                size_differs = abs(len(r.text) - baseline[1]) > 100
                error_keywords = any(
                    e in r.text.lower()
                    for e in ["sql syntax", "mysql", "sql server", "sqlite", "odbc", "oracle"]
                )
                if code_differs or size_differs or error_keywords:
                    log_warn(
                        f"Posible SQLi en {url} parámetro '{p}' con payload '{payload}' "
                        f"(status {r.status_code})"
                    )
                    findings.append(
                        {
                            "type": "sqli",
                            "url": url,
                            "parameter": p,
                            "payload": payload,
                            "status": r.status_code,
                        }
                    )
                    break
            else:
                # Sin baseline, solo mensajes de error
                if any(e in r.text.lower() for e in ["sql syntax", "mysql", "sql server", "sqlite", "odbc", "oracle"]):
                    log_warn(
                        f"Posible SQLi en {url} parámetro '{p}' con payload '{payload}' "
                        f"(status {r.status_code})"
                    )
                    findings.append(
                        {
                            "type": "sqli",
                            "url": url,
                            "parameter": p,
                            "payload": payload,
                            "status": r.status_code,
                        }
                    )
                    break
    return findings


def check_headers(session, url: str, timeout: int):
    try:
        r = session.get(url, timeout=timeout, verify=True)
    except requests.RequestException as e:
        log_warn(f"No se pudieron verificar encabezados en {url}: {e}")
        return []

    missing = []
    for h in SECURITY_HEADERS:
        if h not in r.headers:
            missing.append(h)

    if missing:
        log_warn(f"Cabeceras de seguridad ausentes en {url}: {', '.join(missing)}")
        return [
            {
                "type": "missing_header",
                "url": url,
                "header": h,
            }
            for h in missing
        ]

    return []


def parse_args():
    parser = argparse.ArgumentParser(
        description="tool-webflow – Descubrimiento y escaneo básico de vulnerabilidades web."
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="URL inicial objetivo (ej: https://example.com)",
    )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=1,
        help="Profundidad máxima de crawling (por defecto 1)."
    )
    parser.add_argument(
        "--no-xss",
        action="store_true",
        help="No probar XSS.",
    )
    parser.add_argument(
        "--no-sqli",
        action="store_true",
        help="No probar SQLi.",
    )
    parser.add_argument(
        "--no-headers",
        action="store_true",
        help="No comprobar cabeceras de seguridad.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Timeout en segundos para peticiones HTTP (por defecto 10)."
    )
    parser.add_argument(
        "--json-output",
        help="Ruta de archivo para guardar resultados en JSON.",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    log_info("tool-webflow – Web scanner by TheOffSecGirl")

    start_url = args.url
    timeout = args.timeout

    log_info(f"Descubriendo URLs a partir de {start_url} (profundidad {args.depth})...")
    urls = discover_urls(start_url, max_depth=args.depth, timeout=timeout)
    log_info(f"URLs descubiertas: {len(urls)}")


    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    all_findings = []

    for u in tqdm(urls, desc="Escaneando URLs", unit="url"):
        if not args.no_xss:
            all_findings.extend(check_xss(session, u, timeout=timeout))
        if not args.no_sqli:
            all_findings.extend(check_sqli(session, u, timeout=timeout))
        if not args.no_headers:
            all_findings.extend(check_headers(session, u, timeout=timeout))

    log_info("Escaneo completado.")
    log_info(f"Hallazgos totales: {len(all_findings)}")

    # Mostrar pequeño resumen por tipo
    resumen = {}
    for f in all_findings:
        resumen[f["type"]] = resumen.get(f["type"], 0) + 1
    if resumen:
        log_info("Resumen por tipo:")
        for tipo, count in resumen.items():
            print(f"  - {tipo}: {count}")
    else:
        log_info("No se encontraron hallazgos relevantes (según las heurísticas usadas).")


    if args.json_output:
        try:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(all_findings, f, indent=2, ensure_ascii=False)
            log_info(f"Resultados guardados en {args.json_output}")
        except OSError as e:
            log_error(f"No se pudo escribir el archivo JSON: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrumpido por el usuario.")
        sys.exit(1)
