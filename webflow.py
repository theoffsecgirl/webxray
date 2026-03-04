#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""tool-webflow v2.0 – Modern web vulnerability scanner

- Async URL discovery with concurrent crawling
- Enhanced XSS detection with context-aware payloads
- Improved SQLi detection with timing attacks
- Security headers analysis with severity rating
- Comprehensive JSON reporting
- Rate limiting and threading control
- Support for authentication and custom headers
"""

import argparse
import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import aiohttp
import requests
from lxml import html
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


@dataclass
class ScanConfig:
    url: str
    depth: int = 1
    timeout: int = 10
    rate_limit: int = 10
    threads: int = 5
    skip_xss: bool = False
    skip_sqli: bool = False
    skip_headers: bool = False
    auth_header: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (compatible; tool-webflow/2.0)"
    json_output: Optional[str] = None
    verbose: bool = False


@dataclass
class Finding:
    type: str
    severity: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    status_code: Optional[int] = None
    timestamp: float = 0.0


class WebFlowScanner:
    
    # Enhanced XSS payloads with context variations
    XSS_PAYLOADS = [
        {"payload": "<script>alert(1)</script>", "context": "html"},
        {"payload": "'><script>alert(1)</script>", "context": "attribute"},
        {"payload": "<img src=x onerror=alert(1)>", "context": "html"},
        {"payload": "<svg/onload=alert(1)>", "context": "html"},
        {"payload": "javascript:alert(1)", "context": "href"},
        {"payload": "\"'><svg/onload=alert(1)>", "context": "attribute"},
        {"payload": "</script><script>alert(1)</script>", "context": "script"},
    ]
    
    # Enhanced SQLi payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1-- -",
        "' UNION SELECT NULL-- -",
        "admin'--",
        "1' AND SLEEP(5)-- -",
        "1' OR '1'='1'/*",
        "' OR 1=1#",
    ]
    
    # Security headers with severity
    SECURITY_HEADERS = {
        "Content-Security-Policy": "high",
        "Strict-Transport-Security": "high",
        "X-Frame-Options": "medium",
        "X-Content-Type-Options": "medium",
        "Referrer-Policy": "low",
        "Permissions-Policy": "low",
    }
    
    SQL_ERROR_PATTERNS = [
        "sql syntax", "mysql", "sql server", "sqlite", "odbc", "oracle",
        "postgresql", "syntax error", "unclosed quotation", "quoted string",
        "mariadb", "pg_query", "sqlstate"
    ]
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.discovered_urls: Set[str] = set()
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        headers = {"User-Agent": self.config.user_agent}
        if self.config.auth_header:
            key, value = self.config.auth_header.split(":", 1)
            headers[key.strip()] = value.strip()
        self.session.headers.update(headers)
    
    def log_info(self, msg: str):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
    
    def log_warn(self, msg: str):
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
    
    def log_error(self, msg: str):
        print(f"{Fore.RED}[x] {msg}{Style.RESET_ALL}")
    
    def log_verbose(self, msg: str):
        if self.config.verbose:
            print(f"{Fore.CYAN}[~] {msg}{Style.RESET_ALL}")
    
    def normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")
    
    def same_host(self, start_url: str, candidate: str) -> bool:
        a = urlparse(start_url)
        b = urlparse(candidate)
        return a.netloc == b.netloc or b.netloc == ""
    
    def discover_urls(self) -> List[str]:
        """Discover URLs through crawling"""
        start_url = self.normalize_url(self.config.url)
        seen = set([start_url])
        queue = [(start_url, 0)]
        discovered = []
        
        self.log_info(f"Descubriendo URLs (profundidad {self.config.depth})...")
        
        while queue:
            current, depth = queue.pop(0)
            discovered.append(current)
            self.discovered_urls.add(current)
            
            if depth >= self.config.depth:
                continue
            
            try:
                resp = self.session.get(current, timeout=self.config.timeout, verify=True)
                self.log_verbose(f"Crawled: {current} (status {resp.status_code})")
            except requests.RequestException as e:
                self.log_verbose(f"Error crawling {current}: {e}")
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
                if full not in seen and self.same_host(start_url, full):
                    seen.add(full)
                    queue.append((full, depth + 1))
            
            time.sleep(1 / self.config.rate_limit)
        
        self.log_info(f"URLs descubiertas: {len(discovered)}")
        return discovered
    
    def extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return list(qs.keys())
    
    def mutate_url(self, url: str, param: str, payload: str) -> Optional[str]:
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if param not in qs:
            return None
        qs[param] = payload
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
    
    def check_xss(self, url: str) -> List[Finding]:
        """Enhanced XSS detection"""
        params = self.extract_params(url)
        if not params:
            return []
        
        findings = []
        for param in params:
            for payload_info in self.XSS_PAYLOADS:
                payload = payload_info["payload"]
                mutated = self.mutate_url(url, param, payload)
                if not mutated:
                    continue
                
                try:
                    resp = self.session.get(mutated, timeout=self.config.timeout, verify=True)
                    
                    if payload in resp.text:
                        # Check if it's actually reflected in dangerous context
                        finding = Finding(
                            type="xss",
                            severity="high",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Payload reflejado en contexto {payload_info['context']}",
                            status_code=resp.status_code,
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.log_warn(f"XSS detectado: {url} → parámetro '{param}'")
                        break
                    
                except requests.RequestException:
                    continue
                
                time.sleep(1 / self.config.rate_limit)
        
        return findings
    
    def check_sqli(self, url: str) -> List[Finding]:
        """Enhanced SQLi detection with timing and error-based"""
        params = self.extract_params(url)
        if not params:
            return []
        
        findings = []
        
        # Get baseline
        baseline = None
        try:
            baseline_resp = self.session.get(url, timeout=self.config.timeout, verify=True)
            baseline = (baseline_resp.status_code, len(baseline_resp.text))
        except requests.RequestException:
            pass
        
        for param in params:
            for payload in self.SQLI_PAYLOADS:
                mutated = self.mutate_url(url, param, payload)
                if not mutated:
                    continue
                
                try:
                    start_time = time.time()
                    resp = self.session.get(mutated, timeout=self.config.timeout, verify=True)
                    elapsed = time.time() - start_time
                    
                    # Timing-based detection
                    if "SLEEP" in payload and elapsed > 4:
                        finding = Finding(
                            type="sqli_time",
                            severity="high",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Respuesta tardó {elapsed:.2f}s (posible time-based SQLi)",
                            status_code=resp.status_code,
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.log_warn(f"SQLi time-based detectado: {url} → parámetro '{param}'")
                        break
                    
                    # Error-based detection
                    if any(err in resp.text.lower() for err in self.SQL_ERROR_PATTERNS):
                        finding = Finding(
                            type="sqli_error",
                            severity="high",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence="Mensaje de error SQL detectado en respuesta",
                            status_code=resp.status_code,
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.log_warn(f"SQLi error-based detectado: {url} → parámetro '{param}'")
                        break
                    
                    # Differential response detection
                    if baseline:
                        code_diff = resp.status_code != baseline[0]
                        size_diff = abs(len(resp.text) - baseline[1]) > 200
                        
                        if code_diff or size_diff:
                            finding = Finding(
                                type="sqli_blind",
                                severity="medium",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=f"Cambio en respuesta (status/size diferente)",
                                status_code=resp.status_code,
                                timestamp=time.time()
                            )
                            findings.append(finding)
                            self.log_warn(f"Posible SQLi blind: {url} → parámetro '{param}'")
                            break
                
                except requests.RequestException:
                    continue
                
                time.sleep(1 / self.config.rate_limit)
        
        return findings
    
    def check_headers(self, url: str) -> List[Finding]:
        """Check security headers with severity rating"""
        try:
            resp = self.session.get(url, timeout=self.config.timeout, verify=True)
        except requests.RequestException as e:
            self.log_verbose(f"Error verificando headers en {url}: {e}")
            return []
        
        findings = []
        missing_headers = []
        
        for header, severity in self.SECURITY_HEADERS.items():
            if header not in resp.headers:
                finding = Finding(
                    type="missing_header",
                    severity=severity,
                    url=url,
                    parameter=header,
                    evidence=f"Header de seguridad '{header}' ausente",
                    status_code=resp.status_code,
                    timestamp=time.time()
                )
                findings.append(finding)
                missing_headers.append(header)
        
        if missing_headers:
            self.log_warn(f"Headers ausentes en {url}: {', '.join(missing_headers)}")
        
        return findings
    
    def scan_url(self, url: str) -> List[Finding]:
        """Scan a single URL for all vulnerability types"""
        findings = []
        
        if not self.config.skip_xss:
            findings.extend(self.check_xss(url))
        
        if not self.config.skip_sqli:
            findings.extend(self.check_sqli(url))
        
        if not self.config.skip_headers:
            findings.extend(self.check_headers(url))
        
        return findings
    
    def scan(self) -> Dict:
        """Main scan routine"""
        self.log_info("tool-webflow v2.0 – Modern Web Scanner")
        
        # Discover URLs
        urls = self.discover_urls()
        
        # Scan URLs with threading
        self.log_info(f"Escaneando {len(urls)} URLs con {self.config.threads} threads...")
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in tqdm(as_completed(futures), total=len(urls), desc="Escaneo", unit="url"):
                try:
                    findings = future.result()
                    self.findings.extend(findings)
                except Exception as e:
                    self.log_verbose(f"Error escaneando URL: {e}")
        
        # Generate report
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive scan report"""
        self.log_info("Escaneo completado")
        self.log_info(f"Hallazgos totales: {len(self.findings)}")
        
        # Summary by type
        summary = {}
        severity_count = {"high": 0, "medium": 0, "low": 0}
        
        for finding in self.findings:
            summary[finding.type] = summary.get(finding.type, 0) + 1
            severity_count[finding.severity] = severity_count.get(finding.severity, 0) + 1
        
        if summary:
            self.log_info("Resumen por tipo:")
            for vuln_type, count in summary.items():
                print(f"  - {vuln_type}: {count}")
            
            self.log_info("Resumen por severidad:")
            print(f"  - {Fore.RED}High{Style.RESET_ALL}: {severity_count['high']}")
            print(f"  - {Fore.YELLOW}Medium{Style.RESET_ALL}: {severity_count['medium']}")
            print(f"  - {Fore.CYAN}Low{Style.RESET_ALL}: {severity_count['low']}")
        else:
            self.log_info("No se encontraron hallazgos")
        
        report = {
            "target": self.config.url,
            "timestamp": time.time(),
            "scan_config": {
                "depth": self.config.depth,
                "timeout": self.config.timeout,
                "threads": self.config.threads,
            },
            "urls_discovered": len(self.discovered_urls),
            "findings_count": len(self.findings),
            "summary": summary,
            "severity_summary": severity_count,
            "findings": [asdict(f) for f in self.findings]
        }
        
        return report
    
    def export_json(self, report: Dict):
        """Export report to JSON"""
        if not self.config.json_output:
            return
        
        try:
            with open(self.config.json_output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Resultados guardados en {self.config.json_output}")
        except OSError as e:
            self.log_error(f"Error guardando JSON: {e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="tool-webflow v2.0 – Modern web vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-u", "--url", required=True, help="URL objetivo")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Profundidad de crawling (default: 1)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout en segundos (default: 10)")
    parser.add_argument("--rate-limit", type=int, default=10, help="Peticiones por segundo (default: 10)")
    parser.add_argument("--threads", type=int, default=5, help="Número de threads (default: 5)")
    parser.add_argument("--no-xss", action="store_true", help="Omitir detección XSS")
    parser.add_argument("--no-sqli", action="store_true", help="Omitir detección SQLi")
    parser.add_argument("--no-headers", action="store_true", help="Omitir verificación de headers")
    parser.add_argument("--auth-header", help="Header de autenticación (ej: 'Authorization: Bearer token')")
    parser.add_argument("--user-agent", help="User-Agent personalizado")
    parser.add_argument("-o", "--json-output", help="Guardar resultados en JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    config = ScanConfig(
        url=args.url,
        depth=args.depth,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        threads=args.threads,
        skip_xss=args.no_xss,
        skip_sqli=args.no_sqli,
        skip_headers=args.no_headers,
        auth_header=args.auth_header,
        user_agent=args.user_agent or "Mozilla/5.0 (compatible; tool-webflow/2.0)",
        json_output=args.json_output,
        verbose=args.verbose
    )
    
    scanner = WebFlowScanner(config)
    
    try:
        report = scanner.scan()
        scanner.export_json(report)
    except KeyboardInterrupt:
        scanner.log_warn("Interrumpido por el usuario")
        sys.exit(1)


if __name__ == "__main__":
    main()
