# tool-webflow v2.0

Escáner moderno de vulnerabilidades web con detección mejorada, threading y reporting completo.

---

## 🚀 Novedades v2.0 (2026)

### Mejoras Técnicas
- ✅ **Threading multi-URL** para escaneos más rápidos
- ✅ **Detección XSS mejorada** con payloads context-aware
- ✅ **SQLi time-based & error-based** detection
- ✅ **Security headers** con rating de severidad
- ✅ **Rate limiting** configurable
- ✅ **Reporting JSON** estructurado con métricas
- ✅ **Autenticación** con headers personalizados

### Arquitectura
- Código orientado a objetos con dataclasses
- ThreadPoolExecutor para concurrencia
- Sistema de severidad (high/medium/low)
- Logging mejorado con colores y verbose mode

---

## 📦 Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-webflow.git
cd tool-webflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔥 Uso Básico

### Escaneo estándar

```bash
python3 webflow.py -u https://target.com
```

### Escaneo completo con threading

```bash
python3 webflow.py -u https://target.com \
  -d 2 \
  --threads 10 \
  -o results.json \
  -v
```

### Con autenticación

```bash
python3 webflow.py -u https://target.com \
  --auth-header "Authorization: Bearer TOKEN"
```

### Solo XSS (rápido)

```bash
python3 webflow.py -u https://target.com \
  --no-sqli --no-headers
```

---

## ⚙️ Opciones CLI

| Flag              | Descripción                                     |
|-------------------|-------------------------------------------------|
| `-u, --url`       | URL objetivo (obligatorio)                      |
| `-d, --depth`     | Profundidad de crawling (default: 1)            |
| `-t, --timeout`   | Timeout en segundos (default: 10)               |
| `--rate-limit`    | Peticiones por segundo (default: 10)            |
| `--threads`       | Número de threads para escaneo (default: 5)     |
| `--no-xss`        | Omitir detección XSS                            |
| `--no-sqli`       | Omitir detección SQLi                           |
| `--no-headers`    | Omitir verificación de headers                  |
| `--auth-header`   | Header de autenticación                         |
| `--user-agent`    | User-Agent personalizado                        |
| `-o, --json-output` | Guardar resultados en JSON                    |
| `-v, --verbose`   | Modo verbose                                    |

---

## 🎯 Detecciones

### XSS (Cross-Site Scripting)
- Payloads context-aware (HTML, atributos, href, script)
- Detección de reflejos en respuesta
- 7 payloads optimizados para bypass básico

**Payloads incluidos:**
```html
<script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)
"'><svg/onload=alert(1)>
</script><script>alert(1)</script>
```

### SQLi (SQL Injection)
- **Time-based**: Detección con SLEEP()
- **Error-based**: Parsing de mensajes de error SQL
- **Blind**: Análisis diferencial de respuestas

**Patrones de error detectados:**
- MySQL, PostgreSQL, SQLite, Oracle, MSSQL
- MariaDB, ODBC, pg_query

### Security Headers
Verificación con severidad:
- **High**: Content-Security-Policy, Strict-Transport-Security
- **Medium**: X-Frame-Options, X-Content-Type-Options
- **Low**: Referrer-Policy, Permissions-Policy

---

## 📊 Formato JSON Output

```json
{
  "target": "https://target.com",
  "timestamp": 1709577600.123,
  "scan_config": {
    "depth": 2,
    "timeout": 10,
    "threads": 5
  },
  "urls_discovered": 15,
  "findings_count": 8,
  "summary": {
    "xss": 2,
    "sqli_error": 1,
    "missing_header": 5
  },
  "severity_summary": {
    "high": 3,
    "medium": 3,
    "low": 2
  },
  "findings": [
    {
      "type": "xss",
      "severity": "high",
      "url": "https://target.com/search",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "evidence": "Payload reflejado en contexto html",
      "status_code": 200,
      "timestamp": 1709577601.456
    }
  ]
}
```

---

## 🎯 Casos de Uso

### Bug Bounty
```bash
# Escaneo rápido de subdominios
cat subdomains.txt | while read url; do
  python3 webflow.py -u "$url" --threads 10 -o "scan_$url.json"
done
```

### Pentesting
```bash
# Escaneo profundo con autenticación
python3 webflow.py -u https://app.target.com \
  --auth-header "Cookie: session=abc123" \
  -d 3 --threads 15 -v
```

### CI/CD Security Testing
```bash
# Verificar headers de seguridad
python3 webflow.py -u https://staging.app.com \
  --no-xss --no-sqli -o security-headers.json
```

---

## ⚠️ Limitaciones

- No gestiona formularios POST (solo parámetros GET)
- No soporta JavaScript rendering (usa crawling HTML estático)
- Detecciones basadas en heurísticas (pueden generar falsos positivos)
- No realiza bypass de WAF avanzado
- CSRF tokens no son gestionados automáticamente

**tool-webflow es una herramienta de reconnaissance inicial, no un reemplazo de análisis manual exhaustivo.**

---

## 🔬 Roadmap

- [ ] Playwright integration para JavaScript rendering
- [ ] Soporte para formularios POST
- [ ] Detección de CSRF
- [ ] Bypass automático de WAF
- [ ] Integración con Nuclei templates
- [ ] Reporting HTML interactivo

---

## 📖 Uso Ético

Utiliza esta herramienta únicamente en:
- ✅ Sistemas propios
- ✅ Entornos autorizados
- ✅ Programas de bug bounty con scope definido

**El uso no autorizado es ilegal.**

---

## 📜 Licencia

MIT License
