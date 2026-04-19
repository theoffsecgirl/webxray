<div align="center">

# webxray

**Escáner ofensivo web: crawling, XSS, SQLi, headers y WAF bypass**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.2.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Escáner ofensivo web escrito en Python que combina crawling, candidatos a XSS reflected, candidatos a SQLi, análisis de cabeceras de seguridad y checks de XSS orientados a WAF. Pensado para bug bounty y pentesting web como primer filtro rápido.

Importante: los hallazgos son **candidatos / señales**, no confirmaciones de vulnerabilidad.

---

## Funcionalidades

- Crawling de la aplicación objetivo
- Detección de candidatos XSS reflected (GET y formularios)
- Detección de candidatos SQLi GET y POST en formularios
- Análisis de cabeceras de seguridad (6 cabeceras)
- Detección de WAF y payloads orientados a bypass (`--waf-xss`)
- Output normalizado para workflows
- Exportación en JSON y JSONL
- Modo `stdout` para pipelines

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
pip install -e .
webxray --help
```

---

## Uso

```bash
# Escaneo básico
webxray -u https://example.com

# Profundidad de crawling
webxray -u https://example.com -d 2

# Con bypass WAF
webxray -u https://example.com --waf-xss

# Exportar findings normalizados en JSON
webxray -u https://example.com --json-output resultados.json

# Exportar findings normalizados en JSONL
webxray -u https://example.com --json-output resultados.jsonl --format jsonl

# Enviar findings a stdout para pipelines
webxray -u https://example.com --format jsonl --stdout

# Ver versión
webxray --version
```

---

## Ejemplo de output

### Finding normalizado en JSONL

```json
{"type":"candidate","vector":"xss","target":"https://example.com/search?q=test","host":"example.com","method":"GET","param":"q","severity":"medium","confidence":"medium","evidence":["payload reflected in response"],"tags":["reflection","get-param"],"raw":{"type":"xss","url":"https://example.com/search?q=test","parameter":"q","payload":"<svg/onload=alert(1)>","status":200}}
```

### Notas

- Los logs van a `stderr`
- Los findings van a `stdout` cuando usas `--stdout`
- `--json-output -` también imprime findings por stdout

---

## Integración en workflow

### Guardar a fichero e ingerir en `bb-copilot`

```bash
webxray -u https://target.com -d 2 --format jsonl --json-output out.jsonl
bbcopilot ingest webxray out.jsonl
bbcopilot findings --tool webxray
bbcopilot correlate
bbcopilot auto-triage
bbcopilot exploit-plan
```

### Flujo por pipe

```bash
webxray -u https://target.com --format jsonl --stdout > out.jsonl
bbcopilot ingest webxray out.jsonl
```

### Modos enfocados

```bash
# Solo XSS + WAF
webxray -u https://target.com --waf-xss --no-sqli --no-headers

# Solo cabeceras
webxray -u https://target.com --no-xss --no-sqli
```

---

## Parámetros

```text
-u, --url          URL objetivo
-d, --depth        Profundidad de crawling (default: 1)
--no-xss           Omitir detección básica de XSS
--no-sqli          Omitir detección de SQLi
--no-headers       Omitir cabeceras
--waf-xss          Modo WAF + XSS avanzado (requiere wafw00f)
-t, --timeout      Timeout en segundos (default: 10)
--json-output      Guardar findings normalizados en JSON/JSONL
--format           Formato de salida: json | jsonl
--stdout           Imprimir findings normalizados por stdout
    --version      Muestra la versión
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
