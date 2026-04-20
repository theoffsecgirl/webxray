# webxray

Escáner ofensivo web: crawling, XSS, SQLi, headers y WAF bypass.

> 🇬🇧 [English version](README.md)

---

## ¿Qué hace?

Escáner ofensivo web escrito en Python que combina crawling, detección de XSS, inyección SQL, análisis de cabeceras de seguridad y detección de WAF.

---

## Funcionalidades

- Crawling de la aplicación objetivo
- Detección de XSS reflected (GET y formularios)
- Detección de SQLi GET y POST en formularios
- Análisis de cabeceras de seguridad
- Detección de WAF y bypass (`--waf-xss`)
- Output en JSON / JSONL

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
pip install -e .
```

---

## Uso

```bash
webxray -u https://example.com
```

### Pipeline

```bash
webxray -u https://target.com --format jsonl --stdout | bbcopilot ingest webxray -
```

---

## Notas

- Los findings son candidatos, no vulnerabilidades confirmadas
- Pensado para recon y para integrarse en pipelines

---

## Licencia

MIT
