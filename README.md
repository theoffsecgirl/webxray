<div align="center">

# webxray

**Escáner ofensivo web: crawling, XSS, SQLi, headers y WAF bypass**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ██████╗ ███████╗ ██████╗  ██╗ ██████╗  █████╗ ██╗   │
│  ██╔══██╗██╔════╝ ██╔══██╗██║██╔══██╗██╔══██╗██║   │
│  ██████╔╝█████╗  ██████╔╝██║██║  ██║███████║██║   │
│  ██╔══██╗██╔══╝  ██╔══██╗██║██║  ██║██╔══██║╚═╝   │
│  ██████╔╝███████╗██████╔╝██║██████╔╝██║  ██║██╗   │
│  ╚═════╝ ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝   │
│                                                      │
│        offensive web scanner  ·  by theoffsecgirl    │
└──────────────────────────────────────────────────────┘
```

---

## ¿Qué hace?

Escáner ofensivo web escrito en Python que combina crawling, detección de XSS, inyección SQL, análisis de cabeceras de seguridad y detección de WAF con bypass por proveedor. Pensado para bug bounty y pentesting web.

---

## Funcionalidades

- Crawling de la aplicación objetivo
- Detección de XSS (reflected, DOM)
- Detección de SQLi
- Análisis de cabeceras de seguridad
- Detección de WAF y bypass por proveedor (`--waf-xss`)
- Soporte para scope personalizado
- Exportación de resultados

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/webxray.git
cd webxray
pip install -r requirements.txt
```

---

## Uso

```bash
# Escaneo básico
python3 webxray.py -u https://example.com

# Con bypass WAF
python3 webxray.py -u https://example.com --waf-xss

# Verbose
python3 webxray.py -u https://example.com -v
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
