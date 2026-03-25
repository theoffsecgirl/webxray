<div align="center">

# webxray

**Escáner ofensivo web: crawling, XSS, SQLi, headers y WAF bypass**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ██████╗ ███████╗ ██████╗  ██╗ ██████╗  █████╗ ██╗  │
│  ██╔══██╗██╔════╝ ██╔══██╗██║██╔══██╗██╔══██╗██║  │
│  ██████╔╝█████╗  ██████╔╝██║██║  ██║███████║██║  │
│  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║╚═╝  │
│  ██║     ███████╗██████╔╝██║██████╔╝██║  ██║██╗  │
│  ╚═╝     ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  │
│                                                      │
│  offensive web scanner  v1.1.0  ·  by theoffsecgirl  │
└──────────────────────────────────────────────────────┘
```

---

## ¿Qué hace?

Escáner ofensivo web escrito en Python que combina crawling, detección de XSS, inyección SQL, análisis de cabeceras de seguridad y detección de WAF con bypass por proveedor. Pensado para bug bounty y pentesting web.

---

## Funcionalidades

- Crawling de la aplicación objetivo
- Detección de XSS reflected (GET y formularios)
- Detección de SQLi GET y POST en formularios
- Análisis de cabeceras de seguridad (6 cabeceras)
- Detección de WAF y bypass por proveedor (`--waf-xss`)
- Exportación de resultados a JSON

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

# Profundidad de crawling
python3 webxray.py -u https://example.com -d 2

# Con bypass WAF
python3 webxray.py -u https://example.com --waf-xss

# Exportar resultados
python3 webxray.py -u https://example.com --json-output resultados.json

# Ver versión
python3 webxray.py --version
```

---

## Parámetros

```text
-u, --url          URL objetivo
-d, --depth        Profundidad de crawling (default: 1)
--no-xss           Omitir XSS
--no-sqli          Omitir SQLi
--no-headers       Omitir cabeceras
--waf-xss          Modo WAF + XSS avanzado (requiere wafw00f)
-t, --timeout      Timeout en segundos (default: 10)
--json-output      Guardar resultados en JSON
    --version      Muestra la versión
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
