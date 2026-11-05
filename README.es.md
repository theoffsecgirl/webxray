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

Escáner ofensivo web escrito en Python que combina crawling, detección de XSS, inyección SQL, análisis de cabeceras de seguridad y detección de WAF con bypass por proveedor. Pensado para bug bounty y pentesting web.

---

## Funcionalidades

- Crawling de la aplicación objetivo
- Detección de XSS reflected (GET y formularios)
- Detección de SQLi GET y POST en formularios
- Análisis de cabeceras de seguridad (6 cabeceras)
- Detección de WAF y bypass por proveedor (`--waf-xss`)
- Exportación de resultados a JSON / JSONL

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

# Bug bounty: cabecera identificativa, sesión autenticada y límite de peticiones
python3 webxray.py -u https://target.com -H "X-Bugbounty: miusuario" -c "session=..." --rate 5

# A través de Burp
python3 webxray.py -u https://target.com -x http://127.0.0.1:8080 -k

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
-H, --header       Cabecera extra, repetible ('Nombre: valor')
-c, --cookie       Cookies para zonas autenticadas
-x, --proxy        Proxy HTTP(S), p. ej. Burp
-k, --insecure     No verificar TLS
--rate             Máximo de peticiones por segundo
--json-output      Guardar resultados en JSON/JSONL
--format           Formato de salida para export y stdout (json|jsonl)
--stdout           Enviar findings normalizados a stdout
    --version      Muestra la versión
```

> `-H`, `-c`, `-x`, `-k` y `--rate` se aplican a todas las peticiones de webxray, crawler incluido. En `--waf-xss`, la detección del WAF la hace `wafw00f`, que no las recibe.

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
