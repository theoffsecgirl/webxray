<div align="center">

```
 ██╗    ██╗███████╗██████╗ ███████╗██╗      ██████╗ ██╗    ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║
 ██║ █╗ ██║█████╗  ██████╔╝█████╗  ██║     ██║   ██║██║ █╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║███╗██║
 ╚███╔███╔╝███████╗██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
```

**Escáner ofensivo de vulnerabilidades web**  
*by [TheOffSecGirl](https://github.com/theoffsecgirl)*

![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![BugBounty](https://img.shields.io/badge/Bug%20Bounty-Ready-brightgreen?style=flat-square)

</div>

---

## ¿Qué es tool-webflow?

`tool-webflow` es un escáner ofensivo en Python diseñado como **primer filtro rápido** para bug bounty y pentesting web. Combina crawling ligero, detección de vulnerabilidades comunes y — con el flag `--waf-xss` — detección de WAF con payloads específicos de bypass.

---

## Funcionalidades

| Módulo | Descripción |
|--------|-------------|
| 🕷️ Crawling | Descubrimiento de URLs internas con profundidad configurable |
| 🔥 XSS | Payloads básicos reflejados sobre parámetros de URL |
| 💉 SQLi | Heurísticas por código de estado, tamaño de respuesta y errores DB |
| 🔒 Headers | Revisión de cabeceras de seguridad HTTP ausentes |
| 🛡️ WAF + XSS | Detección de WAF + payloads bypass específicos por proveedor |

**WAFs soportados en modo `--waf-xss`:**  
Akamai · Cloudflare · CloudFront · ModSecurity · Imperva · Sucuri

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-webflow.git
cd tool-webflow
pip install -r requirements.txt
```

> El modo `--waf-xss` requiere además: `pip install wafw00f`

---

## Uso

### Escaneo estándar

```bash
python3 webflow.py -u https://example.com
```

### Cambiar profundidad de crawling

```bash
python3 webflow.py -u https://example.com -d 2
```

### Solo XSS (sin SQLi ni headers)

```bash
python3 webflow.py -u https://example.com --no-sqli --no-headers
```

### Modo WAF + XSS avanzado

```bash
python3 webflow.py -u https://example.com --waf-xss
```

Este modo:
1. Detecta el WAF presente (via `wafw00f`).
2. Selecciona payloads XSS específicos de bypass para ese WAF.
3. Prueba parámetros URL **y** formularios HTML.

Ejemplo de salida:

```text
[+] tool-webflow – Web scanner by TheOffSecGirl
[+] Iniciando modo WAF + XSS avanzado...
[!] WAF detectado: Cloudflare
[+] Usando payloads específicos para cloudflare.
[!] [WAF-XSS] Posible XSS en 'q' con payload: <Svg Only=1 OnLoad=confirm(document.cookie)>
[+] Escaneo completado. Hallazgos totales: 1
```

### Exportar a JSON

```bash
python3 webflow.py -u https://example.com --json-output resultados.json
```

---

## Flags disponibles

| Flag | Descripción |
|------|-------------|
| `-u`, `--url` | URL objetivo (**requerido**) |
| `-d`, `--depth` | Profundidad de crawling (default: 1) |
| `--no-xss` | Deshabilitar XSS básico |
| `--no-sqli` | Deshabilitar SQLi |
| `--no-headers` | Deshabilitar revisión de headers |
| `--waf-xss` | Activar modo WAF + XSS avanzado |
| `-t`, `--timeout` | Timeout HTTP en segundos (default: 10) |
| `--json-output` | Exportar hallazgos a JSON |

---

## Limitaciones

- No gestiona autenticación ni sesiones complejas.
- Las detecciones son heurísticas → validar manualmente todo hallazgo.
- El modo `--waf-xss` requiere `wafw00f` instalado en el sistema.

---

## Uso ético

> Usa esta herramienta **solo en sistemas propios, laboratorios o programas de bug bounty con autorización explícita.**  
> El uso indebido puede ser ilegal y es responsabilidad exclusiva del usuario.

---

## Licencia

MIT · [TheOffSecGirl](https://theoffsecgirl.com)
