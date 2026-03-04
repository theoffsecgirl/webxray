# tool-webflow

Escáner básico de vulnerabilidades web escrito en Python.

`webflow` realiza:

- descubrimiento de URLs internas a partir de una URL inicial,
- pruebas heurísticas de XSS reflejado,
- pruebas heurísticas de inyección SQL,
- revisión de cabeceras de seguridad HTTP.

Pensado como **primer filtro ofensivo** para bug bounty y pentesting, no como sustituto de un análisis manual completo.

---

## Características

- Crawling ligero del sitio (profundidad configurable).
- Detección de parámetros en la query string.
- Payloads básicos de XSS.
- Payloads típicos de SQLi con detección por:
  - cambios de código de estado,
  - diferencias de tamaño de respuesta,
  - mensajes de error de base de datos.
- Revisión de cabeceras de seguridad:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Strict-Transport-Security`
- Posibilidad de desactivar XSS / SQLi / headers según necesidad.
- Exportación de resultados a JSON.

---

## Requisitos

- Python 3.8 o superior
- Librerías de Python:

```bash
pip install requests lxml termcolor tqdm
```

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-webflow.git
cd tool-webflow
chmod +x tool-webflow.py
```

Puedes renombrarlo si lo prefieres:

```bash
mv tool-webflow.py webflow.py
chmod +x webflow.py
```

---

## Uso básico

### Escaneo rápido

```bash
python3 tool-webflow.py -u https://example.com
```

Esto:

- descubre URLs internas hasta profundidad 1,
- prueba XSS y SQLi en aquellas que tengan parámetros,
- revisa cabeceras de seguridad.

### Cambiar profundidad de crawling

```bash
python3 tool-webflow.py -u https://example.com -d 2
```

### Desactivar ciertos checks

```bash
# Solo cabeceras de seguridad
python3 tool-webflow.py -u https://example.com --no-xss --no-sqli

# Solo XSS
python3 tool-webflow.py -u https://example.com --no-sqli --no-headers
```

### Exportar resultados a JSON

```bash
python3 tool-webflow.py -u https://example.com --json-output resultados_webflow.json
```

---

## Interpretación de resultados

Ejemplo de detección de XSS:

```text
[!] Posible XSS en https://example.com/search?q=... parámetro 'q' con payload '<script>alert(1)</script>'
```

Ejemplo de posible SQLi:

```text
[!] Posible SQLi en https://example.com/item?id=... parámetro 'id' con payload '' OR 1=1-- - (status 500)
```

Cabeceras de seguridad ausentes:

```text
[!] Cabeceras de seguridad ausentes en https://example.com: Content-Security-Policy, X-Frame-Options
```

Recuerda que el script utiliza **heurísticas**. Todo hallazgo debe ser validado manualmente.

---

## Limitaciones

- No realiza autenticación ni gestión avanzada de sesión.
- No soporta formularios POST ni cuerpos complejos (solo parámetros en URL).
- Las detecciones de XSS y SQLi son básicas y pueden producir falsos positivos o negativos.
- No hace bypass de WAF ni payloads evasivos.

`tool-webflow` está diseñado como herramienta rápida para apoyar el reconocimiento ofensivo, no como un escáner completo.

---

##  Uso ético

Utiliza esta herramienta únicamente en:

- sistemas propios,
- laboratorios,
- o programas de bug bounty donde tengas autorización.

El uso indebido puede ser ilegal y es responsabilidad exclusiva del usuario.

---

## Licencia

Este proyecto está bajo licencia **MIT**.  
Consulta el archivo `LICENSE` para más detalles.
