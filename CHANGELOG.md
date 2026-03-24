# Changelog

All notable changes to **webxray** are documented here.

---

## [1.1.0] – 2026-03-24

### Added
- Banner ASCII en arranque.
- `__version__ = "1.1.0"` y flag `--version`.
- SQLi en formularios POST (`sqli_post`).
- Payloads XSS ampliados: `<svg/onload=alert(1)>`, `autofocus onfocus`.
- Keywords SQLi adicionales: `pg::`, `pdo`, `syntax error`, `unclosed quotation`.
- Cabecera `Permissions-Policy` en lista de comprobacion.
- Type hints con `typing` (compatible Python 3.8+).

### Changed
- Archivo renombrado: `webflow.py` → `webxray.py`.
- Docstrings y User-Agent actualizados a `webxray`.
- `str | None` → `Optional[str]` para compatibilidad Python 3.8/3.9.
- `_sqli_hit()` extrae logica de deteccion SQLi como funcion reutilizable.
- Umbral de cambio de tamano en SQLi: 100 → 200 bytes (menos falsos positivos).

### Removed
- `webflow.py` (reemplazado por `webxray.py`).

---

## [1.0.0] – 2023-12-04

### Added
- Version inicial: crawling, XSS GET, SQLi GET, cabeceras, modo `--waf-xss`.
