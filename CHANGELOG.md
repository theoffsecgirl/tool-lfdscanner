# Changelog

All notable changes to **pathraider** are documented here.

---

## [1.1.0] – 2026-03-24

### Added
- Banner ASCII en arranque.
- `__version__ = "1.1.0"` y flag `--version`.
- Type hints con `typing` (compatible Python 3.8+).
- JSON report incluye `tool`, `version` y `generated_at`.
- User-Agent actualizado: `pathraider/1.1.0`.

### Changed
- Archivo renombrado: `LFDScanner.py` → `pathraider.py`.
- `response_looks_interesting()` simplificada con expresion booleana directa.
- `scan_target()` usa list comprehension para construir futures.

### Removed
- `LFDScanner.py` (reemplazado por `pathraider.py`).

---

## [1.0.0] – 2024-10-06

### Added
- Version inicial: 132 rutas con encodings, concurrencia, exportacion JSON.
