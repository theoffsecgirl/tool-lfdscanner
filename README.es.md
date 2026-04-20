# pathraider

Escáner ofensivo de Local File Disclosure y Directory Traversal.

> 🇬🇧 [English version](README.md)

---

## ¿Qué hace?

Comprueba si un parámetro permite leer archivos locales del sistema (LFD / Path Traversal) generando variantes de traversal y bypass de encoding.

Importante: los findings son candidatos, no vulnerabilidades confirmadas.

---

## Funcionalidades

- Un objetivo (`--url`) o múltiples (`--list`)
- Inyección con `FUZZ` o parámetro (`--param`)
- Variantes de traversal con múltiples encodings
- Detección heurística de contenido sensible
- Escaneo concurrente
- Output normalizado
- Exportación JSON / JSONL
- Modo `stdout` para pipelines
- Manejo limpio de `Ctrl+C`

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/pathraider.git
cd pathraider
pip install -e .
```

---

## Uso

```bash
pathraider -u "https://example.com/download.php?file=FUZZ"
```

### Pipeline

```bash
pathraider -u "https://target.com/download?file=FUZZ" --format jsonl --stdout | bbcopilot ingest pathraider -
```

### Guardar findings

```bash
pathraider -L scope.txt --format jsonl --findings-output findings.jsonl
```

---

## Parámetros

```text
-u, --url                URL objetivo (puede contener FUZZ)
-L, --list               Archivo con objetivos
--paths                  Rutas personalizadas
-p, --param              Parámetro (default: file)
-t, --timeout            Timeout por request
-T, --threads            Hilos
-A, --agent              User-Agent
--insecure               Sin verificación TLS
--json-output            Informe JSON clásico
--format json|jsonl      Formato de findings
--stdout                 Output por stdout
--findings-output        Guardar findings
-v, --verbose            Verbose
--version                Versión
```

---

## Notas

- Logs → `stderr`
- Findings → `stdout`
- Ctrl+C limpio
- Pensado para recon y pipelines

---

## Uso ético

Solo para entornos autorizados.

---

## Licencia

MIT
