netpulse.py
#!/usr/bin/env python3
"""NetPulse CLI — компактная утилита базовой сетевой диагностики и разведки."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_PORTS = [21, 22, 53, 80, 443, 8080, 8443]
DEFAULT_TIMEOUT = float(os.getenv("NETPULSE_TIMEOUT", "2.5"))
DEFAULT_REPORT_DIR = Path(os.getenv("NETPULSE_OUTPUT_DIR", "reports"))


def normalize_target(raw_target: str) -> str:
    """Очищает ввод от схемы http(s):// и пути, оставляя домен или IP."""
    cleaned = raw_target.strip()
    for prefix in ("https://", "http://"):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    cleaned = cleaned.split("/", 1)[0].split(":", 1)[0].strip()
    return cleaned


def resolve_dns(host: str) -> dict[str, Any]:
    """Получает IPv4/IPv6 адреса и обратное DNS-имя."""
    result: dict[str, Any] = {
        "ipv4": [],
        "ipv6": [],
        "ptr": None,
        "error": None,
    }
    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ipv4_set: list[str] = []
        ipv6_set: list[str] = []
        for item in addr_info:
            sockaddr = item[4]
            ip = sockaddr[0]
            if item[0] == socket.AF_INET and ip not in ipv4_set:
                ipv4_set.append(ip)
            elif item[0] == socket.AF_INET6 and ip not in ipv6_set:
                ipv6_set.append(ip)
        result["ipv4"] = ipv4_set
        result["ipv6"] = ipv6_set

        primary_ip = ipv4_set[0] if ipv4_set else (ipv6_set[0] if ipv6_set else None)
        if primary_ip:
            try:
                ptr_name, _, _ = socket.gethostbyaddr(primary_ip)
                result["ptr"] = ptr_name
            except socket.herror:
                result["ptr"] = None
    except socket.gaierror as exc:
        result["error"] = f"DNS lookup failed: {exc}"
    return result


def check_single_port(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Проверяет TCP-подключение к конкретному порту и измеряет задержку в мс."""
    start = time.perf_counter()
    status = "closed"
    error_msg = None
    try:
        with socket.create_connection((host, port), timeout=timeout):
            status = "open"
    except TimeoutError:
        status = "filtered/timeout"
    except ConnectionRefusedError:
        status = "closed"
    except OSError as exc:
        status = "error"
        error_msg = str(exc)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    return {
        "port": port,
        "status": status,
        "latency_ms": elapsed_ms,
        "error": error_msg,
    }


def scan_ports(host: str, ports: list[int], timeout: float) -> list[dict[str, Any]]:
    """Параллельно проверяет список портов."""
    if not ports:
        return []
    workers = min(len(ports), 16)
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_single_port, host, port, timeout) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["port"])
    return results


def fetch_http_info(host: str, timeout: float) -> dict[str, Any]:
    """Запрашивает заголовки и статус по HTTPS (с fallback на HTTP)."""
    schemes = ("https", "http")
    context = ssl.create_default_context()
    last_error = "Connection failed"

    for scheme in schemes:
        url = f"{scheme}://{host}"
        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={"User-Agent": "NetPulseCLI/1.0"},
        )
        try:
            ssl_ctx = context if scheme == "https" else None
            with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as resp:
                headers_subset = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower()
                    in {
                        "server",
                        "content-type",
                        "strict-transport-security",
                        "x-frame-options",
                        "location",
                    }
                }
                return {
                    "reachable": True,
                    "scheme_used": scheme,
                    "final_url": resp.geturl(),
                    "status_code": resp.status,
                    "headers": headers_subset,
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            return {
                "reachable": True,
                "scheme_used": scheme,
                "final_url": url,
                "status_code": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
                "error": f"HTTP status {exc.code}",
            }
        except Exception as exc:
            last_error = str(exc)

    return {
        "reachable": False,
        "scheme_used": None,
        "final_url": None,
        "status_code": None,
        "headers": {},
        "error": last_error,
    }


def fetch_ip_metadata(ip: str | None, timeout: float) -> dict[str, Any]:
    """Получает базовую сетевую/гео-информацию по IP через бесплатный публичный API."""
    if not ip:
        return {"available": False, "reason": "No IP address resolved"}

    url = f"https://ipwho.is/{ip}"
    request = urllib.request.Request(url, headers={"User-Agent": "NetPulseCLI/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            if not payload.get("success", False):
                return {
                    "available": False,
                    "reason": payload.get("message", "Lookup returned unsuccessful status"),
                }
            connection = payload.get("connection") or {}
            return {
                "available": True,
                "ip": ip,
                "country": payload.get("country"),
                "region": payload.get("region"),
                "city": payload.get("city"),
                "isp": connection.get("isp"),
                "asn": connection.get("asn"),
                "org": connection.get("org"),
            }
    except Exception as exc:
        return {"available": False, "reason": str(exc)}


def run_audit(target: str, ports: list[int], timeout: float, include_geo: bool) -> dict[str, Any]:
    """Запускает полный набор проверок для цели."""
    clean_host = normalize_target(target)
    if not clean_host:
        raise ValueError("Target host cannot be empty.")

    dns_data = resolve_dns(clean_host)
    primary_ip = (
        dns_data["ipv4"][0]
        if dns_data["ipv4"]
        else (dns_data["ipv6"][0] if dns_data["ipv6"] else None)
    )

    port_results = scan_ports(clean_host, ports, timeout) if primary_ip else []
    http_data = (
        fetch_http_info(clean_host, timeout)
        if primary_ip
        else {
            "reachable": False,
            "scheme_used": None,
            "final_url": None,
            "status_code": None,
            "headers": {},
            "error": "Skipped because DNS resolution failed",
        }
    )
    geo_data = (
        fetch_ip_metadata(primary_ip, timeout)
        if include_geo
        else {"available": False, "reason": "Disabled by flag --no-geo"}
    )

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input_target": target,
        "normalized_host": clean_host,
        "dns": dns_data,
        "ports": port_results,
        "http": http_data,
        "ip_info": geo_data,
    }


def print_human_report(report: dict[str, Any]) -> None:
    """Выводит аккуратный отчёт в консоль."""
    print("\n=== NETPULSE CLI REPORT ===")
    print(f"Target : {report['normalized_host']} (input: {report['input_target']})")
    print(f"Time   : {report['timestamp_utc']}")

    dns = report["dns"]
    print("\n[DNS]")
    if dns["error"]:
        print(f"  Error: {dns['error']}")
    else:
        print(f"  IPv4 : {', '.join(dns['ipv4']) if dns['ipv4'] else 'none'}")
        print(f"  IPv6 : {', '.join(dns['ipv6']) if dns['ipv6'] else 'none'}")
        print(f"  PTR  : {dns['ptr'] or 'none'}")

    print("\n[TCP PORTS]")
    if not report["ports"]:
        print("  No ports scanned.")
    else:
        for p in report["ports"]:
            print(f"  Port {p['port']:<5} -> {p['status']:<16} ({p['latency_ms']} ms)")

    http = report["http"]
    print("\n[HTTP / HTTPS]")
    if http["reachable"]:
        print(f"  Status : {http['status_code']} via {str(http['scheme_used']).upper()}")
        print(f"  URL    : {http['final_url']}")
        if http["headers"]:
            print("  Headers:")
            for k, v in http["headers"].items():
                print(f"    {k}: {v}")
    else:
        print(f"  Not reachable ({http['error']})")

    geo = report["ip_info"]
    print("\n[IP NETWORK / GEO]")
    if geo.get("available"):
        loc = ", ".join(
            part for part in (geo.get("city"), geo.get("region"), geo.get("country")) if part
        )
        print(f"  Location : {loc or 'unknown'}")
        print(f"  ASN/ISP  : AS{geo.get('asn')} | {geo.get('isp') or geo.get('org') or 'unknown'}")
    else:
        print(f"  Unavailable ({geo.get('reason')})")
    print()


def save_report(report: dict[str, Any], output_dir: Path) -> Path:
    """Сохраняет JSON-отчёт в директорию отчётов."""
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(
        c if c.isalnum() or c in ("-", "_") else "_" for c in report["normalized_host"]
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    file_path = output_dir / f"{safe_name}_{stamp}.json"
    file_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return file_path


def parse_ports_arg(raw_ports: str | None) -> list[int]:
    """Разбирает строку портов вида '80,443,8000'."""
    if not raw_ports:
        return DEFAULT_PORTS
    ports: list[int] = []
    for chunk in raw_ports.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit():
            raise ValueError(f"Invalid port value: '{chunk}'")
        port_num = int(chunk)
        if not (1 <= port_num <= 65535):
            raise ValueError(f"Port out of range (1-65535): {port_num}")
        if port_num not in ports:
            ports.append(port_num)
    if not ports:
        raise ValueError("Port list cannot be empty.")
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpulse",
        description="NetPulse CLI — базовая диагностика DNS, портов, HTTP/HTTPS и IP-данных.",
    )
    parser.add_argument("target", help="Домен или IP-адрес для проверки (например, example.com)")
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Список портов через запятую (по умолчанию: 21,22,53,80,443,8080,8443)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Таймаут соединения в секундах (по умолчанию: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-geo",
        action="store_true",
        help="Не делать внешний запрос геолокации/ASN по IP",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Не сохранять JSON-отчёт на диск",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports_arg(args.ports)
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        report = run_audit(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            include_geo=not args.no_geo,
        )
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    print_human_report(report)

    if not args.no_save:
        saved_path = save_report(report, DEFAULT_REPORT_DIR)
        print(f"Saved report: {saved_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
