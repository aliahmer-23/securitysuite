#!/usr/bin/env python3

import argparse
import concurrent.futures
import hashlib
import html
import ipaddress
import json
import socket
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = "6.0.0"
SCHEMA_VERSION = "1.0"

DEFAULT_TIMEOUT = 0.6
DEFAULT_WORKERS = 150
REPORT_DIR = Path("reports")

PROFILE_PORTS = {
    "quick": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
        389, 443, 445, 465, 587, 631, 993, 995, 1433, 1521,
        2049, 2375, 3000, 3306, 3389, 5432, 5601, 5900, 6379,
        8000, 8080, 8081, 8443, 8888, 9200, 27017
    ],
    "web": [
        80, 443, 3000, 3001, 4000, 5000, 5001, 7001,
        8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443
    ],
}

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    2375: "Docker API",
    3389: "RDP",
    5900: "VNC",
}

MEDIUM_RISK_PORTS = {
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

WEB_PORTS = {
    80, 443, 3000, 3001, 4000, 5000, 5001, 7001,
    8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443
}

TLS_PORTS = {443, 465, 993, 995, 8443, 9443}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def banner():
    print(f"""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                     NETSCOUT v{VERSION}                       ║
║             Network Security Assessment Engine             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")


def normalize_target(value):
    target = (value or "").strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    # Accept URLs too, but only use the host.
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("Could not extract a hostname from the URL.")
        target = parsed.hostname

    return target


def resolve_target(target):
    target = normalize_target(target)

    try:
        ip_obj = ipaddress.ip_address(target)
        return {
            "input": target,
            "resolved_ip": str(ip_obj),
            "addresses": [str(ip_obj)],
            "ip_version": ip_obj.version,
            "is_ip": True,
        }
    except ValueError:
        pass

    try:
        entries = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from exc

    addresses = []
    for entry in entries:
        address = entry[4][0]
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise ValueError(f"No IP address found for '{target}'.")

    # Prefer IPv4 for this scanner version because scan_port uses AF_INET.
    ipv4 = [a for a in addresses if ":" not in a]
    selected = ipv4[0] if ipv4 else addresses[0]

    ip_obj = ipaddress.ip_address(selected)

    return {
        "input": target,
        "resolved_ip": selected,
        "addresses": addresses,
        "ip_version": ip_obj.version,
        "is_ip": False,
    }


def validate_authorized_scope(resolved_ip):
    """
    NetScout does not attempt to decide whether a target is authorized.
    This function only returns useful scope metadata for reporting.
    """
    ip_obj = ipaddress.ip_address(resolved_ip)
    return {
        "private": ip_obj.is_private,
        "loopback": ip_obj.is_loopback,
        "link_local": ip_obj.is_link_local,
        "multicast": ip_obj.is_multicast,
        "reserved": ip_obj.is_reserved,
    }


def build_ports(profile, start_port=None, end_port=None):
    if start_port is not None or end_port is not None:
        start = 1 if start_port is None else start_port
        end = 1024 if end_port is None else end_port

        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port range.")

        return list(range(start, end + 1)), f"custom:{start}-{end}"

    if profile == "quick":
        return sorted(PROFILE_PORTS["quick"]), profile

    if profile == "web":
        return sorted(PROFILE_PORTS["web"]), profile

    if profile == "standard":
        return list(range(1, 1025)), profile

    if profile == "full":
        return list(range(1, 65536)), profile

    raise ValueError(f"Unknown profile: {profile}")


def port_risk(port):
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


def scan_port(target_ip, port, timeout):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET

    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service_guess": get_service_guess(port),
                    "port_risk": port_risk(port),
                }
    except (OSError, socket.error):
        pass

    return None


def get_service_guess(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_ports(target_ip, ports, timeout, workers):
    results = []
    total = len(ports)
    completed = 0

    print(f"[+] Discovery: scanning {total} TCP ports")
    print(f"[+] Workers: {workers}")
    print()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(futures):
            completed += 1

            try:
                result = future.result()
            except Exception:
                result = None

            if result:
                results.append(result)

            if total:
                percent = (completed / total) * 100
                print(
                    f"\rScanning {percent:6.2f}% "
                    f"| Open: {len(results)}",
                    end="",
                    flush=True,
                )

    print()
    results.sort(key=lambda item: item["port"])
    return results


def safe_recv(sock, size=2048):
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""


def generic_banner(target_ip, port, timeout):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET

    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_ip, port))

            # Some services send a banner immediately.
            data = safe_recv(sock, 2048)
            if data:
                return clean_text(data.decode("utf-8", errors="replace"))[:500]

            # Safe generic CRLF probe for text protocols.
            try:
                sock.sendall(b"\r\n")
                data = safe_recv(sock, 2048)
                if data:
                    return clean_text(
                        data.decode("utf-8", errors="replace")
                    )[:500]
            except OSError:
                pass

    except (socket.timeout, OSError):
        pass

    return None


def clean_text(value):
    return " ".join(str(value).replace("\x00", " ").split())


def parse_http_response(raw):
    text = raw.decode("iso-8859-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")

    status_line = lines[0] if lines else ""
    headers = {}

    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    title = None
    lower_body = body.lower()

    start = lower_body.find("<title")
    if start != -1:
        start = lower_body.find(">", start)
        end = lower_body.find("</title>", start)
        if start != -1 and end != -1:
            title = clean_text(body[start + 1:end])[:200]

    return {
        "status_line": clean_text(status_line),
        "headers": headers,
        "title": title,
    }


def http_probe(target_name, target_ip, port, timeout, use_tls=False):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_name}\r\n"
        "User-Agent: NetScout/6.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    raw = b""

    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(max(timeout, 1.2))
            raw_sock.connect((target_ip, port))

            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with context.wrap_socket(
                    raw_sock,
                    server_hostname=target_name if not _is_ip(target_name) else None,
                ) as sock:
                    sock.settimeout(max(timeout, 1.2))
                    sock.sendall(request)

                    while len(raw) < 65536:
                        chunk = safe_recv(sock, 4096)
                        if not chunk:
                            break
                        raw += chunk
            else:
                raw_sock.sendall(request)
                while len(raw) < 65536:
                    chunk = safe_recv(raw_sock, 4096)
                    if not chunk:
                        break
                    raw += chunk

    except (ssl.SSLError, socket.timeout, OSError):
        return None

    if not raw:
        return None

    parsed = parse_http_response(raw)
    parsed["scheme"] = "https" if use_tls else "http"
    parsed["body_sample_hash"] = hashlib.sha256(raw[:8192]).hexdigest()
    return parsed


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def tls_probe(target_name, target_ip, port, timeout):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(max(timeout, 1.5))
            raw_sock.connect((target_ip, port))

            with context.wrap_socket(
                raw_sock,
                server_hostname=target_name if not _is_ip(target_name) else None,
            ) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                version = sock.version()

                return {
                    "version": version,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "certificate_subject": cert.get("subject"),
                    "certificate_issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }

    except (ssl.SSLError, socket.timeout, OSError):
        return None


def fingerprint_service(target_name, target_ip, port, timeout):
    service_guess = get_service_guess(port)

    # Try HTTPS first on known TLS ports.
    if port in TLS_PORTS:
        web = http_probe(
            target_name,
            target_ip,
            port,
            timeout,
            use_tls=True,
        )
        tls = tls_probe(
            target_name,
            target_ip,
            port,
            timeout,
        )
        if web:
            return {
                "detected_service": "https",
                "application": identify_web_application(web),
                "banner": None,
                "http": web,
                "tls": tls,
            }

    # Try plain HTTP on likely web ports.
    if port in WEB_PORTS:
        web = http_probe(
            target_name,
            target_ip,
            port,
            timeout,
            use_tls=False,
        )
        if web:
            return {
                "detected_service": "http",
                "application": identify_web_application(web),
                "banner": None,
                "http": web,
                "tls": None,
            }

        # Some custom web ports may actually speak HTTPS.
        web_tls = http_probe(
            target_name,
            target_ip,
            port,
            timeout,
            use_tls=True,
        )
        if web_tls:
            tls = tls_probe(
                target_name,
                target_ip,
                port,
                timeout,
            )
            return {
                "detected_service": "https",
                "application": identify_web_application(web_tls),
                "banner": None,
                "http": web_tls,
                "tls": tls,
            }

    banner = generic_banner(target_ip, port, max(timeout, 1.0))
    detected = identify_from_banner(service_guess, banner)

    return {
        "detected_service": detected,
        "application": identify_application_banner(banner),
        "banner": banner,
        "http": None,
        "tls": None,
    }


def identify_from_banner(service_guess, banner):
    if not banner:
        return service_guess

    lower = banner.lower()

    if "ssh-" in lower or "openssh" in lower:
        return "ssh"
    if "ftp" in lower:
        return "ftp"
    if "smtp" in lower or lower.startswith("220"):
        return "smtp"
    if "redis" in lower:
        return "redis"
    if "mysql" in lower:
        return "mysql"

    return service_guess


def identify_application_banner(banner):
    if not banner:
        return None

    value = clean_text(banner)

    for marker in (
        "OpenSSH",
        "nginx",
        "Apache",
        "Microsoft-IIS",
        "Postfix",
        "Exim",
        "vsFTPd",
        "ProFTPD",
    ):
        if marker.lower() in value.lower():
            return value[:200]

    return None


def identify_web_application(web):
    headers = {
        str(k).lower(): str(v)
        for k, v in web.get("headers", {}).items()
    }

    clues = []

    server = headers.get("server")
    powered = headers.get("x-powered-by")

    if server:
        clues.append(server)

    if powered:
        clues.append(powered)

    title = web.get("title")
    if title:
        clues.append(title)

    if clues:
        return " | ".join(clues)[:300]

    return None


def finding(
    finding_id,
    severity,
    title,
    category,
    port,
    service,
    observation,
    recommendation,
    evidence=None,
):
    return {
        "id": finding_id,
        "source": "NetScout",
        "severity": severity,
        "title": title,
        "category": category,
        "port": port,
        "service": service,
        "observation": observation,
        "recommendation": recommendation,
        "evidence": evidence or [],
        "status": "OPEN",
    }


def analyze_service(service_record):
    findings = []

    port = service_record["port"]
    detected = service_record.get("detected_service") or "unknown"
    banner = service_record.get("banner")
    http = service_record.get("http")
    tls = service_record.get("tls")

    if port == 21 or detected == "ftp":
        findings.append(
            finding(
                "NET-FTP-001",
                "HIGH",
                "FTP service exposed",
                "Network Service",
                port,
                detected,
                "FTP is reachable. Traditional FTP commonly transmits authentication and data without modern transport encryption.",
                "Prefer SFTP/SSH or another encrypted file-transfer protocol and restrict access to trusted networks.",
                [banner] if banner else [f"TCP/{port} accepted a connection"],
            )
        )

    if port == 23 or detected == "telnet":
        findings.append(
            finding(
                "NET-TELNET-001",
                "HIGH",
                "Telnet service exposed",
                "Network Service",
                port,
                detected,
                "Telnet is reachable and does not provide modern encrypted transport.",
                "Disable Telnet and use SSH or another encrypted management protocol.",
                [banner] if banner else [f"TCP/{port} accepted a connection"],
            )
        )

    if port == 22 or detected == "ssh":
        findings.append(
            finding(
                "NET-SSH-001",
                "MEDIUM",
                "SSH service reachable",
                "Remote Administration",
                port,
                detected,
                "An SSH service is reachable from the assessment host.",
                "Restrict SSH to trusted administration networks, enforce strong authentication, and keep the service patched.",
                [banner] if banner else [f"TCP/{port} accepted a connection"],
            )
        )

    if port == 445 or detected in ("microsoft-ds", "smb"):
        findings.append(
            finding(
                "NET-SMB-001",
                "HIGH",
                "SMB service reachable",
                "Network Service",
                port,
                detected,
                "SMB is reachable. Exposure to untrusted networks increases attack surface.",
                "Restrict SMB with firewall policy and network segmentation.",
                [f"TCP/{port} accepted a connection"],
            )
        )

    if port == 3389 or detected in ("ms-wbt-server", "rdp"):
        findings.append(
            finding(
                "NET-RDP-001",
                "HIGH",
                "RDP service reachable",
                "Remote Administration",
                port,
                detected,
                "Remote Desktop Protocol is reachable from the assessment host.",
                "Restrict RDP to trusted administration paths and enforce strong authentication.",
                [f"TCP/{port} accepted a connection"],
            )
        )

    if banner:
        lower = banner.lower()
        if any(token in lower for token in ("openssh", "server:", "apache", "nginx", "iis")):
            findings.append(
                finding(
                    "INFO-BANNER-001",
                    "LOW",
                    "Service software information disclosed",
                    "Information Disclosure",
                    port,
                    detected,
                    "The service response reveals software or implementation details.",
                    "Review whether software-identifying banners are necessary and avoid exposing unnecessary version detail.",
                    [banner[:300]],
                )
            )

    if http:
        findings.extend(analyze_http(port, detected, http))

    if tls:
        findings.extend(analyze_tls(port, detected, tls))

    return findings


def analyze_http(port, service, http):
    findings = []
    headers_original = http.get("headers", {})
    headers = {str(k).lower(): str(v) for k, v in headers_original.items()}
    scheme = http.get("scheme", "http")

    evidence_base = []
    if http.get("status_line"):
        evidence_base.append(http["status_line"])
    if http.get("title"):
        evidence_base.append(f"Title: {http['title']}")
    if headers.get("server"):
        evidence_base.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        evidence_base.append(f"X-Powered-By: {headers['x-powered-by']}")

    if scheme == "http":
        findings.append(
            finding(
                "WEB-HTTP-001",
                "LOW",
                "Unencrypted HTTP service reachable",
                "Web Security",
                port,
                service,
                "The web service is reachable over HTTP without TLS transport protection.",
                "Use HTTPS for sensitive applications and redirect plain HTTP to HTTPS where appropriate.",
                evidence_base or [f"HTTP detected on TCP/{port}"],
            )
        )

    security_headers = {
        "content-security-policy": (
            "WEB-HDR-001",
            "MEDIUM",
            "Missing Content-Security-Policy",
            "Define an appropriate Content-Security-Policy to reduce client-side content injection risk.",
        ),
        "x-content-type-options": (
            "WEB-HDR-002",
            "LOW",
            "Missing X-Content-Type-Options",
            "Set X-Content-Type-Options: nosniff where appropriate.",
        ),
        "x-frame-options": (
            "WEB-HDR-003",
            "MEDIUM",
            "Missing clickjacking protection header",
            "Use X-Frame-Options or an equivalent frame-ancestors CSP directive.",
        ),
        "referrer-policy": (
            "WEB-HDR-004",
            "LOW",
            "Missing Referrer-Policy",
            "Set a suitable Referrer-Policy for the application's privacy and functionality requirements.",
        ),
    }

    for header_name, values in security_headers.items():
        if header_name not in headers:
            fid, severity, title, recommendation = values
            findings.append(
                finding(
                    fid,
                    severity,
                    title,
                    "HTTP Security Headers",
                    port,
                    service,
                    f"The HTTP response did not contain the {header_name} header.",
                    recommendation,
                    evidence_base or [http.get("status_line", "HTTP response received")],
                )
            )

    if scheme == "https" and "strict-transport-security" not in headers:
        findings.append(
            finding(
                "WEB-HDR-005",
                "LOW",
                "Missing Strict-Transport-Security",
                "HTTP Security Headers",
                port,
                service,
                "The HTTPS response did not contain a Strict-Transport-Security header.",
                "Consider enabling HSTS after confirming that the application should be HTTPS-only.",
                evidence_base or [http.get("status_line", "HTTPS response received")],
            )
        )

    if headers.get("x-powered-by"):
        findings.append(
            finding(
                "INFO-WEB-001",
                "LOW",
                "Web technology disclosure",
                "Information Disclosure",
                port,
                service,
                "The application exposes implementation information in the X-Powered-By header.",
                "Remove or minimize unnecessary technology disclosure headers where operationally appropriate.",
                [f"X-Powered-By: {headers['x-powered-by']}"],
            )
        )

    if headers.get("server"):
        findings.append(
            finding(
                "INFO-WEB-002",
                "LOW",
                "Web server information disclosed",
                "Information Disclosure",
                port,
                service,
                "The Server header discloses web-server information.",
                "Reduce unnecessary server banner detail where supported.",
                [f"Server: {headers['server']}"],
            )
        )

    return findings


def analyze_tls(port, service, tls):
    findings = []

    version = tls.get("version")
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            finding(
                "TLS-001",
                "HIGH",
                "Legacy TLS protocol negotiated",
                "Transport Security",
                port,
                service,
                f"The service negotiated {version}.",
                "Disable legacy SSL/TLS versions and allow modern TLS configurations only.",
                [f"Negotiated protocol: {version}"],
            )
        )

    return findings


def enumerate_services(target_name, target_ip, open_ports, timeout, workers):
    if not open_ports:
        return []

    print(f"[+] Enumeration: fingerprinting {len(open_ports)} open services")

    services = []

    def task(item):
        fingerprint = fingerprint_service(
            target_name,
            target_ip,
            item["port"],
            timeout,
        )
        return {**item, **fingerprint}

    enum_workers = min(max(4, workers // 4), 40)

    with concurrent.futures.ThreadPoolExecutor(max_workers=enum_workers) as executor:
        futures = [executor.submit(task, item) for item in open_ports]

        for future in concurrent.futures.as_completed(futures):
            try:
                services.append(future.result())
            except Exception:
                pass

    services.sort(key=lambda item: item["port"])
    return services


def analyze_services(services):
    findings = []

    for service in services:
        findings.extend(analyze_service(service))

    # Stable IDs for repeated header findings on multiple ports.
    counts = {}
    for item in findings:
        base = item["id"]
        counts[base] = counts.get(base, 0) + 1
        if counts[base] > 1:
            item["id"] = f"{base}-{counts[base]:02d}"

    return findings


def calculate_risk(findings):
    weights = {
        "CRITICAL": 25,
        "HIGH": 12,
        "MEDIUM": 6,
        "LOW": 2,
        "INFO": 0,
    }

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    raw_score = 0

    for item in findings:
        severity = str(item.get("severity", "INFO")).upper()
        raw_score += weights.get(severity, 0)
        key = severity.lower()
        if key in counts:
            counts[key] += 1

    score = min(raw_score, 100)

    if score >= 80:
        rating = "CRITICAL"
    elif score >= 55:
        rating = "HIGH"
    elif score >= 25:
        rating = "MEDIUM"
    elif score > 0:
        rating = "LOW"
    else:
        rating = "PASS"

    return {
        "score": score,
        "rating": rating,
        "raw_score": raw_score,
        "counts": counts,
        "total_findings": len(findings),
    }


def build_asset(target_info, scope, services):
    return {
        "asset_id": f"host:{target_info['resolved_ip']}",
        "hostname": target_info["input"] if not target_info["is_ip"] else None,
        "ip": target_info["resolved_ip"],
        "ip_version": target_info["ip_version"],
        "scope": scope,
        "services": services,
    }


def build_report(
    scan_id,
    target_info,
    scope,
    profile,
    ports,
    services,
    findings,
    risk,
    started_at,
    completed_at,
    duration,
):
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "NetScout",
        "version": VERSION,
        "scan_id": scan_id,
        "target": target_info,
        "profile": profile,
        "scope": scope,
        "timing": {
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": round(duration, 3),
        },
        "statistics": {
            "ports_scanned": len(ports),
            "open_ports": len(services),
            "total_findings": len(findings),
            "critical_findings": risk["counts"]["critical"],
            "high_findings": risk["counts"]["high"],
            "medium_findings": risk["counts"]["medium"],
            "low_findings": risk["counts"]["low"],
            "info_findings": risk["counts"]["info"],
        },
        "risk": risk,
        "assets": [
            build_asset(
                target_info,
                scope,
                services,
            )
        ],
        "services": services,
        "findings": findings,
    }


def save_json_report(report, output_path=None):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if output_path:
        filename = Path(output_path).expanduser().resolve()
        filename.parent.mkdir(parents=True, exist_ok=True)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = REPORT_DIR / (
            f"netscout_{timestamp}_{report['scan_id'][:8]}.json"
        )

    with open(filename, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    return filename


def save_html_report(report):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / (
        f"netscout_{timestamp}_{report['scan_id'][:8]}.html"
    )

    services_rows = []
    for item in report["services"]:
        http_info = item.get("http") or {}
        app = item.get("application") or "-"
        status = http_info.get("status_line") or "-"

        services_rows.append(
            "<tr>"
            f"<td>{item['port']}</td>"
            f"<td>{html.escape(str(item.get('detected_service') or '-'))}</td>"
            f"<td>{html.escape(str(app))}</td>"
            f"<td>{html.escape(str(status))}</td>"
            "</tr>"
        )

    finding_cards = []
    for item in report["findings"]:
        evidence = "<br>".join(
            html.escape(str(value))
            for value in item.get("evidence", [])
        ) or "No additional evidence captured."

        finding_cards.append(
            f"""
            <div class="finding">
                <div class="finding-head">
                    <span class="sev {item['severity'].lower()}">
                        {html.escape(item['severity'])}
                    </span>
                    <strong>{html.escape(item['id'])}</strong>
                    — {html.escape(item['title'])}
                </div>
                <p><b>Port:</b> {item['port']}</p>
                <p><b>Category:</b> {html.escape(item['category'])}</p>
                <p><b>Observation:</b> {html.escape(item['observation'])}</p>
                <p><b>Evidence:</b><br>{evidence}</p>
                <p><b>Recommendation:</b> {html.escape(item['recommendation'])}</p>
            </div>
            """
        )

    if not finding_cards:
        finding_cards.append("<p>No security findings generated.</p>")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScout Security Assessment</title>
<style>
body {{
    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
    margin: 0;
    background: #f4f6f8;
    color: #172033;
}}
.container {{
    max-width: 1200px;
    margin: 32px auto;
    padding: 0 20px;
}}
.hero, .section {{
    background: white;
    border-radius: 14px;
    padding: 26px;
    margin-bottom: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,.06);
}}
.hero {{
    background: #111827;
    color: white;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit,minmax(150px,1fr));
    gap: 12px;
}}
.card {{
    background: white;
    border-radius: 12px;
    padding: 18px;
}}
.hero .card {{
    background: #1f2937;
}}
.big {{
    font-size: 30px;
    font-weight: 800;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th,td {{
    border-bottom: 1px solid #e5e7eb;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}
.finding {{
    border-left: 5px solid #9ca3af;
    background: #f9fafb;
    border-radius: 8px;
    padding: 16px;
    margin: 14px 0;
}}
.finding-head {{
    font-size: 17px;
}}
.sev {{
    padding: 4px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 800;
    margin-right: 8px;
}}
.critical,.high {{ color: #991b1b; background: #fee2e2; }}
.medium {{ color: #92400e; background: #fef3c7; }}
.low {{ color: #1e40af; background: #dbeafe; }}
.info {{ color: #374151; background: #e5e7eb; }}
.small {{ color: #cbd5e1; }}
</style>
</head>
<body>
<div class="container">

<div class="hero">
<h1>NetScout Security Assessment</h1>
<p class="small">NetScout v{VERSION} • Schema {SCHEMA_VERSION}</p>
<p><b>Scan ID:</b> {html.escape(report['scan_id'])}</p>
<p><b>Target:</b> {html.escape(report['target']['input'])}
({html.escape(report['target']['resolved_ip'])})</p>
<p><b>Profile:</b> {html.escape(report['profile'])}</p>

<div class="grid">
<div class="card"><div>Risk Score</div>
<div class="big">{report['risk']['score']}/100</div></div>
<div class="card"><div>Overall Risk</div>
<div class="big">{report['risk']['rating']}</div></div>
<div class="card"><div>Ports Scanned</div>
<div class="big">{report['statistics']['ports_scanned']}</div></div>
<div class="card"><div>Open Ports</div>
<div class="big">{report['statistics']['open_ports']}</div></div>
<div class="card"><div>Findings</div>
<div class="big">{report['statistics']['total_findings']}</div></div>
</div>
</div>

<div class="section">
<h2>Discovered Services</h2>
<table>
<thead>
<tr><th>Port</th><th>Service</th><th>Application</th><th>HTTP Status</th></tr>
</thead>
<tbody>
{''.join(services_rows) if services_rows else '<tr><td colspan="4">No open ports detected.</td></tr>'}
</tbody>
</table>
</div>

<div class="section">
<h2>Security Findings</h2>
{''.join(finding_cards)}
</div>

<div class="section">
<h2>Assessment Metadata</h2>
<p><b>Started:</b> {html.escape(report['timing']['started_at'])}</p>
<p><b>Completed:</b> {html.escape(report['timing']['completed_at'])}</p>
<p><b>Duration:</b> {report['timing']['duration_seconds']} seconds</p>
<p><b>Authorized testing:</b> This report is intended for systems you own or are explicitly authorized to assess.</p>
</div>

</div>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as handle:
        handle.write(html_doc)

    return filename


def display_summary(report):
    print("\n" + "─" * 72)
    print("NETSCOUT SUMMARY")
    print("─" * 72)
    print(f"Target:           {report['target']['input']}")
    print(f"Resolved IP:      {report['target']['resolved_ip']}")
    print(f"Profile:          {report['profile']}")
    print(f"Ports scanned:    {report['statistics']['ports_scanned']}")
    print(f"Open ports:       {report['statistics']['open_ports']}")
    print(f"Findings:         {report['statistics']['total_findings']}")
    print(f"Risk score:       {report['risk']['score']}/100")
    print(f"Overall risk:     {report['risk']['rating']}")
    print("─" * 72)

    if report["services"]:
        print("\nDISCOVERED SERVICES")
        print("─" * 72)

        for item in report["services"]:
            app = item.get("application") or "-"
            print(
                f"{item['port']:>5}/tcp  "
                f"{item.get('detected_service', 'unknown'):<12} "
                f"{app}"
            )

    if report["findings"]:
        print("\nSECURITY FINDINGS")
        print("─" * 72)

        for item in report["findings"]:
            print(
                f"[{item['severity']}] "
                f"{item['id']} | "
                f"{item['title']} "
                f"(port {item['port']})"
            )


def build_parser():
    parser = argparse.ArgumentParser(
        description="NetScout - Network Security Assessment Engine"
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Authorized IP address, hostname, or URL",
    )

    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "full", "web"],
        default="standard",
        help="Scan profile (default: standard)",
    )

    parser.add_argument(
        "--start",
        type=int,
        help="Custom start port (overrides profile)",
    )

    parser.add_argument(
        "--end",
        type=int,
        help="Custom end port (overrides profile)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent discovery workers (default: {DEFAULT_WORKERS})",
    )

    parser.add_argument(
        "--json-output",
        help="Write structured JSON to this exact path",
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Do not generate the HTML report",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce terminal output",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NetScout {VERSION}",
    )

    return parser


def main():
    args = build_parser().parse_args()

    if not args.quiet:
        banner()

    target = args.target

    if not target:
        try:
            target = input("Authorized target IP, hostname, or URL: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Scan cancelled.")
            return 130

    try:
        target_info = resolve_target(target)
        ports, selected_profile = build_ports(
            args.profile,
            args.start,
            args.end,
        )
    except ValueError as exc:
        print(f"[-] {exc}")
        return 1

    if args.timeout <= 0:
        print("[-] Timeout must be greater than zero.")
        return 1

    if args.workers < 1 or args.workers > 1000:
        print("[-] Workers must be between 1 and 1000.")
        return 1

    scope = validate_authorized_scope(
        target_info["resolved_ip"]
    )

    scan_id = str(uuid.uuid4())
    started_at = now_iso()
    started_perf = time.perf_counter()

    if not args.quiet:
        print(f"[+] Scan ID: {scan_id}")
        print(
            f"[+] Target resolved: "
            f"{target_info['input']} -> "
            f"{target_info['resolved_ip']}"
        )
        print(f"[+] Profile: {selected_profile}")
        print("[+] Authorized systems only")

    open_ports = scan_ports(
        target_info["resolved_ip"],
        ports,
        args.timeout,
        args.workers,
    )

    services = enumerate_services(
        target_info["input"],
        target_info["resolved_ip"],
        open_ports,
        args.timeout,
        args.workers,
    )

    findings = analyze_services(services)
    risk = calculate_risk(findings)

    completed_at = now_iso()
    duration = time.perf_counter() - started_perf

    report = build_report(
        scan_id=scan_id,
        target_info=target_info,
        scope=scope,
        profile=selected_profile,
        ports=ports,
        services=services,
        findings=findings,
        risk=risk,
        started_at=started_at,
        completed_at=completed_at,
        duration=duration,
    )

    json_path = save_json_report(
        report,
        args.json_output,
    )

    html_path = None
    if not args.no_html:
        html_path = save_html_report(report)

    if not args.quiet:
        display_summary(report)
        print(f"\n[+] JSON report: {json_path}")
        if html_path:
            print(f"[+] HTML report: {html_path}")
        print("[+] Scan completed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
