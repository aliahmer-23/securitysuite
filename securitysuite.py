#!/usr/bin/env python3

import argparse
import html
import json
import socket
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path


VERSION = "2.2.0"
SCHEMA_VERSION = "2.2"

BASE_DIR = Path(__file__).resolve().parent
NETSCOUT_DIR = BASE_DIR / "netscout"
CLOUDGUARD_DIR = BASE_DIR / "cloudguard"

NETSCOUT_SCRIPT = NETSCOUT_DIR / "netscout.py"
CLOUDGUARD_SCRIPT = CLOUDGUARD_DIR / "cloudguard.py"

DEFAULT_CLOUD_CONFIG = BASE_DIR / "cloud_environment.json"
REPORT_DIR = BASE_DIR / "reports"


# ============================================================
# Terminal UI
# ============================================================

def banner():
    print(f"""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                  SECURITYSUITE v{VERSION}                  ║
║          Network + Cloud Security Assessment               ║
║                                                            ║
║              STRUCTURED JSON INTEGRATION                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")


def separator():
    print("─" * 72)


# ============================================================
# Utility
# ============================================================

def check_projects(mode):
    problems = []

    if mode in ("full", "network-only") and not NETSCOUT_SCRIPT.exists():
        problems.append(f"NetScout not found: {NETSCOUT_SCRIPT}")

    if mode in ("full", "cloud-only") and not CLOUDGUARD_SCRIPT.exists():
        problems.append(f"CloudGuard not found: {CLOUDGUARD_SCRIPT}")

    return problems


def run_process(command, cwd, timeout=900):
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout
        )

        return {
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "return_code": -1,
            "stdout": "",
            "stderr": f"Process timed out after {timeout} seconds."
        }

    except Exception as error:
        return {
            "return_code": -1,
            "stdout": "",
            "stderr": str(error)
        }


def resolve_target(target):
    target = str(target or "").strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    try:
        socket.inet_pton(socket.AF_INET, target)
        return {
            "input": target,
            "resolved": target,
            "addresses": [target],
            "is_ip": True
        }
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, target)
        return {
            "input": target,
            "resolved": target,
            "addresses": [target],
            "is_ip": True
        }
    except OSError:
        pass

    try:
        addresses = socket.getaddrinfo(
            target,
            None,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror as error:
        raise ValueError(
            f"Could not resolve target '{target}': {error}"
        ) from error

    resolved_addresses = []

    for entry in addresses:
        address = entry[4][0]
        if address not in resolved_addresses:
            resolved_addresses.append(address)

    if not resolved_addresses:
        raise ValueError(
            f"No DNS address found for {target}"
        )

    ipv4 = [
        address
        for address in resolved_addresses
        if ":" not in address
    ]

    selected = (
        ipv4[0]
        if ipv4
        else resolved_addresses[0]
    )

    return {
        "input": target,
        "resolved": selected,
        "addresses": resolved_addresses,
        "is_ip": False
    }


def empty_netscout():
    return {
        "tool": "NetScout",
        "version": None,
        "schema_version": None,
        "return_code": None,
        "status": "NOT_RUN",
        "error": None,
        "scan_id": None,
        "target": None,
        "profile": None,
        "services": [],
        "open_ports": [],
        "findings": [],
        "risk": {
            "score": 0,
            "rating": "PASS",
            "counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        },
        "statistics": {},
        "raw_output": ""
    }


def empty_cloudguard():
    return {
        "tool": "CloudGuard",
        "version": None,
        "schema_version": None,
        "return_code": None,
        "status": "NOT_RUN",
        "error": None,
        "scan_id": None,
        "mode": None,
        "source": None,
        "summary": {
            "risk_score": 0,
            "raw_score": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
            "overall": "PASS"
        },
        "findings": [],
        "remediation": None,
        "raw_output": ""
    }


def load_json_report(path, expected_tool):
    path = Path(path)

    if not path.exists():
        raise ValueError(
            f"{expected_tool} did not create the expected JSON report."
        )

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Could not load {expected_tool} JSON report: {error}"
        ) from error

    if data.get("tool") != expected_tool:
        raise ValueError(
            f"Unexpected report format from {expected_tool}."
        )

    return data


# ============================================================
# NetScout Integration
# ============================================================

def run_netscout(target, profile="standard"):
    print("\n[+] Starting NetScout")
    print(f"[+] Target: {target}")
    print(f"[+] Profile: {profile}")
    print("[+] Integration mode: STRUCTURED JSON")

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="securitysuite_netscout_"
        )
    )

    report_path = (
        temp_dir /
        "netscout_result.json"
    )

    command = [
        sys.executable,
        str(NETSCOUT_SCRIPT),
        target,
        "--profile",
        profile,
        "--json-output",
        str(report_path),
        "--no-html"
    ]

    process = run_process(
        command,
        NETSCOUT_DIR,
        timeout=900
    )

    process["report_path"] = report_path
    return process


def load_netscout_report(process_result):
    result = empty_netscout()
    result["return_code"] = (
        process_result.get("return_code")
    )
    result["raw_output"] = ""

    if process_result.get("return_code") != 0:
        result["status"] = "FAILED"
        result["error"] = (
            process_result.get("stderr")
            or process_result.get("stdout")
            or "NetScout exited with a non-zero return code."
        ).strip()
        return result

    data = load_json_report(
        process_result.get("report_path"),
        "NetScout"
    )

    services = data.get("services", [])

    open_ports = []

    for service in services:
        open_ports.append({
            "port": service.get("port"),
            "service": (
                service.get("detected_service")
                or service.get("service_guess")
                or "unknown"
            ),
            "application": service.get("application"),
            "state": service.get("state", "open")
        })

    result.update({
        "status": "SUCCESS",
        "error": None,
        "tool": data.get("tool", "NetScout"),
        "version": data.get("version"),
        "schema_version": data.get("schema_version"),
        "scan_id": data.get("scan_id"),
        "target": data.get("target"),
        "profile": data.get("profile"),
        "services": services,
        "open_ports": open_ports,
        "findings": data.get("findings", []),
        "risk": data.get("risk", result["risk"]),
        "statistics": data.get("statistics", {}),
        "assets": data.get("assets", []),
        "timing": data.get("timing", {}),
        "scope": data.get("scope", {})
    })

    return result


# ============================================================
# CloudGuard Integration
# ============================================================

def run_cloudguard(
    config_path=None,
    demo=False,
    remediate=False
):
    print("\n[+] Starting CloudGuard")
    print("[+] Integration mode: STRUCTURED JSON")
    print("[+] Local cloud assessment")

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="securitysuite_cloudguard_"
        )
    )

    report_path = (
        temp_dir /
        "cloudguard_result.json"
    )

    command = [
        sys.executable,
        str(CLOUDGUARD_SCRIPT)
    ]

    if demo:
        command.append("--demo")
    else:
        command.extend([
            "--config",
            str(config_path)
        ])

    if remediate:
        command.append("--remediate")

    command.extend([
        "--json-output",
        str(report_path),
        "--no-html"
    ])

    process = run_process(
        command,
        CLOUDGUARD_DIR,
        timeout=900
    )

    process["report_path"] = report_path
    return process


def load_cloudguard_report(process_result):
    result = empty_cloudguard()
    result["return_code"] = (
        process_result.get("return_code")
    )
    result["raw_output"] = ""

    if process_result.get("return_code") != 0:
        result["status"] = "FAILED"
        result["error"] = (
            process_result.get("stderr")
            or process_result.get("stdout")
            or "CloudGuard exited with a non-zero return code."
        ).strip()
        return result

    data = load_json_report(
        process_result.get("report_path"),
        "CloudGuard"
    )

    result.update({
        "status": "SUCCESS",
        "error": None,
        "tool": data.get("tool", "CloudGuard"),
        "version": data.get("version"),
        "schema_version": data.get("schema_version"),
        "scan_id": data.get("scan_id"),
        "mode": data.get("mode"),
        "source": data.get("source"),
        "summary": data.get(
            "summary",
            result["summary"]
        ),
        "findings": data.get("findings", []),
        "remediation": data.get("remediation"),
        "before_summary": data.get("before_summary"),
        "timing": data.get("timing", {}),
        "cloud_access": data.get("cloud_access", {})
    })

    return result


# ============================================================
# Unified Risk Engine
# ============================================================

def active_cloud_findings(cloudguard):
    remediation = cloudguard.get(
        "remediation"
    )

    if (
        remediation
        and remediation.get("after_findings") == 0
    ):
        return []

    return cloudguard.get(
        "findings",
        []
    )


def calculate_combined_risk(
    netscout,
    cloudguard
):
    network_findings = netscout.get(
        "findings",
        []
    )

    cloud_findings = active_cloud_findings(
        cloudguard
    )

    all_findings = (
        network_findings
        + cloud_findings
    )

    weights = {
        "CRITICAL": 25,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 0
    }

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    raw_score = 0

    for finding in all_findings:
        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        raw_score += weights.get(
            severity,
            0
        )

        key = severity.lower()

        if key in counts:
            counts[key] += 1

    score = min(
        raw_score,
        100
    )

    if score >= 70:
        overall = "CRITICAL"
    elif score >= 40:
        overall = "HIGH"
    elif score >= 20:
        overall = "MEDIUM"
    elif score > 0:
        overall = "LOW"
    else:
        overall = "PASS"

    return {
        "risk_score": score,
        "raw_score": raw_score,
        "overall_risk": overall,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "total": len(all_findings),
        "network_findings": len(
            network_findings
        ),
        "cloud_findings": len(
            cloud_findings
        )
    }


# ============================================================
# Display
# ============================================================

def display_netscout(result):
    print("\nNETSCOUT RESULTS")
    separator()

    print(
        f"Status:              "
        f"{result.get('status', 'UNKNOWN')}"
    )

    print(
        f"Version:             "
        f"{result.get('version') or 'Unknown'}"
    )

    print(
        f"Profile:             "
        f"{result.get('profile') or 'Unknown'}"
    )

    print(
        f"Open ports detected: "
        f"{len(result.get('open_ports', []))}"
    )

    for port in result.get(
        "open_ports",
        []
    ):
        app = port.get("application")

        suffix = (
            f" | {app}"
            if app
            else ""
        )

        print(
            f"  Port {port.get('port')} → "
            f"{port.get('service')}"
            f"{suffix}"
        )

    print(
        f"Security findings:   "
        f"{len(result.get('findings', []))}"
    )

    risk = result.get(
        "risk",
        {}
    )

    print(
        f"NetScout risk:       "
        f"{risk.get('score', 0)}/100 "
        f"{risk.get('rating', 'PASS')}"
    )


def display_cloudguard(result):
    print("\nCLOUDGUARD RESULTS")
    separator()

    summary = result.get(
        "summary",
        {}
    )

    print(
        f"Status:              "
        f"{result.get('status', 'UNKNOWN')}"
    )

    print(
        f"Version:             "
        f"{result.get('version') or 'Unknown'}"
    )

    print(
        f"CloudGuard risk:     "
        f"{summary.get('risk_score', 0)}/100 "
        f"{summary.get('overall', 'PASS')}"
    )

    print(
        f"Security findings:   "
        f"{len(active_cloud_findings(result))}"
    )

    remediation = result.get(
        "remediation"
    )

    if remediation:
        print(
            f"Simulated fixes:     "
            f"{remediation.get('total_fixed', 0)}"
        )

        print(
            f"Before risk:         "
            f"{remediation.get('before_risk_score', 'N/A')}/100"
        )

        print(
            f"After risk:          "
            f"{remediation.get('after_risk_score', 'N/A')}/100"
        )

        print(
            f"Risk reduction:      "
            f"{remediation.get('risk_reduction', 'N/A')} points"
        )


def display_combined_summary(summary):
    print("\nCOMBINED SECURITY SUMMARY")
    separator()

    print(
        f"Risk score:       "
        f"{summary['risk_score']}/100"
    )

    print(
        f"Overall risk:     "
        f"{summary['overall_risk']}"
    )

    print(
        f"Critical:         "
        f"{summary['critical']}"
    )

    print(
        f"High findings:    "
        f"{summary['high']}"
    )

    print(
        f"Medium findings:  "
        f"{summary['medium']}"
    )

    print(
        f"Low findings:     "
        f"{summary['low']}"
    )

    print(
        f"Info findings:    "
        f"{summary['info']}"
    )

    print(
        f"Network findings: "
        f"{summary['network_findings']}"
    )

    print(
        f"Cloud findings:   "
        f"{summary['cloud_findings']}"
    )

    print(
        f"Total findings:   "
        f"{summary['total']}"
    )


# ============================================================
# JSON Report
# ============================================================

def save_json_report(
    scan_id,
    target,
    mode,
    network_profile,
    cloud_config,
    netscout,
    cloudguard,
    summary,
    started,
    completed
):
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        REPORT_DIR /
        f"securitysuite_{timestamp}_"
        f"{scan_id[:8]}.json"
    )

    duration = (
        datetime.fromisoformat(completed)
        - datetime.fromisoformat(started)
    ).total_seconds()

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": "SecuritySuite",
        "version": VERSION,
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "network_profile": network_profile,
        "started": started,
        "completed": completed,
        "duration_seconds": round(
            duration,
            2
        ),
        "cloud_config": (
            Path(cloud_config).name
            if cloud_config
            else None
        ),
        "component_status": {
            "netscout": netscout.get("status", "NOT_RUN"),
            "cloudguard": cloudguard.get("status", "NOT_RUN")
        },
        "components": {
            "netscout": netscout,
            "cloudguard": cloudguard
        },
        "combined_summary": summary
    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    return filename


# ============================================================
# HTML Report
# ============================================================

def severity_class(severity):
    return str(
        severity
    ).lower()


def format_evidence(finding):
    evidence = finding.get(
        "evidence",
        []
    )

    if not evidence:
        return "-"

    if isinstance(
        evidence,
        str
    ):
        evidence = [evidence]

    return "<br>".join(
        html.escape(
            str(item)
        )
        for item in evidence
    )


def html_findings(findings):
    if not findings:
        return """
        <tr>
            <td colspan="9">
                No findings detected.
            </td>
        </tr>
        """

    rows = []

    for finding in findings:
        rows.append(
            f"""
            <tr>
                <td>{html.escape(str(finding.get('source', 'Unknown')))}</td>
                <td>{html.escape(str(finding.get('id', '-')))}</td>
                <td>
                    <span class="severity {severity_class(finding.get('severity', 'INFO'))}">
                        {html.escape(str(finding.get('severity', 'INFO')))}
                    </span>
                </td>
                <td>{html.escape(str(finding.get('category', '-')))}</td>
                <td>{html.escape(str(finding.get('service', '-')))}</td>
                <td>{html.escape(str(finding.get('title', '-')))}</td>
                <td>{html.escape(str(finding.get('observation', '-')))}</td>
                <td>{format_evidence(finding)}</td>
                <td>{html.escape(str(finding.get('recommendation', '-')))}</td>
            </tr>
            """
        )

    return "\n".join(rows)


def html_services(netscout):
    services = netscout.get(
        "services",
        []
    )

    if not services:
        return """
        <tr>
            <td colspan="5">
                No open network services detected.
            </td>
        </tr>
        """

    rows = []

    for service in services:
        http_info = (
            service.get("http")
            or {}
        )

        rows.append(
            f"""
            <tr>
                <td>{html.escape(str(service.get('port', '-')))}</td>
                <td>{html.escape(str(service.get('state', 'open')))}</td>
                <td>{html.escape(str(
                    service.get('detected_service')
                    or service.get('service_guess')
                    or 'unknown'
                ))}</td>
                <td>{html.escape(str(service.get('application') or '-'))}</td>
                <td>{html.escape(str(http_info.get('status_line') or '-'))}</td>
            </tr>
            """
        )

    return "\n".join(rows)


def save_html_report(
    scan_id,
    target,
    mode,
    network_profile,
    cloud_config,
    netscout,
    cloudguard,
    summary,
    started,
    completed
):
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        REPORT_DIR /
        f"securitysuite_{timestamp}_"
        f"{scan_id[:8]}.html"
    )

    duration = (
        datetime.fromisoformat(completed)
        - datetime.fromisoformat(started)
    ).total_seconds()

    cloud_findings = active_cloud_findings(
        cloudguard
    )

    all_findings = (
        netscout.get("findings", [])
        + cloud_findings
    )

    rows = html_findings(
        all_findings
    )

    services_rows = html_services(
        netscout
    )

    cloud_summary = cloudguard.get(
        "summary",
        {}
    )

    remediation = cloudguard.get(
        "remediation"
    )

    remediation_html = ""

    if remediation:
        fixed_items = "".join(
            f"<li>{html.escape(str(item))}</li>"
            for item in remediation.get(
                "fixed_findings",
                []
            )
        ) or "<li>No remediation actions required.</li>"

        remediation_html = f"""
        <div class="section">
        <h2>CloudGuard Remediation Simulation</h2>

        <ul>
            {fixed_items}
        </ul>

        <p>
            <strong>Before risk:</strong>
            {remediation.get('before_risk_score', 'N/A')}/100
            &nbsp;&nbsp;

            <strong>After risk:</strong>
            {remediation.get('after_risk_score', 'N/A')}/100
            &nbsp;&nbsp;

            <strong>Risk reduction:</strong>
            {remediation.get('risk_reduction', 'N/A')} points
        </p>
        </div>
        """

    html_report = f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>SecuritySuite Security Assessment</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    margin: 0;
    background: #eef2f7;
    color: #1f2937;
}}

.container {{
    max-width: 1500px;
    margin: 35px auto;
    padding: 0 20px;
}}

.hero,
.section {{
    background: white;
    padding: 28px;
    border-radius: 14px;
    margin-bottom: 22px;
    box-shadow: 0 2px 10px rgba(0,0,0,.06);
}}

.hero {{
    background: #111827;
    color: white;
}}

.subtitle {{
    color: #cbd5e1;
}}

.meta {{
    line-height: 1.8;
    margin-top: 18px;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px;
    margin-top: 24px;
}}

.card {{
    background: #1f2937;
    border-radius: 10px;
    padding: 18px;
}}

.card strong {{
    display: block;
    font-size: 28px;
    margin-top: 6px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 18px;
}}

th,
td {{
    border-bottom: 1px solid #e5e7eb;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f8fafc;
}}

.severity {{
    font-weight: 800;
    padding: 4px 8px;
    border-radius: 999px;
    font-size: 12px;
}}

.critical,
.high {{
    color: #991b1b;
    background: #fee2e2;
}}

.medium {{
    color: #92400e;
    background: #fef3c7;
}}

.low {{
    color: #1e40af;
    background: #dbeafe;
}}

.info {{
    color: #374151;
    background: #e5e7eb;
}}

.small {{
    color: #64748b;
}}

</style>

</head>

<body>

<div class="container">

<div class="hero">

<h1>SecuritySuite Security Assessment</h1>

<div class="subtitle">
Network + Cloud Security Assessment Platform
v{VERSION}
</div>

<div class="meta">

<strong>Scan ID:</strong>
{html.escape(scan_id)}

<br>

<strong>Target:</strong>
{html.escape(str(target or 'N/A'))}

<br>

<strong>Mode:</strong>
{html.escape(str(mode))}

<br>

<strong>Network Profile:</strong>
{html.escape(str(network_profile or 'N/A'))}

<br>

<strong>Cloud Config:</strong>
{html.escape(Path(cloud_config).name if cloud_config else 'N/A')}

<br>

<strong>Started:</strong>
{html.escape(started)}

<br>

<strong>Completed:</strong>
{html.escape(completed)}

<br>

<strong>Duration:</strong>
{duration:.2f} seconds

</div>

<div class="cards">

<div class="card">
Combined Score
<strong>
{summary['risk_score']}/100
</strong>
</div>

<div class="card">
Overall Risk
<strong>
{html.escape(summary['overall_risk'])}
</strong>
</div>

<div class="card">
Critical
<strong>
{summary['critical']}
</strong>
</div>

<div class="card">
High
<strong>
{summary['high']}
</strong>
</div>

<div class="card">
Medium
<strong>
{summary['medium']}
</strong>
</div>

<div class="card">
Low
<strong>
{summary['low']}
</strong>
</div>

<div class="card">
Network
<strong>
{summary['network_findings']}
</strong>
</div>

<div class="card">
Cloud
<strong>
{summary['cloud_findings']}
</strong>
</div>

<div class="card">
Total
<strong>
{summary['total']}
</strong>
</div>

</div>

</div>


<div class="section">

<h2>Component Risk Scores</h2>

<table>

<tr>
<th>Component</th>
<th>Status</th>
<th>Version</th>
<th>Risk Score</th>
<th>Overall</th>
<th>Findings</th>
</tr>

<tr>
<td>NetScout</td>
<td>{html.escape(str(netscout.get('status', 'NOT_RUN')))}</td>
<td>{html.escape(str(netscout.get('version') or 'N/A'))}</td>
<td>{netscout.get('risk', {}).get('score', 0)}/100</td>
<td>{html.escape(str(netscout.get('risk', {}).get('rating', 'PASS')))}</td>
<td>{len(netscout.get('findings', []))}</td>
</tr>

<tr>
<td>CloudGuard</td>
<td>{html.escape(str(cloudguard.get('status', 'NOT_RUN')))}</td>
<td>{html.escape(str(cloudguard.get('version') or 'N/A'))}</td>
<td>{cloud_summary.get('risk_score', 0)}/100</td>
<td>{html.escape(str(cloud_summary.get('overall', 'PASS')))}</td>
<td>{len(cloud_findings)}</td>
</tr>

</table>

</div>


<div class="section">

<h2>Network Service Inventory</h2>

<table>

<thead>
<tr>
<th>Port</th>
<th>State</th>
<th>Service</th>
<th>Application</th>
<th>HTTP Status</th>
</tr>
</thead>

<tbody>
{services_rows}
</tbody>

</table>

</div>


<div class="section">

<h2>Unified Security Findings</h2>

<table>

<thead>

<tr>
<th>Source</th>
<th>ID</th>
<th>Severity</th>
<th>Category</th>
<th>Service</th>
<th>Finding</th>
<th>Observation</th>
<th>Evidence</th>
<th>Recommendation</th>
</tr>

</thead>

<tbody>
{rows}
</tbody>

</table>

</div>

{remediation_html}


<div class="section">

<h2>Risk Methodology</h2>

<p>
CRITICAL findings contribute 25 points.
</p>

<p>
HIGH findings contribute 10 points.
</p>

<p>
MEDIUM findings contribute 5 points.
</p>

<p>
LOW findings contribute 2 points.
</p>

<p>
INFO findings contribute 0 points.
</p>

<p>
The combined score is capped at 100.
</p>

<p class="small">
Component scores remain visible separately from the combined SecuritySuite score.
Each component may retain its own engine-specific scoring thresholds; the unified
SecuritySuite score uses the methodology shown above.
</p>

</div>

</div>

</body>

</html>
"""

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(
            html_report
        )

    return filename


# ============================================================
# Main Assessment
# ============================================================

def run_full_assessment(
    mode,
    target=None,
    network_profile="standard",
    cloud_config=None,
    cloud_demo=False,
    remediate=False
):
    scan_id = str(
        uuid.uuid4()
    )

    started = datetime.now().isoformat()

    print(
        f"\n[+] Scan ID: {scan_id}"
    )

    print(
        f"[+] Mode: {mode}"
    )

    if target:
        print(
            f"[+] Target: {target}"
        )

    if mode in (
        "full",
        "network-only"
    ):
        print(
            f"[+] Network profile: "
            f"{network_profile}"
        )

    if cloud_config:
        print(
            f"[+] Cloud config: "
            f"{cloud_config}"
        )

    separator()

    netscout = empty_netscout()
    cloudguard = empty_cloudguard()

    # --------------------------------------------------------
    # NetScout
    # --------------------------------------------------------

    if mode in (
        "full",
        "network-only"
    ):
        netscout_process = run_netscout(
            target,
            profile=network_profile
        )

        if netscout_process["stdout"]:
            print(
                netscout_process["stdout"]
            )

        if (
            netscout_process["return_code"]
            != 0
        ):
            print(
                "[!] NetScout returned an error."
            )

            if netscout_process["stderr"]:
                print(
                    netscout_process["stderr"]
                )
        else:
            try:
                netscout = load_netscout_report(
                    netscout_process
                )

            except ValueError as error:
                print(
                    f"[!] NetScout integration error: "
                    f"{error}"
                )

                netscout["return_code"] = 1
                netscout["status"] = "FAILED"
                netscout["error"] = str(error)

    # --------------------------------------------------------
    # CloudGuard
    # --------------------------------------------------------

    if mode in (
        "full",
        "cloud-only"
    ):
        cloudguard_process = run_cloudguard(
            config_path=cloud_config,
            demo=cloud_demo,
            remediate=remediate
        )

        if cloudguard_process["stdout"]:
            print(
                cloudguard_process["stdout"]
            )

        if (
            cloudguard_process["return_code"]
            != 0
        ):
            print(
                "[!] CloudGuard returned an error."
            )

            if cloudguard_process["stderr"]:
                print(
                    cloudguard_process["stderr"]
                )
        else:
            try:
                cloudguard = load_cloudguard_report(
                    cloudguard_process
                )

            except ValueError as error:
                print(
                    f"[!] CloudGuard integration error: "
                    f"{error}"
                )

                cloudguard["return_code"] = 1
                cloudguard["status"] = "FAILED"
                cloudguard["error"] = str(error)

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    if mode in (
        "full",
        "network-only"
    ):
        display_netscout(
            netscout
        )

    if mode in (
        "full",
        "cloud-only"
    ):
        display_cloudguard(
            cloudguard
        )

    summary = calculate_combined_risk(
        netscout,
        cloudguard
    )

    display_combined_summary(
        summary
    )

    completed = datetime.now().isoformat()

    json_report = save_json_report(
        scan_id,
        target,
        mode,
        network_profile,
        cloud_config,
        netscout,
        cloudguard,
        summary,
        started,
        completed
    )

    html_report = save_html_report(
        scan_id,
        target,
        mode,
        network_profile,
        cloud_config,
        netscout,
        cloudguard,
        summary,
        started,
        completed
    )

    print("\n")
    separator()

    print(
        "[+] JSON report saved:"
    )

    print(
        f"    {json_report}"
    )

    print(
        "[+] HTML report saved:"
    )

    print(
        f"    {html_report}"
    )

    print(
        "\n[+] SecuritySuite assessment completed."
    )

    return 0


# ============================================================
# CLI
# ============================================================

def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "SecuritySuite - Network + Cloud "
            "Security Assessment Platform"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "full",
            "network-only",
            "cloud-only"
        ],
        default="full",
        help=(
            "Assessment mode: full, network-only, "
            "or cloud-only"
        )
    )

    parser.add_argument(
        "--target",
        help=(
            "Authorized IP address or hostname "
            "for NetScout"
        )
    )

    parser.add_argument(
        "--network-profile",
        choices=[
            "quick",
            "standard",
            "web",
            "full"
        ],
        default="standard",
        help=(
            "NetScout v6 scan profile "
            "(default: standard)"
        )
    )

    parser.add_argument(
        "--cloud-config",
        default=str(
            DEFAULT_CLOUD_CONFIG
        ),
        help=(
            "Local CloudGuard JSON configuration "
            "(default: cloud_environment.json)"
        )
    )

    parser.add_argument(
        "--cloud-demo",
        action="store_true",
        help=(
            "Use CloudGuard's built-in simulated "
            "environment instead of --cloud-config"
        )
    )

    parser.add_argument(
        "--remediate",
        action="store_true",
        help=(
            "Run CloudGuard simulated remediation "
            "and reassessment"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SecuritySuite {VERSION}"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    banner()

    if (
        args.mode == "network-only"
        and args.remediate
    ):
        print(
            "[!] --remediate is only available "
            "when CloudGuard is running."
        )
        return 1

    if (
        args.cloud_demo
        and args.mode == "network-only"
    ):
        print(
            "[!] --cloud-demo cannot be used "
            "with --mode network-only."
        )
        return 1

    target = args.target

    if (
        args.mode in (
            "full",
            "network-only"
        )
        and not target
    ):
        try:
            target = input(
                "Authorized target IP or hostname: "
            ).strip()

        except (
            KeyboardInterrupt,
            EOFError
        ):
            print(
                "\n[!] Assessment cancelled."
            )
            return 130

        if not target:
            print(
                "[!] Target cannot be empty."
            )
            return 1

        print()

        print(
            "[!] Only scan systems you own "
            "or have explicit authorization to test."
        )

        try:
            confirmation = input(
                "Continue? [y/N]: "
            ).strip().lower()

        except (
            KeyboardInterrupt,
            EOFError
        ):
            print(
                "\n[!] Assessment cancelled."
            )
            return 130

        if confirmation != "y":
            print(
                "[!] Assessment cancelled."
            )
            return 0

    if args.mode in (
        "full",
        "network-only"
    ):
        try:
            target_info = resolve_target(
                target
            )

            print(
                f"[+] Target resolution check: "
                f"{target_info['resolved']}"
            )

        except ValueError as error:
            print(
                f"[!] Target resolution failed: "
                f"{error}"
            )
            return 1

    cloud_config = None

    if args.mode in (
        "full",
        "cloud-only"
    ):
        if args.cloud_demo:
            print(
                "[+] CloudGuard source: BUILT-IN DEMO"
            )
        else:
            cloud_config = Path(
                args.cloud_config
            ).expanduser().resolve()

            if not cloud_config.exists():
                print(
                    "[ERROR] Cloud configuration file "
                    f"not found: {cloud_config}"
                )

                print("\nUse:")

                print(
                    "  --cloud-config "
                    "~/Desktop/securitysuite/"
                    "cloud_environment.json"
                )

                print(
                    "\nOr use the built-in demo:"
                )

                print(
                    "  --cloud-demo"
                )

                return 1

            print(
                f"[+] CloudGuard config found: "
                f"{cloud_config}"
            )

    problems = check_projects(
        args.mode
    )

    if problems:
        print(
            "\n[!] Required project files were not found:"
        )

        for problem in problems:
            print(
                f"    - {problem}"
            )

        return 1

    if args.mode in (
        "full",
        "network-only"
    ):
        print(
            "[+] NetScout structured JSON integration detected"
        )

    if args.mode in (
        "full",
        "cloud-only"
    ):
        print(
            "[+] CloudGuard structured JSON integration detected"
        )

    print(
        "[+] Local integration ready"
    )

    print(
        f"[+] Assessment mode: "
        f"{args.mode.upper()}"
    )

    if args.mode in (
        "full",
        "network-only"
    ):
        print(
            f"[+] Network profile: "
            f"{args.network_profile.upper()}"
        )

    if args.remediate:
        print(
            "[+] CloudGuard remediation: ENABLED"
        )

    print()

    return run_full_assessment(
        mode=args.mode,
        target=target,
        network_profile=args.network_profile,
        cloud_config=cloud_config,
        cloud_demo=args.cloud_demo,
        remediate=args.remediate
    )


if __name__ == "__main__":
    sys.exit(main())
