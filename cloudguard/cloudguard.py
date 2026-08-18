#!/usr/bin/env python3

import argparse
import copy
import html
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "6.0.0"
SCHEMA_VERSION = "1.0"
REPORT_DIR = Path("reports")


def banner():
    print(f"""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                  CLOUDGUARD v{VERSION}                      ║
║          Cloud Security Assessment Engine                  ║
║                                                            ║
║              LOCAL CLOUD SIMULATION                       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")


def ensure_parent(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def generate_demo_environment():
    return {
        "account": {
            "root_access_key": True,
            "mfa_enabled": False
        },
        "iam": {
            "unused_credentials": 3,
            "administrative_users": 2,
            "password_min_length": 10,
            "password_requires_symbols": False
        },
        "s3": {
            "bucket_name": "company-data",
            "public_access_blocked": False,
            "encryption_enabled": False,
            "versioning_enabled": False
        },
        "security_groups": [
            {
                "id": "sg-001",
                "name": "web-server",
                "rules": [
                    {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"},
                    {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}
                ]
            }
        ],
        "logging": {
            "cloudtrail_enabled": False
        }
    }


def load_config(config_path):
    path = Path(config_path).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Configuration path is not a file: {path}")

    try:
        with open(path, "r", encoding="utf-8") as file:
            environment = json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON configuration: {error}") from error

    validate_environment(environment)
    return environment


def validate_environment(environment):
    if not isinstance(environment, dict):
        raise ValueError("Cloud environment must be a JSON object.")

    for section in ("account", "iam", "s3", "security_groups", "logging"):
        if section not in environment:
            raise ValueError(f"Missing required section: {section}")

    for field in ("root_access_key", "mfa_enabled"):
        if field not in environment["account"]:
            raise ValueError(f"Missing account field: {field}")

    for field in (
        "unused_credentials",
        "administrative_users",
        "password_min_length",
        "password_requires_symbols",
    ):
        if field not in environment["iam"]:
            raise ValueError(f"Missing IAM field: {field}")

    for field in (
        "bucket_name",
        "public_access_blocked",
        "encryption_enabled",
        "versioning_enabled",
    ):
        if field not in environment["s3"]:
            raise ValueError(f"Missing S3 field: {field}")

    if not isinstance(environment["security_groups"], list):
        raise ValueError("'security_groups' must be a list.")

    for group in environment["security_groups"]:
        for field in ("id", "name", "rules"):
            if field not in group:
                raise ValueError(f"Missing security group field: {field}")

        if not isinstance(group["rules"], list):
            raise ValueError(f"Rules for {group['id']} must be a list.")

        for rule in group["rules"]:
            for field in ("protocol", "port", "source"):
                if field not in rule:
                    raise ValueError(f"Missing rule field: {field}")

    if "cloudtrail_enabled" not in environment["logging"]:
        raise ValueError("Missing logging.cloudtrail_enabled")


def create_finding(
    finding_id,
    title,
    severity,
    category,
    service,
    observation,
    impact,
    recommendation,
    evidence=None,
):
    return {
        "id": finding_id,
        "source": "CloudGuard",
        "severity": severity.upper(),
        "category": category,
        "service": service,
        "title": title,
        "observation": observation,
        "impact": impact,
        "recommendation": recommendation,
        "evidence": evidence or [],
        "status": "OPEN",
    }


def analyze_account(environment):
    findings = []
    account = environment["account"]

    if account["root_access_key"]:
        findings.append(create_finding(
            "ACCOUNT-001",
            "Root access key detected",
            "HIGH",
            "Identity & Access Management",
            "Account",
            "A root account access key exists in the simulated environment.",
            "A compromised root access key could provide unrestricted access to the cloud environment.",
            "Remove root access keys and use controlled IAM roles or users with least privilege.",
            ["account.root_access_key = true"],
        ))

    if not account["mfa_enabled"]:
        findings.append(create_finding(
            "ACCOUNT-002",
            "MFA protection not enabled",
            "HIGH",
            "Authentication",
            "Account",
            "Multi-factor authentication is disabled in the simulated environment.",
            "Compromised credentials could allow unauthorized account access.",
            "Enable MFA for privileged and sensitive accounts.",
            ["account.mfa_enabled = false"],
        ))

    return findings


def analyze_iam(environment):
    findings = []
    iam = environment["iam"]

    if iam["unused_credentials"] > 0:
        findings.append(create_finding(
            "IAM-001",
            "Unused IAM credentials detected",
            "MEDIUM",
            "Identity & Access Management",
            "IAM",
            f"The environment contains {iam['unused_credentials']} unused credentials.",
            "Unused credentials increase the attack surface and may provide forgotten access paths.",
            "Review inactive credentials and remove or rotate credentials that are no longer required.",
            [f"iam.unused_credentials = {iam['unused_credentials']}"],
        ))

    if iam["administrative_users"] > 1:
        findings.append(create_finding(
            "IAM-002",
            "Multiple administrative users detected",
            "MEDIUM",
            "Least Privilege",
            "IAM",
            f"The environment contains {iam['administrative_users']} administrative users.",
            "Excessive administrative privileges increase the potential impact of compromised accounts.",
            "Apply least privilege and reduce the number of permanent administrative users.",
            [f"iam.administrative_users = {iam['administrative_users']}"],
        ))

    if iam["password_min_length"] < 12:
        findings.append(create_finding(
            "IAM-003",
            "Weak IAM password policy",
            "MEDIUM",
            "Authentication",
            "IAM",
            f"The minimum password length is {iam['password_min_length']} characters.",
            "Short passwords are more susceptible to password guessing and brute-force attacks.",
            "Require passwords of at least 12 characters.",
            [f"iam.password_min_length = {iam['password_min_length']}"],
        ))

    if not iam["password_requires_symbols"]:
        findings.append(create_finding(
            "IAM-004",
            "IAM password policy lacks symbol requirement",
            "LOW",
            "Authentication",
            "IAM",
            "The password policy does not require special characters.",
            "Weak password complexity can make credential attacks easier.",
            "Require appropriate password complexity and special characters.",
            ["iam.password_requires_symbols = false"],
        ))

    return findings


def analyze_s3(environment):
    findings = []
    s3 = environment["s3"]
    bucket_name = s3["bucket_name"]

    if not s3["public_access_blocked"]:
        findings.append(create_finding(
            "S3-001",
            "S3 public access protection disabled",
            "HIGH",
            "Data Protection",
            "S3",
            f"Bucket '{bucket_name}' does not have public access protection enabled.",
            "Publicly accessible storage could expose sensitive organizational data.",
            "Enable S3 Block Public Access unless public access is explicitly required.",
            [f"s3.bucket_name = {bucket_name}", "s3.public_access_blocked = false"],
        ))

    if not s3["encryption_enabled"]:
        findings.append(create_finding(
            "S3-002",
            "S3 encryption not configured",
            "MEDIUM",
            "Data Protection",
            "S3",
            f"Bucket '{bucket_name}' does not have encryption enabled.",
            "Stored data may not receive the expected protection against unauthorized access.",
            "Enable server-side encryption for stored data.",
            [f"s3.bucket_name = {bucket_name}", "s3.encryption_enabled = false"],
        ))

    if not s3["versioning_enabled"]:
        findings.append(create_finding(
            "S3-003",
            "S3 versioning not enabled",
            "LOW",
            "Data Protection",
            "S3",
            f"Bucket '{bucket_name}' does not have versioning enabled.",
            "Accidental deletion or modification may be more difficult to recover from.",
            "Enable versioning for important data and recovery requirements.",
            [f"s3.bucket_name = {bucket_name}", "s3.versioning_enabled = false"],
        ))

    return findings


def analyze_security_groups(environment):
    findings = []

    for group in environment["security_groups"]:
        group_id = group["id"]
        group_name = group["name"]

        for rule in group["rules"]:
            port = rule["port"]
            source = rule["source"]
            protocol = rule["protocol"]

            if source != "0.0.0.0/0":
                continue

            evidence = [
                f"group_id = {group_id}",
                f"group_name = {group_name}",
                f"protocol = {protocol}",
                f"port = {port}",
                f"source = {source}",
            ]

            if port == 22:
                findings.append(create_finding(
                    f"SG-001-{group_id}",
                    "SSH exposed to the internet",
                    "HIGH",
                    "Network Security",
                    "Security Groups",
                    f"{group_id} ({group_name}) allows TCP/22 from 0.0.0.0/0.",
                    "Internet-exposed SSH increases the attack surface for password attacks and credential-based compromise.",
                    "Restrict SSH access to trusted IP addresses or private networks.",
                    evidence,
                ))

            elif port == 3389:
                findings.append(create_finding(
                    f"SG-002-{group_id}",
                    "RDP exposed to the internet",
                    "HIGH",
                    "Network Security",
                    "Security Groups",
                    f"{group_id} ({group_name}) allows TCP/3389 from 0.0.0.0/0.",
                    "Internet-exposed RDP increases the attack surface for credential attacks and unauthorized remote access.",
                    "Restrict RDP access to trusted networks or VPN infrastructure.",
                    evidence,
                ))

            elif port == 80:
                findings.append(create_finding(
                    f"SG-003-{group_id}",
                    "HTTP exposed to the internet",
                    "LOW",
                    "Network Security",
                    "Security Groups",
                    f"{group_id} ({group_name}) allows TCP/80 from 0.0.0.0/0.",
                    "HTTP traffic is unencrypted and may expose sensitive information if used for sensitive applications.",
                    "Use HTTPS for sensitive traffic and restrict unnecessary HTTP exposure.",
                    evidence,
                ))

    return findings


def analyze_logging(environment):
    findings = []

    if not environment["logging"]["cloudtrail_enabled"]:
        findings.append(create_finding(
            "LOG-001",
            "CloudTrail logging disabled",
            "HIGH",
            "Logging & Monitoring",
            "CloudTrail",
            "CloudTrail logging is disabled in the simulated environment.",
            "Without audit logging, security events and unauthorized activity may be difficult to investigate.",
            "Enable CloudTrail and centralize logs for security monitoring and incident investigation.",
            ["logging.cloudtrail_enabled = false"],
        ))

    return findings


def run_assessment(environment):
    findings = []
    findings.extend(analyze_account(environment))
    findings.extend(analyze_iam(environment))
    findings.extend(analyze_s3(environment))
    findings.extend(analyze_security_groups(environment))
    findings.extend(analyze_logging(environment))
    return findings


def calculate_risk(findings):
    weights = {
        "CRITICAL": 25,
        "HIGH": 10,
        "MEDIUM": 5,
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

    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        raw_score += weights.get(severity, 0)

        key = severity.lower()
        if key in counts:
            counts[key] += 1

    score = min(raw_score, 100)

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
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "total": len(findings),
        "overall": overall,
    }


def remediate_environment(environment):
    fixed = []
    env = copy.deepcopy(environment)

    if env["account"]["root_access_key"]:
        env["account"]["root_access_key"] = False
        fixed.append("ACCOUNT-001")

    if not env["account"]["mfa_enabled"]:
        env["account"]["mfa_enabled"] = True
        fixed.append("ACCOUNT-002")

    if env["iam"]["unused_credentials"] > 0:
        env["iam"]["unused_credentials"] = 0
        fixed.append("IAM-001")

    if env["iam"]["administrative_users"] > 1:
        env["iam"]["administrative_users"] = 1
        fixed.append("IAM-002")

    if env["iam"]["password_min_length"] < 12:
        env["iam"]["password_min_length"] = 12
        fixed.append("IAM-003")

    if not env["iam"]["password_requires_symbols"]:
        env["iam"]["password_requires_symbols"] = True
        fixed.append("IAM-004")

    s3 = env["s3"]

    if not s3["public_access_blocked"]:
        s3["public_access_blocked"] = True
        fixed.append("S3-001")

    if not s3["encryption_enabled"]:
        s3["encryption_enabled"] = True
        fixed.append("S3-002")

    if not s3["versioning_enabled"]:
        s3["versioning_enabled"] = True
        fixed.append("S3-003")

    for group in env["security_groups"]:
        group_id = group["id"]

        for rule in group["rules"]:
            if rule["source"] != "0.0.0.0/0":
                continue

            if rule["port"] == 22:
                rule["source"] = "10.0.0.0/16"
                fixed.append(f"SG-001-{group_id}")

            elif rule["port"] == 3389:
                rule["source"] = "10.0.0.0/16"
                fixed.append(f"SG-002-{group_id}")

            elif rule["port"] == 80:
                rule["source"] = "10.0.0.0/16"
                fixed.append(f"SG-003-{group_id}")

    if not env["logging"]["cloudtrail_enabled"]:
        env["logging"]["cloudtrail_enabled"] = True
        fixed.append("LOG-001")

    return env, fixed


def display_findings(findings):
    print("\nSECURITY ANALYSIS")
    print("─" * 75)

    if not findings:
        print("No security findings detected.")
        return

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['id']} | {finding['title']}")
        print(f"Category: {finding['category']}")
        print(f"Service: {finding['service']}")
        print(f"Observation: {finding['observation']}")
        print(f"Impact: {finding['impact']}")
        print(f"Recommendation: {finding['recommendation']}")

        if finding.get("evidence"):
            print("Evidence:")
            for evidence in finding["evidence"]:
                print(f"  - {evidence}")

        print(f"Status: {finding['status']}")


def display_summary(summary):
    print("\nSECURITY SUMMARY")
    print("─" * 44)
    print(f"Risk score:       {summary['risk_score']}/100")
    print(f"Critical:         {summary['critical']}")
    print(f"High findings:    {summary['high']}")
    print(f"Medium findings:  {summary['medium']}")
    print(f"Low findings:     {summary['low']}")
    print(f"Info findings:    {summary['info']}")
    print(f"Total findings:   {summary['total']}")
    print(f"Overall risk:     {summary['overall']}")


def display_remediation(fixed):
    print("\nREMEDIATION SIMULATION")
    print("─" * 75)

    if not fixed:
        print("No remediation actions required.")
        return

    for finding_id in fixed:
        print(f"[FIXED] {finding_id}")

    print(f"\nTotal simulated fixes: {len(fixed)}")


def build_report(
    scan_id,
    mode,
    source,
    started,
    completed,
    duration_seconds,
    findings,
    summary,
    before_summary=None,
    fixed=None,
):
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": "CloudGuard",
        "version": VERSION,
        "engine": "cloud",
        "scan_id": scan_id,
        "mode": mode,
        "source": source,
        "cloud_access": {
            "aws_account_required": False,
            "aws_credentials_required": False,
            "aws_api_access": False,
            "cloud_resources_accessed": False,
            "cloud_charges_generated": False,
        },
        "timing": {
            "started_at": started,
            "completed_at": completed,
            "duration_seconds": round(duration_seconds, 4),
        },
        "summary": summary,
        "findings": findings,
    }

    if before_summary is not None:
        report["before_summary"] = before_summary

    if fixed is not None:
        report["remediation"] = {
            "simulated": True,
            "fixed_findings": fixed,
            "total_fixed": len(fixed),
            "before_risk_score": before_summary["risk_score"] if before_summary else None,
            "after_risk_score": summary["risk_score"],
            "risk_reduction": (
                before_summary["risk_score"] - summary["risk_score"]
                if before_summary else None
            ),
            "before_findings": before_summary["total"] if before_summary else None,
            "after_findings": summary["total"],
        }

    return report


def save_json_report(report, output_path=None):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if output_path:
        filename = Path(output_path).expanduser().resolve()
        ensure_parent(filename)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = REPORT_DIR / f"cloudguard_{timestamp}_{report['scan_id'][:8]}.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return filename


def save_html_report(report):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"cloudguard_{timestamp}_{report['scan_id'][:8]}.html"

    rows = ""

    for finding in report["findings"]:
        severity_class = finding["severity"].lower()
        evidence_html = "<br>".join(
            html.escape(str(item))
            for item in finding.get("evidence", [])
        ) or "-"

        rows += f"""
<tr>
<td>{html.escape(finding['id'])}</td>
<td class="{severity_class}">{html.escape(finding['severity'])}</td>
<td>{html.escape(finding['category'])}</td>
<td>{html.escape(finding['service'])}</td>
<td>{html.escape(finding['title'])}</td>
<td>{html.escape(finding['observation'])}</td>
<td>{evidence_html}</td>
<td>{html.escape(finding['recommendation'])}</td>
<td>{html.escape(finding['status'])}</td>
</tr>
"""

    if not rows:
        rows = '<tr><td colspan="9">No security findings detected.</td></tr>'

    summary = report["summary"]
    remediation = report.get("remediation")
    remediation_html = ""

    if remediation:
        fixed_items = "".join(
            f"<li>{html.escape(str(item))}</li>"
            for item in remediation.get("fixed_findings", [])
        ) or "<li>No remediation actions required.</li>"

        remediation_html = f"""
<div class="section">
<h2>Remediation Simulation</h2>
<p>The remediation process was simulated locally. No cloud resources were modified.</p>
<ul>{fixed_items}</ul>
<table>
<tr><th>Metric</th><th>Before</th><th>After</th></tr>
<tr><td>Risk Score</td><td>{remediation.get('before_risk_score', 'N/A')}/100</td><td>{remediation.get('after_risk_score', 'N/A')}/100</td></tr>
<tr><td>Total Findings</td><td>{remediation.get('before_findings', 'N/A')}</td><td>{remediation.get('after_findings', 'N/A')}</td></tr>
</table>
<p><strong>Risk reduction:</strong> {remediation.get('risk_reduction', 'N/A')} points</p>
</div>
"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudGuard Security Assessment</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: #f1f5f9; color: #1e293b;
    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
}}
.container {{ max-width: 1350px; margin: auto; padding: 35px 20px; }}
.header {{
    background: #0f172a; color: white; padding: 30px;
    border-radius: 14px; margin-bottom: 24px;
}}
.cards {{
    display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr));
    gap: 15px; margin: 25px 0;
}}
.card {{
    background: white; padding: 20px; border-radius: 10px;
    box-shadow: 0 2px 8px rgba(15,23,42,.06);
}}
.card h3 {{ margin: 0 0 10px; font-size: 13px; color: #64748b; }}
.number {{ font-size: 28px; font-weight: bold; }}
.section {{
    background: white; padding: 25px; border-radius: 10px;
    margin-bottom: 25px; box-shadow: 0 2px 8px rgba(15,23,42,.06);
}}
table {{ width: 100%; border-collapse: collapse; }}
th,td {{
    padding: 12px; border-bottom: 1px solid #e2e8f0;
    text-align: left; vertical-align: top;
}}
th {{ background: #f8fafc; }}
.critical,.high {{ color: #991b1b; font-weight: bold; }}
.medium {{ color: #d97706; font-weight: bold; }}
.low {{ color: #2563eb; font-weight: bold; }}
.info {{ color: #475569; font-weight: bold; }}
.security-notice {{
    margin-bottom: 24px; padding: 15px; background: #eff6ff;
    border-left: 4px solid #2563eb; border-radius: 5px;
}}
.footer {{ text-align: center; color: #64748b; padding: 20px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
<h1>CloudGuard Security Assessment</h1>
<p>Cloud Security Assessment Engine v{VERSION}</p>
<p><strong>Scan ID:</strong> {html.escape(report['scan_id'])}</p>
<p><strong>Mode:</strong> {html.escape(report['mode'])}</p>
<p><strong>Source:</strong> {html.escape(str(report['source']))}</p>
</div>

<div class="security-notice">
<strong>Security Notice:</strong>
This report was generated from a local simulated cloud environment.
CloudGuard did not connect to AWS, use AWS credentials, access cloud resources,
or generate cloud charges.
</div>

<div class="cards">
<div class="card"><h3>RISK SCORE</h3><div class="number">{summary['risk_score']}/100</div></div>
<div class="card"><h3>OVERALL RISK</h3><div class="number">{html.escape(summary['overall'])}</div></div>
<div class="card"><h3>CRITICAL</h3><div class="number critical">{summary['critical']}</div></div>
<div class="card"><h3>HIGH</h3><div class="number high">{summary['high']}</div></div>
<div class="card"><h3>MEDIUM</h3><div class="number medium">{summary['medium']}</div></div>
<div class="card"><h3>LOW</h3><div class="number low">{summary['low']}</div></div>
<div class="card"><h3>INFO</h3><div class="number info">{summary['info']}</div></div>
<div class="card"><h3>TOTAL</h3><div class="number">{summary['total']}</div></div>
</div>

<div class="section">
<h2>Security Findings</h2>
<table>
<tr>
<th>ID</th><th>Severity</th><th>Category</th><th>Service</th>
<th>Finding</th><th>Observation</th><th>Evidence</th>
<th>Recommendation</th><th>Status</th>
</tr>
{rows}
</table>
</div>

{remediation_html}

<div class="section">
<h2>Risk Methodology</h2>
<p>CRITICAL findings contribute 25 points.</p>
<p>HIGH findings contribute 10 points.</p>
<p>MEDIUM findings contribute 5 points.</p>
<p>LOW findings contribute 2 points.</p>
<p>INFO findings contribute 0 points.</p>
<p>The final risk score is capped at 100.</p>
</div>

<div class="footer">
CloudGuard v{VERSION}<br>
LOCAL SIMULATION — NO CLOUD ACCESS
</div>

</div>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_doc)

    return filename


def determine_scan_mode(args):
    if args.demo:
        return "LOCAL_DEMO_REMEDIATION" if args.remediate else "LOCAL_DEMO"

    if args.config:
        return "LOCAL_CONFIG_REMEDIATION" if args.remediate else "LOCAL_CONFIG"

    return None


def build_parser():
    parser = argparse.ArgumentParser(
        description="CloudGuard v6.0.0 - Local Cloud Security Assessment Engine"
    )

    scan_group = parser.add_mutually_exclusive_group()

    scan_group.add_argument(
        "--demo",
        action="store_true",
        help="Run the built-in simulated cloud environment",
    )

    scan_group.add_argument(
        "--config",
        type=str,
        metavar="FILE",
        help="Run a local cloud scenario from a JSON file",
    )

    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Simulate remediation and reassess",
    )

    parser.add_argument(
        "--json-output",
        help="Write the structured CloudGuard JSON report to this exact path",
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
        version=f"CloudGuard {VERSION}",
    )

    return parser


def main():
    args = build_parser().parse_args()

    if not args.quiet:
        banner()

    mode = determine_scan_mode(args)

    if mode is None:
        print("[!] No scan mode selected.")
        print("\nAvailable scan modes:")
        print("  python3 cloudguard.py --demo")
        print("  python3 cloudguard.py --demo --remediate")
        print("  python3 cloudguard.py --config cloud_environment.json")
        print("  python3 cloudguard.py --config cloud_environment.json --remediate")
        return 1

    if not args.quiet:
        print("[+] LOCAL assessment mode")
        print("[+] No AWS account required")
        print("[+] No AWS credentials required")
        print("[+] No AWS API access")
        print("[+] No cloud resources accessed")
        print("[+] No cloud charges generated")
        print(f"[+] Scan mode: {mode}")

    try:
        if args.demo:
            if not args.quiet:
                print("\n[+] Loading built-in demo environment...")
            environment = generate_demo_environment()
            source = "BUILT_IN_DEMO"
        else:
            if not args.quiet:
                print("\n[+] Loading configuration:")
                print(f"    {args.config}")

            environment = load_config(args.config)
            source = str(Path(args.config).expanduser().resolve())

            if not args.quiet:
                print("[+] Configuration validated")

    except (FileNotFoundError, ValueError) as error:
        print(f"\n[ERROR] {error}")
        return 1

    if not args.quiet:
        print("\n[+] Account security analysis enabled")
        print("[+] IAM analysis enabled")
        print("[+] S3 analysis enabled")
        print("[+] Security group analysis enabled")
        print("[+] Logging analysis enabled")
        print("[+] MFA analysis enabled")
        print("[+] Least privilege analysis enabled")
        print("[+] Password policy analysis enabled")
        print("[+] Structured JSON reporting enabled")

    scan_id = str(uuid.uuid4())
    started_datetime = datetime.now(timezone.utc)
    started = started_datetime.isoformat()

    findings_before = run_assessment(environment)
    summary_before = calculate_risk(findings_before)

    if not args.quiet:
        display_findings(findings_before)
        display_summary(summary_before)

    if args.remediate:
        if not args.quiet:
            print("\n[+] Starting remediation simulation...")

        remediated_environment, fixed = remediate_environment(environment)

        if not args.quiet:
            display_remediation(fixed)
            print("\n[+] Reassessing remediated environment...")

        findings_after = run_assessment(remediated_environment)
        summary_after = calculate_risk(findings_after)

        completed_datetime = datetime.now(timezone.utc)
        completed = completed_datetime.isoformat()
        duration = (completed_datetime - started_datetime).total_seconds()

        if not args.quiet:
            reduction = summary_before["risk_score"] - summary_after["risk_score"]

            print("\nREASSESSMENT")
            print("─" * 45)
            print(f"Before risk:     {summary_before['risk_score']}/100")
            print(f"After risk:      {summary_after['risk_score']}/100")
            print(f"Risk reduction:  {reduction} points")
            print(f"Before findings: {summary_before['total']}")
            print(f"After findings:  {summary_after['total']}")
            print(f"Final risk:      {summary_after['overall']}")

        report = build_report(
            scan_id,
            mode,
            source,
            started,
            completed,
            duration,
            findings_after,
            summary_after,
            before_summary=summary_before,
            fixed=fixed,
        )

    else:
        completed_datetime = datetime.now(timezone.utc)
        completed = completed_datetime.isoformat()
        duration = (completed_datetime - started_datetime).total_seconds()

        report = build_report(
            scan_id,
            mode,
            source,
            started,
            completed,
            duration,
            findings_before,
            summary_before,
        )

    json_report = save_json_report(report, args.json_output)

    html_report = None
    if not args.no_html:
        html_report = save_html_report(report)

    if not args.quiet:
        print("\n[+] JSON report saved:")
        print(f"    {json_report}")

        if html_report:
            print("[+] HTML report saved:")
            print(f"    {html_report}")

        print("\n[+] Scan ID:")
        print(f"    {scan_id}")
        print("\n[+] CloudGuard assessment completed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
