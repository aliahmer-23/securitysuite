# SecuritySuite v2.2.0

**Automated Network & Cloud Security Assessment Platform**

SecuritySuite is a Python-based cybersecurity portfolio project that
combines two security assessment engines:

- **NetScout v6.0.0** — network discovery, TCP port scanning,
  service fingerprinting, HTTP/TLS inspection, security analysis, and
  risk scoring.
- **CloudGuard v6.0.0** — local cloud-configuration security
  assessment, remediation simulation, risk scoring, and reporting.

SecuritySuite orchestrates both engines, normalizes their findings,
calculates a unified security score, and produces structured **JSON**
and professional **HTML** reports.

> **Important:** Use NetScout/SecuritySuite network scanning only
> against systems you own or have explicit permission to assess.
> CloudGuard v6.0.0 operates on local simulated/configuration data and
> does not connect to a real AWS account.

---

## Project Status

**Release:** SecuritySuite v2.2.0  
**NetScout:** v6.0.0  
**CloudGuard:** v6.0.0  
**Status:** Portfolio-ready core release

The final integration test successfully executed both assessment
engines, combined their findings, calculated unified risk, and generated
JSON and HTML reports.

Example full-assessment results:

| Component | Result |
|---|---:|
| NetScout status | SUCCESS |
| NetScout open ports | 2 |
| NetScout findings | 8 |
| NetScout risk | 28/100 — MEDIUM |
| CloudGuard status | SUCCESS |
| CloudGuard findings | 12 |
| CloudGuard risk | 76/100 — CRITICAL |
| Combined findings | 20 |
| Combined risk | 100/100 — CRITICAL |

These numbers are an example assessment result, not a fixed output of
the application.

---

## Architecture

```text
                         +----------------------+
                         |    SecuritySuite     |
                         |       v2.2.0         |
                         +----------+-----------+
                                    |
                     +--------------+--------------+
                     |                             |
                     v                             v
            +----------------+            +----------------+
            |    NetScout    |            |   CloudGuard   |
            |     v6.0.0     |            |     v6.0.0     |
            +-------+--------+            +-------+--------+
                    |                             |
          Network assessment             Local cloud config
          Service fingerprinting         IAM / S3 / SG / logs
          HTTP/TLS analysis              Risk analysis
          Security findings              Remediation simulation
                    |                             |
                    +--------------+--------------+
                                   |
                                   v
                         +----------------------+
                         | Unified Findings     |
                         | Unified Risk Score   |
                         | JSON + HTML Reports  |
                         +----------------------+
```

---

## Key Features

### SecuritySuite

- Orchestrates network and cloud-security assessments.
- Supports `full`, `network-only`, and `cloud-only` modes.
- Uses structured JSON integration between components.
- Tracks component execution status and failures.
- Normalizes findings from both engines.
- Calculates a unified SecuritySuite risk score.
- Generates combined JSON and HTML reports.
- Supports CloudGuard remediation simulation.
- Distinguishes initial risk from residual post-remediation risk.
- Produces portfolio-ready assessment evidence.

### NetScout v6.0.0

- TCP port discovery.
- Concurrent scanning with configurable workers and timeouts.
- `quick`, `web`, `standard`, and `full` scan profiles.
- Custom port ranges.
- Hostname, IP address, and URL target normalization.
- Service fingerprinting.
- Banner collection.
- HTTP/HTTPS probing.
- Basic TLS inspection.
- HTTP security-header analysis.
- Detection of exposed services such as SSH, FTP, SMB, and RDP.
- Evidence-based security findings.
- Risk scoring.
- Structured JSON and HTML reports.

### CloudGuard v6.0.0

- Local cloud-security configuration analysis.
- Account/root-access-key checks.
- MFA checks.
- IAM credential and privilege checks.
- Password-policy checks.
- S3 public-access, encryption, and versioning checks.
- Security-group exposure analysis.
- CloudTrail/logging checks.
- Evidence and remediation recommendations.
- Local remediation simulation.
- Before/after risk comparison.
- Residual-risk calculation.
- Structured JSON and HTML reports.

---

## CloudGuard Scope

CloudGuard v6.0.0 is intentionally a **local cloud-security
simulation/configuration assessment engine**.

It does **not**:

- require an AWS account;
- require AWS credentials;
- call AWS APIs;
- modify real cloud resources;
- generate cloud charges.

This makes the current release safe for demonstrations and portfolio use
while showing cloud-security assessment logic.

---

## Requirements

- Python 3
- An environment capable of running Python 3
- No third-party Python packages are required by the current core scripts

The project primarily uses Python standard-library modules.

---

## Project Structure

```text
securitysuite/
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── cloudguard/
│   └── cloudguard.py
│
├── docs/
│   ├── sample-report.html
│   └── sample-report.json
│
├── netscout/
│   └── netscout.py
│
├── tests/
│   ├── __init__.py
│   ├── test_cloudguard.py
│   ├── test_netscout.py
│   └── test_securitysuite.py
│
├── cloud_environment.json
├── securitysuite.py
├── README.md
└── .gitignore
```

Generated assessment reports are written to the `reports/` directory
and are excluded from version control.

---

## Usage

Run commands from the SecuritySuite project directory.

### Check Version

```bash
python3 securitysuite.py --version
```

### Cloud-Only Assessment

```bash
python3 securitysuite.py --mode cloud-only
```

### Cloud Assessment With Remediation Simulation

```bash
python3 securitysuite.py --mode cloud-only --remediate
```

### Network-Only Assessment

Only scan systems you own or have explicit authorization to test.

```bash
python3 securitysuite.py \
  --mode network-only \
  --target YOUR_AUTHORIZED_TARGET \
  --network-profile quick
```

### Full Assessment

Runs both NetScout and CloudGuard:

```bash
python3 securitysuite.py \
  --mode full \
  --target YOUR_AUTHORIZED_TARGET \
  --network-profile quick
```

### Full Assessment With CloudGuard Remediation

```bash
python3 securitysuite.py \
  --mode full \
  --target YOUR_AUTHORIZED_TARGET \
  --network-profile quick \
  --remediate
```

---

## NetScout Profiles

| Profile | Purpose |
|---|---|
| `quick` | Selected common/security-relevant TCP ports |
| `web` | Common web/application ports |
| `standard` | TCP ports 1–1024 |
| `full` | TCP ports 1–65535 |

Use the least intrusive profile needed for an authorized assessment.

---

## Example Network Findings

Depending on the target and its configuration, NetScout can generate
findings such as:

- SSH service reachable
- FTP service exposed
- Telnet service exposed
- SMB service reachable
- RDP service reachable
- Unencrypted HTTP reachable
- Missing Content-Security-Policy
- Missing clickjacking protection
- Missing X-Content-Type-Options
- Missing Referrer-Policy
- Missing HSTS on HTTPS
- Service/software information disclosure
- Legacy TLS protocol negotiated

Findings are based on observed network/service behavior and should be
validated in context before being treated as confirmed vulnerabilities.

---

## Example Cloud Findings

CloudGuard can identify simulated configuration issues including:

- Root access key present
- MFA disabled
- Unused IAM credentials
- Multiple administrative users
- Weak password policy
- S3 public-access protection disabled
- S3 encryption disabled
- S3 versioning disabled
- SSH/RDP exposure through security groups
- HTTP exposure
- CloudTrail logging disabled

Each finding includes severity, category, observation, impact,
recommendation, evidence, and status.

---

## Risk Scoring

SecuritySuite produces a unified risk score from normalized findings.

The combined SecuritySuite methodology uses the following
severity-based weights:

| Severity | Risk Points |
|---|---:|
| CRITICAL | 25 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 0 |

The combined score is capped at **100**.

Component-specific risk scores remain visible separately. NetScout and
CloudGuard may retain engine-specific scoring thresholds, while
SecuritySuite provides the unified cross-component assessment score.

This separation makes it possible to view:

1. network-specific risk;
2. cloud-specific risk; and
3. overall SecuritySuite risk.

For remediation assessments, SecuritySuite distinguishes the
**initial risk** from the **residual risk** remaining after simulated
remediation.

---

## Reporting

SecuritySuite creates combined reports in the `reports/` directory.

Example:

```text
reports/
├── securitysuite_YYYYMMDD_HHMMSS_<scan-id>.json
└── securitysuite_YYYYMMDD_HHMMSS_<scan-id>.html
```

Reports can contain:

- assessment metadata;
- scan IDs;
- component versions and statuses;
- assessment target information;
- discovered services;
- normalized security findings;
- severity counts;
- network and cloud finding counts;
- component risk scores;
- unified risk scores;
- evidence;
- remediation recommendations;
- remediation results when enabled;
- initial and residual risk information.

Generated operational reports are excluded from Git version control.

---

## Sample Security Assessment Report

SecuritySuite includes sanitized sample reports demonstrating the
CloudGuard **detection → remediation → reassessment** workflow.

### Example Assessment Result

| Metric | Result |
|---|---:|
| Initial Risk | **76/100 — CRITICAL** |
| Initial Findings | **12** |
| Simulated Fixes | **12** |
| Residual Risk | **0/100 — PASS** |
| Remaining Findings | **0** |
| Risk Reduction | **76 points** |

The sample demonstrates how SecuritySuite identifies security
misconfigurations, simulates remediation actions, reassesses the
environment, and measures residual risk.

### Public Sample Files

- [`docs/sample-report.html`](docs/sample-report.html)
- [`docs/sample-report.json`](docs/sample-report.json)

The published sample reports are sanitized and do not intentionally
include local filesystem paths, device names, credentials, or secrets.

> CloudGuard remediation is simulated locally. No real AWS resources
> are accessed or modified.

---

## Automated Testing & CI/CD

SecuritySuite includes an automated regression test suite covering the
core functionality of all three components.

### Test Coverage

- SecuritySuite integration and unified risk scoring.
- NetScout target validation.
- NetScout scan profiles.
- Port-risk classification.
- Service identification.
- CloudGuard configuration assessment.
- CloudGuard security findings.
- CloudGuard risk scoring.
- CloudGuard remediation behavior.
- Combined SecuritySuite remediation behavior.

The current test suite contains **31 automated tests**.

Run the complete test suite locally with:

```bash
python3 -m unittest discover -s tests -v
```

A successful run should end with:

```text
Ran 31 tests

OK
```

### Continuous Integration

SecuritySuite uses **GitHub Actions** for continuous integration.

The complete automated test suite runs automatically on:

- pushes to the `main` branch;
- pull requests targeting `main`.

This provides continuous validation of SecuritySuite changes and helps
detect regressions before new code is integrated.

---

## Security and Privacy

SecuritySuite is designed so generated public evidence can be sanitized
before publication.

The public sample reports have been checked for obvious exposure of:

- local filesystem paths;
- local device/computer names;
- local usernames;
- temporary local paths;
- obvious credentials and access tokens;
- private-key material.

Raw subprocess output is not included in the combined public report
data.

Users should still review generated reports before publishing them,
particularly when assessments involve real authorized targets.

---

## Security and Ethical Use

SecuritySuite is intended for:

- cybersecurity education;
- defensive security engineering;
- authorized security assessments;
- controlled lab environments;
- portfolio demonstrations.

Do not use the network-scanning functionality against systems without
permission.

The presence of an open port, missing header, banner, or exposed service
does not by itself prove that a system is exploitable. Findings should
be interpreted and validated by a security professional.

---

## Skills Demonstrated

This project demonstrates practical experience with:

- Python security automation
- TCP networking and sockets
- concurrent programming
- service enumeration and fingerprinting
- HTTP security analysis
- TLS inspection
- cloud-security configuration analysis
- IAM security concepts
- network exposure analysis
- security risk scoring
- remediation logic
- residual-risk assessment
- JSON-based component integration
- structured security reporting
- automated regression testing
- GitHub Actions CI/CD
- report privacy hardening
- error handling and component orchestration
- defensive security tooling design

---

## Current Limitations

- CloudGuard currently assesses local simulated/configuration data
  rather than a live AWS environment.
- NetScout performs lightweight security assessment and service
  fingerprinting; it is not intended to replace enterprise
  vulnerability scanners.
- Findings can require manual validation.
- Risk scores are prioritization aids rather than formal compliance or
  vulnerability ratings.
- Network results depend on routing, firewalls, service availability,
  and the assessment host's network position.
- CloudGuard remediation in the current release is simulated rather
  than applied to real cloud infrastructure.

These limitations are deliberate and should be represented accurately
when demonstrating the project.

---

## Future Possibilities

The v2.2.x core is considered complete for portfolio purposes.

Potential future research directions could include:

- optional cloud-provider API integrations;
- additional configuration policies;
- richer asset inventory;
- standardized finding formats;
- expanded automated test coverage;
- optional CI security scanning.

These are future possibilities rather than requirements for the current
portfolio release.

---

## Author

**Ali**  
Cybersecurity portfolio project

---

## Disclaimer

SecuritySuite is an educational and defensive security project.

Network-assessment features must only be used on systems for which the
operator has explicit authorization.

CloudGuard's remediation functionality is a local simulation and does
not modify real cloud infrastructure.

The author assumes no responsibility for unauthorized or unlawful use.