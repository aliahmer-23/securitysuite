# SecuritySuite v2.2.0

**Automated Network & Cloud Security Assessment Platform**

SecuritySuite is a Python-based cybersecurity portfolio project that
combines two security assessment engines:

-   **NetScout v6.0.0** --- network discovery, TCP port scanning,
    service fingerprinting, HTTP/TLS inspection, security analysis, and
    risk scoring.
-   **CloudGuard v6.0.0** --- local cloud-configuration security
    assessment, remediation simulation, risk scoring, and reporting.

SecuritySuite orchestrates both engines, normalizes their findings,
calculates a unified security score, and produces structured **JSON**
and professional **HTML** reports.

> **Important:** Use NetScout/SecuritySuite network scanning only
> against systems you own or have explicit permission to assess.
> CloudGuard v6.0.0 operates on local simulated/configuration data and
> does not connect to a real AWS account.

------------------------------------------------------------------------

## Project Status

**Release:** SecuritySuite v2.2.0\
**NetScout:** v6.0.0\
**CloudGuard:** v6.0.0\
**Status:** Portfolio-ready core release

The final integration test successfully executed both assessment
engines, combined their findings, calculated unified risk, and generated
JSON and HTML reports.

Example final test results:

  Component                             Result
  --------------------- ----------------------
  NetScout status                      SUCCESS
  NetScout open ports                        2
  NetScout findings                          8
  NetScout risk              28/100 --- MEDIUM
  CloudGuard status                    SUCCESS
  CloudGuard findings                       12
  CloudGuard risk          76/100 --- CRITICAL
  Combined findings                         20
  Combined risk           100/100 --- CRITICAL

These numbers are an example assessment result, not a fixed output of
the application.

------------------------------------------------------------------------

## Architecture

``` text
                         +----------------------+
                         |   SecuritySuite      |
                         |      v2.2.0          |
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

------------------------------------------------------------------------

## Key Features

### SecuritySuite

-   Orchestrates network and cloud-security assessments.
-   Supports `full`, `network-only`, and `cloud-only` modes.
-   Uses structured JSON integration between components.
-   Tracks component execution status and failures.
-   Normalizes findings from both engines.
-   Calculates a unified SecuritySuite risk score.
-   Generates combined JSON and HTML reports.
-   Supports CloudGuard remediation simulation.

### NetScout v6.0.0

-   TCP port discovery.
-   Concurrent scanning with configurable workers and timeouts.
-   `quick`, `web`, `standard`, and `full` scan profiles.
-   Custom port ranges.
-   Hostname, IP address, and URL target normalization.
-   Service fingerprinting.
-   Banner collection.
-   HTTP/HTTPS probing.
-   Basic TLS inspection.
-   HTTP security-header analysis.
-   Detection of exposed services such as SSH, FTP, SMB, and RDP.
-   Evidence-based security findings.
-   Risk scoring.
-   Structured JSON and HTML reports.

### CloudGuard v6.0.0

-   Local cloud-security configuration analysis.
-   Account/root-access-key checks.
-   MFA checks.
-   IAM credential and privilege checks.
-   Password-policy checks.
-   S3 public-access, encryption, and versioning checks.
-   Security-group exposure analysis.
-   CloudTrail/logging checks.
-   Evidence and remediation recommendations.
-   Local remediation simulation.
-   Before/after risk comparison.
-   Structured JSON and HTML reports.

------------------------------------------------------------------------

## CloudGuard Scope

CloudGuard v6.0.0 is intentionally a **local cloud-security
simulation/configuration assessment engine**.

It does **not**:

-   require an AWS account;
-   require AWS credentials;
-   call AWS APIs;
-   modify real cloud resources;
-   generate cloud charges.

This makes the current release safe for demonstrations and portfolio use
while showing cloud-security assessment logic.

------------------------------------------------------------------------

## Requirements

-   Python 3
-   macOS, Linux, or another environment capable of running Python 3
-   No third-party Python packages are required by the current core
    scripts.

The project primarily uses Python standard-library modules.

------------------------------------------------------------------------

## Suggested Project Structure

``` text
securitysuite/
├── securitysuite.py
├── cloud_environment.json
├── reports/
│
├── netscout/
│   └── netscout.py
│
└── cloudguard/
    └── cloudguard.py
```

The exact relative locations should match the paths configured in
`securitysuite.py`.

------------------------------------------------------------------------

## Usage

From the SecuritySuite directory:

``` bash
cd ~/Desktop/securitysuite
```

Check the installed SecuritySuite version:

``` bash
python3 securitysuite.py --version
```

### Cloud-only assessment

``` bash
python3 securitysuite.py --mode cloud-only
```

### Cloud assessment with remediation simulation

``` bash
python3 securitysuite.py --mode cloud-only --remediate
```

### Network-only assessment

Only scan systems you own or have explicit authorization to test.

``` bash
python3 securitysuite.py --mode network-only --target YOUR_AUTHORIZED_TARGET --network-profile quick
```

### Full assessment

Runs both NetScout and CloudGuard:

``` bash
python3 securitysuite.py --mode full --target YOUR_AUTHORIZED_TARGET --network-profile quick
```

### Full assessment with CloudGuard remediation simulation

``` bash
python3 securitysuite.py --mode full --target YOUR_AUTHORIZED_TARGET --network-profile quick --remediate
```

------------------------------------------------------------------------

## NetScout Profiles

  Profile      Purpose
  ------------ ---------------------------------------------
  `quick`      Selected common/security-relevant TCP ports
  `web`        Common web/application ports
  `standard`   TCP ports 1--1024
  `full`       TCP ports 1--65535

Use the least intrusive profile needed for an authorized assessment.

------------------------------------------------------------------------

## Example Network Findings

Depending on the target and its configuration, NetScout can generate
findings such as:

-   SSH service reachable
-   FTP service exposed
-   Telnet service exposed
-   SMB service reachable
-   RDP service reachable
-   Unencrypted HTTP reachable
-   Missing Content-Security-Policy
-   Missing clickjacking protection
-   Missing X-Content-Type-Options
-   Missing Referrer-Policy
-   Missing HSTS on HTTPS
-   Service/software information disclosure
-   Legacy TLS protocol negotiated

Findings are based on observed network/service behavior and should be
validated in context before being treated as confirmed vulnerabilities.

------------------------------------------------------------------------

## Example Cloud Findings

CloudGuard can identify simulated configuration issues including:

-   Root access key present
-   MFA disabled
-   Unused IAM credentials
-   Multiple administrative users
-   Weak password policy
-   S3 public-access protection disabled
-   S3 encryption disabled
-   S3 versioning disabled
-   SSH/RDP exposure through security groups
-   HTTP exposure
-   CloudTrail logging disabled

Each finding includes severity, category, observation, impact,
recommendation, evidence, and status.

------------------------------------------------------------------------

## Risk Scoring

SecuritySuite produces a unified risk score from normalized findings.

The combined SecuritySuite methodology uses severity-based weights and
caps the final score at 100.

Component-specific risk scores remain visible separately. NetScout and
CloudGuard may retain engine-specific scoring thresholds, while
SecuritySuite provides the unified cross-component assessment score.

This separation makes it possible to view:

1.  network-specific risk;
2.  cloud-specific risk; and
3.  overall SecuritySuite risk.

------------------------------------------------------------------------

## Reporting

SecuritySuite creates combined reports in the `reports/` directory.

Example:

``` text
reports/
├── securitysuite_YYYYMMDD_HHMMSS_<scan-id>.json
└── securitysuite_YYYYMMDD_HHMMSS_<scan-id>.html
```

Reports can contain:

-   assessment metadata;
-   scan IDs;
-   component versions and statuses;
-   target information;
-   discovered services;
-   normalized security findings;
-   severity counts;
-   network and cloud finding counts;
-   component risk scores;
-   unified risk score;
-   evidence;
-   remediation recommendations;
-   remediation results when enabled.

------------------------------------------------------------------------

## Security and Ethical Use

SecuritySuite is intended for:

-   cybersecurity education;
-   defensive security engineering;
-   authorized security assessments;
-   controlled lab environments;
-   portfolio demonstrations.

Do not use the network-scanning functionality against systems without
permission.

The presence of an open port, missing header, banner, or exposed service
does not by itself prove that a system is exploitable. Findings should
be interpreted and validated by a security professional.

------------------------------------------------------------------------

## Skills Demonstrated

This project demonstrates practical experience with:

-   Python security automation
-   TCP networking and sockets
-   concurrent programming
-   service enumeration and fingerprinting
-   HTTP security analysis
-   TLS inspection
-   cloud-security configuration analysis
-   IAM security concepts
-   network exposure analysis
-   security risk scoring
-   remediation logic
-   JSON-based component integration
-   structured security reporting
-   error handling and component orchestration
-   defensive security tooling design

------------------------------------------------------------------------

## Current Limitations

-   CloudGuard currently assesses local simulated/configuration data
    rather than a live AWS environment.
-   NetScout performs lightweight security assessment and service
    fingerprinting; it is not intended to replace enterprise
    vulnerability scanners.
-   Findings can require manual validation.
-   Risk scores are prioritization aids rather than formal compliance or
    vulnerability ratings.
-   Network results depend on routing, firewalls, service availability,
    and the assessment host's network position.

These limitations are deliberate and should be represented accurately
when demonstrating the project.

------------------------------------------------------------------------

## Future Possibilities

The v2.2.0 core release is considered complete for portfolio purposes.
Potential future research directions could include:

-   optional cloud-provider API integrations;
-   CI/CD security checks;
-   additional configuration policies;
-   richer asset inventory;
-   standardized finding formats;
-   automated regression tests.

These are future possibilities rather than requirements for the current
release.

------------------------------------------------------------------------

## Author

**Ali**\
Cybersecurity portfolio project

------------------------------------------------------------------------

## Disclaimer

SecuritySuite is an educational and defensive security project.
Network-assessment features must only be used on systems for which the
operator has explicit authorization. The author assumes no
responsibility for unauthorized or unlawful use.
