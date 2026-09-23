# Security Policy

The Gorgona team takes security, cryptographic correctness, and user safety seriously. We appreciate the responsible disclosure of vulnerabilities by the community.

---

## Supported Versions

Gorgona is composed of several ecosystem components. Security updates and patches are provided for the current active versions listed below:

| Component | Supported Release | Status | Notes |
| :--- | :--- | :--- | :--- |
| **gorgonad** | `3.5.x` (current: `v3.5.2`) | :white_check_mark: | Daemon & network listener |
| **gorgona** | `3.1.x` (current: `v3.1.1`) | :white_check_mark: | Core CLI client |
| **gfm** | `1.3.x` (current: `v1.3.2`) | :white_check_mark: | Gorgona Failover Manager https://github.com/psqlmaster/gorgona/blob/master/plugins/gfm/readme.md |
| **gorgona_steno** | `latest` | :white_check_mark: | web ui https://github.com/psqlmaster/gorgona/tree/master#quick-start-gorgona-stheno |
| *Older versions* | `< 3.x` / unmaintained | :x: | EOL; please upgrade |

---

## Scope & Critical Areas

We particularly welcome reports on:
- **Cryptographic implementations:** Vulnerabilities in time-lock encryption, key exchange, signature verification, or randomness generation.
- **Remote Execution Boundary:** Bypass of safety controls in listener execution (`-e` / `--exec`), command injection, or unauthorized command escalation.
- **Key & Secret Material Exposure:** Memory leakage of private keys (`.pub` / `.sec`), timing attacks, or unsafe storage on disk.
- **Steganography Carrier Vulnerabilities:** Buffer overflows, out-of-bounds reads/writes, or malformed carrier parsing in `gorgona_steno`.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or discussions.**

### 1. Preferred Method: GitHub Private Vulnerability Reporting
You can report security issues privately directly through GitHub:
1. Navigate to the **Security** tab of the `gorgona` repository.
2. Under **Reporting**, click **Report a vulnerability**.
3. Fill in the advisory form with detailed reproduction steps and impact.

### 2. Alternative: Direct Contact
If you cannot use GitHub Security Advisories, send an encrypted report to our maintainer address:
* **Contact:** `security@gorgona.network` *(или укажите ваш личный/проектный email)*
* *(Optional)* Use our PGP public key to encrypt sensitive details, traces, or PoCs.

---

## What to Include in Your Report

To help us investigate and patch the issue promptly, please include:
- Component name and exact version (e.g. `gorgona v3.1.1` or `gorgonad v3.5.2`).
- Operating system, architecture, and deployment environment.
- A concise description of the vulnerability and its potential security impact.
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- Any proposed mitigations or patch suggestions (if available).

---

## Response Timeline & Expectations

- **Initial Response:** We will acknowledge receipt of your vulnerability report within **48 to 72 hours**.
- **Triage & Assessment:** Within **5 business days**, we will confirm whether the vulnerability is accepted or declined, along with a severity assessment (CVSS rating).
- **Remediation & Patching:** If accepted, we will work with you to test the fix and schedule a coordinated security release.
- **Public Disclosure:** We practice coordinated vulnerability disclosure (CVD). A public advisory and release notes will be published once the patch is verified and tagged.
- **Credit:** We gladly credit security researchers in our release notes and GitHub Security Advisories (unless anonymity is requested).
