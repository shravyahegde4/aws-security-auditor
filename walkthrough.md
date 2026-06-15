# CloudShield – AWS Cloud Security Auditor

## What was built

A premium, dark-themed, fully interactive single-page web application that simulates an AWS security audit workflow.

---

## Project Files

| File | Purpose |
|------|---------|
| [index.html](file:///c:/Users/Hegde/Downloads/Projects/aws-security-auditor/index.html) | Main application markup with sidebar and all five panels |
| [style.css](file:///c:/Users/Hegde/Downloads/Projects/aws-security-auditor/style.css) | Full design system — dark palette, glassmorphism cards, animations |
| [script.js](file:///c:/Users/Hegde/Downloads/Projects/aws-security-auditor/script.js) | Navigation controller, policy analysis engine, scanner simulator, policy generator |

---

## Application Features

### 1. Dashboard
- Live **Security Score gauge** (SVG ring, animates on scan completion)
- **Vulnerability breakdown** by severity (Critical / High / Medium / Low)
- **Compliance Index** bars for CIS, SOC 2, and HIPAA
- **Active Remediation Checklist** with direct "Resolve" navigation links
- **Auditing Activity Guide** with numbered step walkthrough

### 2. IAM Policy & Config Analyzer
- Code editor with **live line numbering**
- **4 pre-loaded sample policies** (via dropdown):
  - Vulnerable S3 Public GetObject
  - Overprivileged Admin (Wildcard Action)
  - Insecure Security Group (Open SSH)
  - Secure KMS Key Access
- Analyzer engine runs **5 security rule checks**:
  1. Public Principal (`*`) exposures
  2. Wildcard Admin access (`Action: *` + `Resource: *`)
  3. Wildcard actions on specific resources
  4. KMS admin without MFA condition
  5. Open SSH/RDP ports in Security Group configs
- Results with **expandable finding cards**, health score, severity pills, and inline **Remediation drawers** with copy buttons

### 3. Scan Simulator
- Configurable scans (5 services: IAM, S3, VPC, KMS, CloudTrail)
- 3 compliance baselines: CIS Benchmark, SOC 2, HIPAA
- **Animated streaming terminal console** with color-coded log severity
- Post-scan **Results Summary** with passed/failed/uncertain counters and a compliance score
- Scan results also **update the Dashboard** security gauge and compliance bars dynamically

### 4. CIS Compliance Checklist
- 4 expandable accordion sections (IAM, S3, Logging, Networking)
- **Pass/Fail filter chips** to quickly surface failing-only items
- 13 CIS controls with status badges and descriptions

### 5. Policy Generator
- Live form-to-JSON builder (reactive — updates as you type/change)
- Supports: **S3, KMS, DynamoDB, SQS**
- 4 permission levels: **Read, Write, Read/Write, Admin**
- Optional constraints: **MFA requirement**, **HTTPS-only enforcement** (generates a Deny block for S3)
- One-click **Copy JSON** button

---

## Running the App

The Python HTTP server is running in the background. Open the app at:

> **[http://localhost:8081](http://localhost:8081)**

If it ever stops, restart it with:
```bash
python -m http.server 8081
```
(run from `c:\Users\Hegde\Downloads\Projects\aws-security-auditor\`)
