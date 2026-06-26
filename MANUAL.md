# SBOMguard User Manual

SBOMguard finds vulnerabilities in your applications. You give it a "bill of materials" (list of libraries your app uses), it checks if any are dangerous.

---

## Quick Start

### What's an SBOM?

A list of all software components in an app. Tools like Syft generate them automatically:

```bash
# Example: scan a Docker image
syft ghcr.io/myapp:latest -o json > myapp-sbom.json
```

Result is JSON listing all packages: `npm packages, Python pip, Java maven, system libraries, etc.`

### Upload & Check

1. **Generate SBOM** from your app (Syft, CycloneDX, etc.)
2. **Upload to SBOMguard** at `http://localhost:8082`
3. **See vulnerabilities** — red = critical, orange = high, yellow = medium
4. **Track fixes** — note which package version fixes each CVE

---

## Reading Results

Click an SBOM to see vulnerabilities:

| Field | Meaning |
|-------|---------|
| **Package** | Library name (e.g., `lodash`, `log4j`) |
| **Current** | Version you're using |
| **Fixed** | Version with the patch |
| **CVE** | Vulnerability ID (e.g., CVE-2021-44228) |
| **CVSS** | Severity 0–10 (10 = critical) |
| **Status** | Not fixed / Patched / Suppressed |

### Example

```
lodash 4.17.20
├─ CVE-2021-23337 — Regular expression DoS
│  ├─ CVSS: 7.5 (HIGH)
│  ├─ Fixed in: 4.17.21
│  └─ Status: Upgrade needed
│
├─ CVE-2020-28500 — Prototype pollution
│  ├─ CVSS: 6.1 (MEDIUM)
│  ├─ Fixed in: 4.17.21
│  └─ Status: Upgrade needed
```

---

## Workflow

### 1. Upload New App Version

Before deploying app v2.0:
1. Build SBOM: `syft myapp:2.0 -o json > v2.0.json`
2. Upload to SBOMguard
3. Review vulnerabilities

### 2. Assess Risk

- **CVSS 9+:** Do not deploy until patched
- **CVSS 7–9:** High priority to patch
- **CVSS 5–7:** Medium priority
- **CVSS <5:** Low priority, can wait

### 3. Plan Remediation

For each HIGH/CRITICAL:
1. Find fixed version
2. Update package
3. Re-run build & tests
4. Regenerate SBOM
5. Verify vulnerability gone
6. Deploy

### 4. Track Progress

Mark vulnerabilities as you fix them:
- **Vulnerable:** Not fixed yet
- **Patched:** Fixed in new version
- **Suppressed:** Accepted risk (requires justification)

---

## Common Scenarios

### Scenario 1: Log4j Vulnerability Found

**SBOM shows:** `log4j-core 2.14.1 → CVE-2021-44228 (CVSS 10)`

**Action:**
1. Upgrade: `maven: log4j:2.17.1`
2. Rebuild app
3. Generate new SBOM
4. Re-upload
5. Verify CVE gone

### Scenario 2: Old Package, No Update Available

**SBOM shows:** `oldlib 1.0 → CVE-2020-1234 (CVSS 8), no fix available`

**Options:**
1. Replace with newer library
2. Suppress with justification ("Old library, isolated from network")
3. Mitigate: "Only used in offline batch jobs"

### Scenario 3: Many Vulnerabilities

**SBOM shows:** 47 vulnerabilities across 200 packages

**Triage:**
1. Sort by CVSS (address HIGH/CRITICAL first)
2. Group by package (easier to track)
3. Create remediation sprint
4. Track progress weekly

---

## Export & Reporting

**Export to CSV:** All vulnerabilities in spreadsheet

**Export to SIEM:** Feed vulnerability data to SOCops/socint

**Report template:**
```
App: MyApp v2.0
SBOM Date: 2026-04-19
Total Packages: 200
Vulnerabilities: 12
  - Critical: 1 (log4j, unfixed → block deployment)
  - High: 3 (all fixable → patch this week)
  - Medium: 5 (low priority)
  - Low: 3 (can defer)

Remediation Plan:
- Week 1: Fix Critical + High
- Week 2: Re-test, deploy
- Week 3+: Fix Medium/Low
```

---

## Tips

- **Automate SBOM generation** in CI/CD pipeline
- **Track over time** — upload after each release
- **Use suppression sparingly** — suppressed CVEs still need mitigation
- **Coordinate with DevOps** — patches need testing

---

That's it. Upload → assess → fix → ship.
