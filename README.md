# SBOMguard

A lightweight, standalone SBOM vulnerability monitoring dashboard. Tracks your software inventory against multiple CVE and exploit intelligence feeds and alerts when a high-severity or actively exploited vulnerability matches something you run.

No external Python dependencies — stdlib only, SQLite, inline HTML/CSS/JS.

---

## Features

- **Multi-source vulnerability feeds** — NVD CVE API v2, CISA KEV, EPSS, OSV (covers GHSA and 20+ ecosystems)
- **Two matching strategies** — CPE exact match for commercial software; purl-based OSV query for open source packages
- **EPSS scoring** — daily exploitation probability from FIRST.org on every CVE
- **KEV highlighting** — CISA Known Exploited Vulnerabilities flagged everywhere
- **SBOM inventory management** — add/edit/delete items, mark as verified, track last-reviewed date
- **Match triage workflow** — acknowledge, mark false positive, or reopen matches
- **Dashboard** — KPIs, open matches, KEV matches, auto-refreshes every 60s
- **Systemd service** — runs as a background service, survives reboots

---

## Pages

| Page | Path | Description |
|---|---|---|
| Dashboard | `/` | KPIs, recent matches, KEV matches |
| SBOM | `/sbom` | Inventory management — add/edit/delete/verify items |
| CVEs | `/cves` | CVE browser with EPSS scores, KEV flag, score filter |
| Matches | `/matches` | Match queue — ack / FP / reopen workflow |

---

## Vulnerability Sources

| Source | Coverage | Key required |
|---|---|---|
| [NVD CVE API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVSS ≥ 7.8, incremental by `lastModified`, every 6h | Optional (free, increases rate limit) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities, full refresh daily | None |
| [EPSS](https://www.first.org/epss/) | Exploitation probability score (0–100%) for every CVE, daily | None |
| [OSV / GHSA](https://osv.dev) | Open source packages — PyPI, npm, Maven, Go, Cargo, NuGet, Debian, Ubuntu, Alpine and more | None |

---

## Matching

**Commercial software (CPE):** Set the CPE field on a SBOM item for precise matching against NVD data.
Example: `cpe:2.3:a:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*`

**Open source packages (purl):** Set the purl field on a SBOM item. SBOMguard queries OSV directly for that package, covering GHSA and all supported ecosystems.
Example: `pkg:pypi/requests@2.28.0`

**Fuzzy fallback:** If neither CPE nor purl is set, vendor and product names are fuzzy-matched against CVE affected product data from NVD.

---

## Installation

### Requirements

- Python 3.8+
- Linux with systemd (for service install)

### Setup

```bash
git clone https://github.com/diagonalciso/soc-sbom
cd soc-sbom
cp .env.example .env
# Edit .env to set port, CVSS threshold, and optionally an NVD API key
```

### Run manually

```bash
python3 app.py
```

### Install as systemd service

```bash
sudo cp soc-sbom.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-sbom
```

---

## Configuration

Edit `.env`:

```
SBOMGUARD_PORT=8082          # HTTP port
CVSS_THRESHOLD=7.8           # Minimum CVSS score to store from NVD
FEED_INTERVAL=21600          # Seconds between feed runs (default 6h)
NVD_API_KEY=                 # Optional — register free at nvd.nist.gov
```

---

## Project Structure

```
app.py               HTTP server, all routes, inline HTML pages
db.py                SQLite schema, migrations, CRUD functions
feeds.py             NVD, KEV, EPSS, OSV fetchers + SBOM matcher
.env                 Live configuration
soc-sbom.service    systemd unit file
```

---

## Stack

- Python stdlib only (no pip install)
- SQLite with WAL mode
- Inline HTML/CSS/JS — single-process, no build step


## Documentation

See **[MANUAL.md](MANUAL.md)** for the full manual (overview, configuration, endpoints, integration, troubleshooting). In the running dashboard, click the **`?` Help button** in the top-right corner to open it at `/manual`.
