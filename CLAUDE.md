# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Is SBOMguard?

SBOMguard is a **vulnerability scanner for software inventories**. 

**The problem it solves:** You deployed app v2.0. It has 200 dependencies. Are any of them vulnerable? Manually checking each would take hours.

**The solution:** You give SBOMguard a "bill of materials" (list of all libraries your app uses). It checks them against vulnerability databases (NVD, CISA, OSV) and instantly tells you "you have 12 vulnerabilities, 3 are critical."

## Key Characteristics

- **No pip dependencies** — Python stdlib only (ultra-lightweight)
- **SQLite database** — stores SBOMs and CVE data locally, auto-backed up
- **Background feed worker** — automatically fetches latest vulnerabilities every 6 hours
- **Simple web UI** — upload SBOM, see vulnerabilities, track fixes
- **Inline HTML** — no build step, no npm, pure Python + f-strings
- **Python 3.8+** required
- **Port 8082**

---

## Quick Start

```bash
# Setup
cp .env.example .env
# Edit .env: SBOMGUARD_PORT, CVSS_THRESHOLD, optional NVD_API_KEY

# Run directly
python3 app.py

# Or as systemd service
sudo cp sbomguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sbomguard
```

Listens on port 8082 (configurable via `.env`). Auto-fetches feeds every 6 hours.

---

## Architecture

### Data Flow

```
NVD CVE API v2 (CVSS ≥ 7.8)
CISA KEV (known exploited)
EPSS (exploitation probability)
OSV (open source packages)
         ↓
    Feed worker thread (async HTTP)
         ↓
    SQLite DB (sbomguard.db)
         ↓
    HTTP routes (app.py)
         ↓
    Browser (port 8082)
         ↓
    SBOM inventory + matches triage
```

### Core Modules

**app.py** (HTTP server + routes)
- Single-threaded `http.server.HTTPServer` on port 8082
- Routes:
  - `/` — Dashboard (KPIs, recent matches, KEV matches)
  - `/sbom` — Inventory management (add/edit/delete/verify items)
  - `/cves` — CVE browser with EPSS scores and KEV flags
  - `/matches` — Match queue (triage workflow: ack/FP/reopen)
  - `/api/*` — JSON endpoints for programmatic access
- All HTML pages are inline f-strings; no separate frontend
- Spawns `_feed_worker()` thread on startup

**db.py** (SQLite schema + CRUD)
- Connection pooling via `threading.local()`
- Migrations handled in `_migrate()` function
- WAL mode enabled for concurrent read access
- Foreign key constraints enabled
- Auto-creates schema if tables don't exist

**feeds.py** (Multi-source vulnerability fetcher)
- **NVD CVE API v2**: Queries for CVEs with CVSS ≥ threshold (every 6h, incremental by `lastModified`)
- **CISA KEV**: Known Exploited Vulnerabilities (daily full refresh)
- **EPSS**: Exploitation probability scores (daily)
- **OSV**: Open source package vulnerabilities (covers PyPI, npm, Maven, Go, Cargo, NuGet, Debian, Ubuntu, Alpine, etc.)
- All fetches are HTTP-based; errors are logged and retried

### Background Feed Worker

Runs in a separate thread, continuously:
1. Sleep `FEED_INTERVAL` (default 6h)
2. Call `feeds.run_all()` — fetches from all 4 sources in parallel
3. Parse responses and insert/update CVE records
4. Match new CVEs against SBOM inventory
5. Log errors but don't crash

---

## Database Schema

```sql
sbom_items
  ├─ id (PK)
  ├─ vendor, product, version  — software identity
  ├─ cpe                       — CPE string for commercial software matching
  ├─ purl                      — Package URL (pkg:pypi/..., pkg:npm/..., etc.)
  ├─ host                      — hostname/IP where inventory came from
  ├─ installed_version         — reported installed version
  ├─ last_reviewed_at          — analyst mark
  ├─ verified_at               — analyst confirmation
  └─ created_at, updated_at

cves
  ├─ id (PK)
  ├─ cve_id                    — CVE-YYYY-NNNN
  ├─ description
  ├─ cvss_score                — CVSS v3 score (0-10)
  ├─ cvss_severity             — LOW|MEDIUM|HIGH|CRITICAL
  ├─ epss                      — exploitation probability (0-100%)
  ├─ epss_percentile           — percentile rank
  ├─ is_kev                    — boolean (CISA Known Exploited)
  ├─ fix_versions              — JSON array of patched versions
  ├─ affected_products         — JSON array of {vendor, product, version_range}
  └─ published_at, updated_at

matches
  ├─ id (PK)
  ├─ sbom_item_id (FK)
  ├─ cve_id (FK)
  ├─ match_type                — cpe|purl|fuzzy (matching strategy used)
  ├─ status                    — open|ack|false_positive|reopened
  ├─ analyst_notes
  └─ created_at, updated_at
```

---

## Routes & API

### HTML Pages

| Path | Purpose |
|------|---------|
| `/` | Dashboard: KPI cards, recent matches, KEV matches, alert trend |
| `/sbom` | Inventory management: add/edit/delete items, mark verified |
| `/cves` | CVE browser with EPSS scores, KEV flag, CVSS filter |
| `/matches` | Match queue: triage workflow (ack/FP/reopen) |

### JSON API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/sbom` | GET | List SBOM items |
| `/api/sbom` | POST | Add SBOM item |
| `/api/sbom/{id}` | PUT | Edit SBOM item |
| `/api/sbom/{id}` | DELETE | Remove SBOM item |
| `/api/cves` | GET | List CVEs with filters |
| `/api/matches` | GET | List matches with status filter |
| `/api/matches/{id}` | PUT | Update match status |
| `/api/import/cyclonedx` | POST | Import CycloneDX JSON |
| `/api/import/spdx` | POST | Import SPDX JSON |

---

## Configuration

Edit `.env`:

```env
SBOMGUARD_PORT=8082           # HTTP listen port
CVSS_THRESHOLD=7.8            # Min CVSS score to store from NVD
FEED_INTERVAL=21600           # Seconds between feed runs (6h default)
NVD_API_KEY=                  # Optional — register free at nvd.nist.gov (boosts rate limit)
```

### Feed Update Behavior

- **NVD**: Queries incrementally by `lastModified` (no re-fetching old data)
- **CISA KEV**: Full refresh daily (small dataset, ~1000 items)
- **EPSS**: Full refresh daily (all CVEs)
- **OSV**: Queried on-demand when SBOM item has a `purl` set

---

## Matching Strategies

### CPE Matching (Commercial Software)

Set the `cpe` field on an SBOM item. Example:
```
cpe:2.3:a:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*
```

Matched against NVD's `affected_products` list. Exact and wildcard matching supported.

### PURL Matching (Open Source Packages)

Set the `purl` field on an SBOM item. Example:
```
pkg:pypi/requests@2.28.0
pkg:npm/lodash@4.17.21
pkg:maven/org.springframework.boot/spring-boot@2.7.0
```

Queries OSV API for that exact package/version. Covers GHSA and 20+ ecosystems.

### Fuzzy Fallback

If neither CPE nor PURL is set, vendor and product names are fuzzy-matched against NVD data. Less reliable but useful for generic names.

---

## Key Design Decisions

### Zero Dependencies

No pip packages. Entire app uses only Python stdlib. Trade-off: simpler deployment, easier to audit, but less sophisticated HTTP client (basic urllib).

### WAL Mode

SQLite in WAL (Write-Ahead Log) mode allows concurrent reads while writes are happening. Important for the feed worker updating CVE data while UI is querying.

### Background Feed Worker

Separate thread handles all network I/O (NVD, CISA KEV, EPSS, OSV). Non-blocking from the HTTP server's perspective. Failures are logged but don't crash the app.

### Inline HTML

No separate frontend build step. All pages are f-string templates in `app.py`. Trade-off: easier to modify, single-file deployment; but harder to version control large HTML blocks.

---

## Common Tasks

### Add a New Vulnerability Feed Source

1. Add a function in `feeds.py`: `def _fetch_mysource()`
2. Call it from `feeds.run_all()`
3. Parse response and insert into `cves` table
4. Maintain the same columns (cve_id, description, cvss_score, etc.)

### Add a New SBOM Import Format

1. Add a parser in `app.py:_parse_sbom()` (currently handles CycloneDX and SPDX)
2. Extract vendor, product, version, cpe, purl from the format
3. Insert into `sbom_items` table

### Customize CVSS Threshold

Edit `.env`:
```env
CVSS_THRESHOLD=6.5   # Store all CVEs ≥ 6.5 instead of 7.8
```

Feed worker will re-fetch from NVD next run.

### Export SBOM as CSV

Endpoint: `GET /api/export/sbom?format=csv`

Returns CSV with columns: vendor, product, version, cpe, purl, last_reviewed_at, verified_at

### Query Matches Programmatically

```bash
# Get all open matches
curl http://localhost:8082/api/matches?status=open

# Get all KEV matches
curl http://localhost:8082/api/matches?kev=true

# Update match to acknowledged
curl -X PUT http://localhost:8082/api/matches/123 \
  -d '{"status":"ack","notes":"Patched on 2026-04-20"}'
```

---

## Database Lifecycle

### Initialization

On first run, `db.init_db()` creates all tables. Subsequent runs detect schema version via column introspection and run migrations if needed (new columns are added safely).

### Feed Updates

Feed worker calls `feeds.run_all()` every 6 hours:
1. Fetch from each source
2. Parse and validate responses
3. Insert new CVEs or update existing ones
4. Commit transaction
5. Log summary (e.g., "fetched 150 new CVEs from NVD")

### Match Generation

After a feed update:
1. New CVEs are scanned against all SBOM items
2. Matching is done via `db.find_matches(cve_id)` (CPE, PURL, fuzzy)
3. New match records are inserted with `status='open'`
4. Analysts triage via UI (ack/FP/reopen)

---

## Systemd Service

File: `sbomguard.service`

```ini
[Unit]
Description=SBOMguard — SBOM Vulnerability Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/SBOMguard
Environment="SBOMGUARD_PORT=8082"
Environment="CVSS_THRESHOLD=7.8"
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Install:
```bash
sudo cp sbomguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sbomguard
sudo journalctl -u sbomguard -f
```

---

## Debugging

### Check Feed Status

Look at stdout/stderr or systemd logs:
```bash
sudo journalctl -u sbomguard -f
```

Feed worker logs lines like:
```
[feeds] fetched 150 new CVEs from NVD
[feeds] fetched 42 KEV items from CISA
[feeds] matched 12 new vulnerabilities against SBOM
```

### Query the Database Directly

```bash
sqlite3 sbomguard.db

# Count CVEs
> SELECT COUNT(*) FROM cves;

# List open matches
> SELECT si.vendor, si.product, c.cve_id, c.cvss_score
  FROM matches m
  JOIN sbom_items si ON m.sbom_item_id = si.id
  JOIN cves c ON m.cve_id = c.id
  WHERE m.status = 'open'
  ORDER BY c.cvss_score DESC;

# Check SBOM items
> SELECT vendor, product, version, cpe, purl FROM sbom_items;
```

### Test Feed Fetch Manually

```python
import feeds
result = feeds._fetch_nvd()
print(f"Fetched {len(result)} CVEs from NVD")
```

### Check WAL File Size

WAL (write-ahead log) can grow large. If `sbomguard.db-wal` is huge, restart the service to trigger a checkpoint:
```bash
sudo systemctl restart sbomguard
```

---

## Performance Notes

- **Feed fetch**: ~30-60 seconds total (all 4 sources in parallel)
- **Match generation**: ~5 seconds per 1000 new CVEs
- **Dashboard load**: ~100ms (cached KPI queries)
- **SBOM inventory**: No practical limit; tested with 10k+ items

---

## Related Projects

- **NVD**: NIST vulnerability database (primary data source)
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **OSV**: Open source vulnerability database
- **SOCops**: Wazuh alert triage (complements SBOMguard for runtime detections)
- **socint**: Threat intelligence platform (could integrate SBOMguard feeds)
