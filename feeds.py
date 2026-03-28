#!/usr/bin/env python3
"""
SBOMguard — CVE feed fetchers and SBOM matcher.

Sources:
  - NVD CVE API v2  (CVSS >= threshold, incremental by lastModStartDate)
  - CISA KEV        (full list, daily)
"""

import csv
import gzip
import io
import json
import os
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

import db

CVSS_THRESHOLD = float(os.environ.get("CVSS_THRESHOLD", "7.8"))
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")   # optional — increases rate limit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NVD CVE API v2
# ---------------------------------------------------------------------------

def _nvd_headers():
    h = {"User-Agent": "SBOMguard/1.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _parse_nvd_item(item):
    cve_id = item.get("cve", {}).get("id", "")
    descriptions = item.get("cve", {}).get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # CVSS score — prefer v3.1, fall back to v3.0, then v2
    metrics = item.get("cve", {}).get("metrics", {})
    cvss_score, cvss_version, severity = 0.0, "", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score   = float(cvss_data.get("baseScore", 0.0))
            cvss_version = cvss_data.get("version", key[-3:])
            severity     = cvss_data.get("baseSeverity", m.get("baseSeverity", ""))
            break

    published = item.get("cve", {}).get("published", "")
    modified  = item.get("cve", {}).get("lastModified", "")

    # CPE list
    cpe_list = []
    for config in item.get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpe_list.append(cpe_match.get("criteria", ""))

    # Affected products: extract vendor+product from CPEs
    products = []
    for cpe in cpe_list:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor  = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            if vendor and product and vendor != "*" and product != "*":
                products.append({"vendor": vendor, "product": product})

    # Deduplicate products
    seen = set()
    unique_products = []
    for p in products:
        key = (p["vendor"], p["product"])
        if key not in seen:
            seen.add(key)
            unique_products.append(p)

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "severity": severity.upper(),
        "published": published,
        "modified": modified,
        "source": "nvd",
        "cpe_list": cpe_list,
        "products": unique_products,
    }


def fetch_nvd(since_days=1):
    """Fetch NVD CVEs modified in the last `since_days` days with CVSS >= threshold."""
    last_run = db.get_setting("nvd_last_run")
    if last_run:
        start = last_run
    else:
        start = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000")

    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    print(f"[nvd] fetching modified {start} → {end}")
    start_index = 0
    total_saved = 0

    while True:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?lastModStartDate={start}&lastModEndDate={end}"
            f"&startIndex={start_index}&resultsPerPage=200"
        )
        try:
            data = _get(url, headers=_nvd_headers(), timeout=60)
        except Exception as e:
            print(f"[nvd] fetch error: {e}")
            break

        items = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        for item in items:
            parsed = _parse_nvd_item(item)
            if parsed["cvss_score"] >= CVSS_THRESHOLD:
                db.upsert_cve(**parsed, kev=False)
                total_saved += 1

        start_index += len(items)
        if start_index >= total_results or not items:
            break

        # NVD rate limit: 5 req/30s without key, 50 req/30s with key
        time.sleep(1 if NVD_API_KEY else 6)

    db.set_setting("nvd_last_run", end)
    print(f"[nvd] saved {total_saved} CVEs (score >= {CVSS_THRESHOLD})")
    return total_saved


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def fetch_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog and mark matching CVEs."""
    print("[kev] fetching CISA KEV catalog")
    try:
        data = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    except Exception as e:
        print(f"[kev] fetch error: {e}")
        return 0

    vulns = data.get("vulnerabilities", [])
    marked = 0
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue

        # If we already have it, just mark kev=1
        existing = db.get_cve(cve_id)
        if existing:
            db.upsert_cve(
                cve_id       = existing["cve_id"],
                description  = existing["description"],
                cvss_score   = existing["cvss_score"],
                cvss_version = existing["cvss_version"],
                severity     = existing["severity"],
                published    = existing["published"],
                modified     = existing["modified"],
                source       = existing["source"],
                kev          = True,
                cpe_list     = json.loads(existing["cpe_list"]),
                products     = json.loads(existing["products"]),
            )
        else:
            # Store KEV entry even if below CVSS threshold — it's actively exploited
            db.upsert_cve(
                cve_id       = cve_id,
                description  = v.get("shortDescription", ""),
                cvss_score   = 0.0,  # will be updated on next NVD run
                cvss_version = "",
                severity     = "",
                published    = v.get("dateAdded", ""),
                modified     = v.get("dateAdded", ""),
                source       = "kev",
                kev          = True,
                cpe_list     = [],
                products     = [{"vendor": v.get("vendorProject", "").lower(),
                                 "product": v.get("product", "").lower()}],
            )
        marked += 1

    db.set_setting("kev_last_run", _now_iso())
    print(f"[kev] processed {marked} KEV entries")
    return marked


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

def fetch_epss():
    """Download FIRST.org EPSS daily CSV and update scores for CVEs in our DB."""
    print("[epss] fetching EPSS scores from FIRST.org")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SBOMguard/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            compressed = resp.read()
    except Exception as e:
        print(f"[epss] fetch error: {e}")
        return 0

    try:
        raw = gzip.decompress(compressed).decode("utf-8")
    except Exception as e:
        print(f"[epss] decompress error: {e}")
        return 0

    # First line is a comment: #model_version:...,score_date:...
    lines = raw.splitlines()
    data_lines = [l for l in lines if not l.startswith("#")]
    reader = csv.DictReader(data_lines)

    scores = {}
    for row in reader:
        cve_id = row.get("cve", "").strip()
        try:
            epss = float(row.get("epss", 0))
            pct  = float(row.get("percentile", 0))
        except ValueError:
            continue
        if cve_id:
            scores[cve_id] = (epss, pct)

    db.update_epss_scores(scores)
    db.set_setting("epss_last_run", _now_iso())
    print(f"[epss] updated scores for up to {len(scores)} CVEs")
    return len(scores)


# ---------------------------------------------------------------------------
# OSV (osv.dev) — covers GHSA, PyPI, npm, Maven, Go, Cargo, NuGet, distros
# ---------------------------------------------------------------------------

def _osv_cvss(vuln):
    """Extract a numeric CVSS score from an OSV vulnerability object."""
    for sev in vuln.get("severity", []):
        vector = sev.get("score", "")
        # Try database_specific first (some sources include numeric score)
        ds = vuln.get("database_specific", {})
        if "cvss" in ds:
            try:
                return float(ds["cvss"])
            except (TypeError, ValueError):
                pass
        # Parse base score from CVSS vector string: last segment after "/"
        # e.g. CVSS:3.1/AV:N/AC:L/.../E:P/RL:O/RC:C -> not in base, but
        # base score is embedded in some NVD-sourced OSV entries as
        # database_specific.nvd_published_at or similar — skip deep parsing,
        # return 0 and let NVD enrich later.
    return 0.0


def _osv_post(url, payload, timeout=30):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "User-Agent":   "SBOMguard/1.0",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def fetch_osv():
    """Query OSV for SBOM items that have a purl set. Covers GHSA and 20+ ecosystems."""
    items = db.get_sbom_items_with_purl()
    if not items:
        print("[osv] no SBOM items with purl — skipping")
        return 0

    print(f"[osv] querying {len(items)} items with purl")

    # Build batch query — OSV supports up to 1000 queries per batch
    queries = [{"package": {"purl": item["purl"]}} for item in items]
    try:
        resp = _osv_post("https://api.osv.dev/v1/querybatch", {"queries": queries})
    except Exception as e:
        print(f"[osv] fetch error: {e}")
        return 0

    results   = resp.get("results", [])
    new_vulns = 0
    new_matches = 0

    for item, result in zip(items, results):
        for vuln in result.get("vulns", []):
            # Extract CVE ID from aliases (prefer CVE-* over GHSA-*)
            aliases = vuln.get("aliases", []) + [vuln.get("id", "")]
            cve_id  = next((a for a in aliases if a.startswith("CVE-")), None)
            if not cve_id:
                cve_id = vuln.get("id", "")  # use OSV/GHSA ID if no CVE alias
            if not cve_id:
                continue

            # Upsert CVE (only if not already present with better data)
            existing = db.get_cve(cve_id)
            if not existing:
                db.upsert_cve(
                    cve_id       = cve_id,
                    description  = vuln.get("summary", vuln.get("details", ""))[:500],
                    cvss_score   = _osv_cvss(vuln),
                    cvss_version = "",
                    severity     = "",
                    published    = vuln.get("published", ""),
                    modified     = vuln.get("modified", ""),
                    source       = "osv",
                    kev          = False,
                    cpe_list     = [],
                    products     = [],
                )
                new_vulns += 1

            # Direct match — OSV confirmed this purl is affected
            if db.add_match(item["id"], cve_id, f"OSV purl match: {item['purl']}"):
                new_matches += 1

    db.set_setting("osv_last_run", _now_iso())
    print(f"[osv] {new_vulns} new CVEs, {new_matches} new matches")
    return new_matches


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

def _normalize(s):
    """Lowercase, strip version numbers and punctuation for fuzzy matching."""
    s = s.lower().strip()
    s = re.sub(r"[\s\-_]+", " ", s)
    return s


def _matches_sbom_item(item, cve_products, cve_cpe_list):
    """Return (matched, reason) for a SBOM item against a CVE's product/CPE data."""

    # 1. CPE exact match (most precise)
    if item.get("cpe"):
        item_cpe = item["cpe"].lower()
        for cpe in cve_cpe_list:
            if item_cpe in cpe.lower():
                return True, f"CPE match: {item_cpe}"

    # 2. Vendor + product fuzzy match
    item_name   = _normalize(item["name"])
    item_vendor = _normalize(item.get("vendor", ""))

    for p in cve_products:
        prod   = _normalize(p.get("product", ""))
        vendor = _normalize(p.get("vendor", ""))

        # product name contained in item name or vice versa
        name_hit = prod and (prod in item_name or item_name in prod)
        # vendor match (if item has vendor set)
        vendor_hit = (not item_vendor) or (vendor and (vendor in item_vendor or item_vendor in vendor))

        if name_hit and vendor_hit:
            return True, f"Product match: {p.get('vendor','')} / {p.get('product','')}"

    return False, ""


def run_matcher():
    """Cross-reference all active SBOM items against all CVEs and record matches."""
    items = db.get_sbom_items(active_only=True)
    if not items:
        return 0

    conn_cves = db._get_conn().execute(
        "SELECT cve_id, cpe_list, products FROM cves"
    ).fetchall()

    new_matches = 0
    for item in items:
        for row in conn_cves:
            cpe_list = json.loads(row["cpe_list"] or "[]")
            products = json.loads(row["products"] or "[]")
            matched, reason = _matches_sbom_item(item, products, cpe_list)
            if matched:
                if db.add_match(item["id"], row["cve_id"], reason):
                    new_matches += 1

    print(f"[matcher] {new_matches} new matches found")
    return new_matches


def run_all():
    """Full feed run: NVD → KEV → EPSS → OSV → matcher."""
    fetch_nvd(since_days=2)
    fetch_kev()
    fetch_epss()
    fetch_osv()
    run_matcher()
    db.set_setting("last_feed_run", _now_iso())
