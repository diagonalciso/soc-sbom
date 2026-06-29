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

    # CPE list + fix versions
    cpe_list     = []
    fix_versions = []   # [{vendor, product, fix_version}]
    for config in item.get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue
                criteria = cpe_match.get("criteria", "")
                cpe_list.append(criteria)
                fix = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")
                if fix:
                    parts = criteria.split(":")
                    fix_versions.append({
                        "vendor":      parts[3].replace("_", " ") if len(parts) > 3 else "",
                        "product":     parts[4].replace("_", " ") if len(parts) > 4 else "",
                        "fix_version": fix,
                        "exclusive":   bool(cpe_match.get("versionEndExcluding")),
                    })

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
        "cve_id":       cve_id,
        "description":  desc,
        "cvss_score":   cvss_score,
        "cvss_version": cvss_version,
        "severity":     severity.upper(),
        "published":    published,
        "modified":     modified,
        "source":       "nvd",
        "cpe_list":     cpe_list,
        "products":     unique_products,
        "fix_versions": fix_versions,
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


def _versioned_purl(purl, version):
    """Return purl with version embedded. OSV uses this for version-aware matching.
    If purl already contains '@', leave it as-is (version already set).
    """
    if not purl:
        return purl
    if "@" in purl:
        return purl          # version already in purl
    if version:
        return f"{purl}@{version}"
    return purl


def fetch_osv():
    """Query OSV for SBOM items that have a purl set. Covers GHSA and 20+ ecosystems.
    Includes version in purl so OSV only returns CVEs affecting that specific version.
    Items without a version get all CVEs for the package (conservative fallback).
    """
    items = db.get_sbom_items_with_purl()
    if not items:
        print("[osv] no SBOM items with purl — skipping")
        return 0

    print(f"[osv] querying {len(items)} items with purl")

    # Build batch query — include version so OSV scopes results to that version
    queries = [{"package": {"purl": _versioned_purl(item["purl"], item.get("version", ""))}} for item in items]
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

            # Direct match — OSV confirmed this purl+version is affected
            vpurl = _versioned_purl(item["purl"], item.get("version", ""))
            if db.add_match(item["id"], cve_id, f"OSV purl match: {vpurl}"):
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


def _word_in(needle, haystack):
    """Whole-word containment: needle appears in haystack on word boundaries.
    Inputs are already _normalize()d (space-separated tokens, lowercased).
    Avoids substring collisions like 'ed' inside 'fedora'."""
    return f" {needle} " in f" {haystack} "


def _matches_sbom_item(item, cve_products, cve_cpe_list):
    """Return (matched, reason) for a SBOM item against a CVE's product/CPE data.

    Matching is deliberately conservative to avoid false positives. The old
    logic used raw substring containment in both directions, so a 2-char item
    like 'ed' matched every CVE whose product contained 'ed' (fedora, edge,
    advanced, ...). Rules now:
      - CPE substring match wins (most precise).
      - Product name must match on WHOLE-WORD boundaries, not raw substring.
      - Fuzzy (one phrase contained in the other) requires both names >= 4 chars
        AND a vendor match.
      - Exact name equality of length >= 4 is accepted on its own.
      - Short exact names (< 4 chars) are accepted only when the item has no
        vendor set, or its vendor matches — too ambiguous otherwise.
    Version-range / patched-vs-affected verdict is computed separately in the UI
    from the CVE fix_versions, so this stage only establishes product identity.
    """

    # 1. CPE exact match (most precise)
    if item.get("cpe"):
        item_cpe = item["cpe"].lower()
        for cpe in cve_cpe_list:
            if item_cpe in cpe.lower():
                return True, f"CPE match: {item_cpe}"

    # 2. Vendor + product name match (word-boundary aware)
    item_name   = _normalize(item["name"])
    item_vendor = _normalize(item.get("vendor", ""))
    if not item_name:
        return False, ""

    for p in cve_products:
        prod   = _normalize(p.get("product", ""))
        vendor = _normalize(p.get("vendor", ""))
        if not prod:
            continue

        exact = prod == item_name
        fuzzy = (
            not exact
            and len(item_name) >= 4 and len(prod) >= 4
            and (_word_in(item_name, prod) or _word_in(prod, item_name))
        )
        if not (exact or fuzzy):
            continue

        vendor_match = bool(item_vendor) and bool(vendor) and (
            vendor == item_vendor
            or _word_in(vendor, item_vendor)
            or _word_in(item_vendor, vendor)
        )

        if exact and len(item_name) >= 4:
            ok = True                       # strong: full product name, >=4 chars
        elif exact:
            ok = (not item_vendor) or vendor_match   # short exact: block only on vendor conflict
        else:
            ok = vendor_match               # fuzzy: must be corroborated by vendor

        if ok:
            return True, f"Product match: {p.get('vendor','')} / {p.get('product','')}"

    return False, ""


def _cpe_token(s):
    """Normalize a vendor/product string to a CPE 2.3 component token.
    Lowercase, collapse non-alphanumerics to '_', strip edge underscores.
    'HTTP Server' -> 'http_server', 'Apache Software Foundation' -> 'apache_software_foundation'."""
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


def _build_cpe_dictionary(conn_cves):
    """From the CVE corpus, build product_token -> set(vendor_token) seen in real CPE criteria.
    This is the authoritative dictionary we validate backfilled CPEs against, so we never
    invent a vendor/product pair that no CVE actually uses."""
    prod_to_vendors = {}
    for row in conn_cves:
        for cpe in json.loads(row["cpe_list"] or "[]"):
            parts = cpe.split(":")
            if len(parts) < 5:
                continue
            vendor, product = parts[3].lower(), parts[4].lower()
            if not vendor or not product or vendor == "*" or product == "*":
                continue
            prod_to_vendors.setdefault(product, set()).add(vendor)
    return prod_to_vendors


def backfill_cpes():
    """Derive a CPE for active SBOM items that lack one, but ONLY when the
    (vendor, product) pair is corroborated by real CVE CPE data. This lets the
    precise CPE-match path fire for commercial software and disambiguates
    products whose bare name is shared across vendors (e.g. cvs/cvs vs distrotech/cvs).
    Conservative: writes nothing when the product is unknown or the vendor is ambiguous."""
    items = db.get_sbom_items(active_only=True)
    if not items:
        return 0
    conn_cves = db._get_conn().execute("SELECT cpe_list FROM cves").fetchall()
    prod_to_vendors = _build_cpe_dictionary(conn_cves)

    filled = 0
    for item in items:
        if (item["cpe"] or "").strip():
            continue
        prod_tok = _cpe_token(item["name"])
        vendors = prod_to_vendors.get(prod_tok)
        if not prod_tok or not vendors:
            continue  # product not in CVE CPE dictionary — leave to name matching

        vendor_tok = _cpe_token(item.get("vendor", ""))
        chosen = None
        if vendor_tok and vendor_tok in vendors:
            chosen = vendor_tok                           # exact vendor token match
        elif vendor_tok:
            # word-overlap against authoritative vendors (e.g. 'apache software foundation' ~ 'apache')
            cand = [v for v in vendors
                    if _word_in(v.replace("_", " "), vendor_tok.replace("_", " "))
                    or _word_in(vendor_tok.replace("_", " "), v.replace("_", " "))]
            if len(cand) == 1:
                chosen = cand[0]
        if chosen is None and len(vendors) == 1:
            chosen = next(iter(vendors))                  # unambiguous: single known vendor

        if chosen:
            db.set_item_cpe(item["id"], f"cpe:2.3:a:{chosen}:{prod_tok}")
            filled += 1

    print(f"[backfill] set CPE on {filled} SBOM items")
    return filled


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


def enrich_cve_scores(limit=100, matched_only=False):
    """Fetch CVSS scores from NVD for CVEs currently stored with score=0.0.
    Runs matched CVEs first. Uses a per-request delay to respect NVD rate limits.
    """
    cve_ids = db.get_cves_needing_enrichment(limit=limit, matched_only=matched_only)
    if not cve_ids:
        print("[enrich] no CVEs need score enrichment")
        return 0

    print(f"[enrich] fetching scores for {len(cve_ids)} CVEs from NVD")
    delay  = 1 if NVD_API_KEY else 6   # NVD: 50/30s with key, 5/30s without
    updated = 0

    for cve_id in cve_ids:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            data  = _get(url, headers=_nvd_headers(), timeout=30)
            items = data.get("vulnerabilities", [])
            if not items:
                time.sleep(delay)
                continue
            parsed = _parse_nvd_item(items[0])
            if parsed["cvss_score"] > 0 or parsed["fix_versions"]:
                db.update_cve_score(
                    cve_id,
                    parsed["cvss_score"],
                    parsed["cvss_version"],
                    parsed["severity"],
                    parsed["cpe_list"],
                    parsed["products"],
                    parsed["modified"],
                    parsed["fix_versions"],
                )
                updated += 1
        except Exception as e:
            print(f"[enrich] {cve_id}: {e}")
        time.sleep(delay)

    print(f"[enrich] updated scores for {updated} CVEs")
    return updated


def enrich_fix_versions(limit=100):
    """Fetch NVD version range data for CVEs that have scores but no fix_versions yet."""
    cve_ids = db.get_cves_needing_fix_versions(limit=limit)
    if not cve_ids:
        print("[fix-ver] all CVEs already have version range data")
        return 0

    print(f"[fix-ver] fetching version ranges for {len(cve_ids)} CVEs")
    delay   = 1 if NVD_API_KEY else 6
    updated = 0

    for cve_id in cve_ids:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            data   = _get(url, headers=_nvd_headers(), timeout=30)
            items  = data.get("vulnerabilities", [])
            if not items:
                time.sleep(delay)
                continue
            parsed = _parse_nvd_item(items[0])
            db.update_cve_score(
                cve_id,
                parsed["cvss_score"] or db.get_cve(cve_id)["cvss_score"],
                parsed["cvss_version"] or db.get_cve(cve_id)["cvss_version"],
                parsed["severity"]    or db.get_cve(cve_id)["severity"],
                parsed["cpe_list"],
                parsed["products"],
                parsed["modified"],
                parsed["fix_versions"],
            )
            updated += 1
        except Exception as e:
            print(f"[fix-ver] {cve_id}: {e}")
        time.sleep(delay)

    print(f"[fix-ver] updated version ranges for {updated} CVEs")
    return updated


def run_all():
    """Full feed run: NVD → KEV → EPSS → OSV → enrich → fix versions → matcher."""
    fetch_nvd(since_days=2)
    fetch_kev()
    fetch_epss()
    fetch_osv()
    enrich_cve_scores(limit=100)
    enrich_fix_versions(limit=100)
    backfill_cpes()
    run_matcher()
    purged = db.purge_unmatched_cves()
    if purged:
        print(f"[feeds] purged {purged} CVEs with no SBOM matches")
    db.set_setting("last_feed_run", _now_iso())
