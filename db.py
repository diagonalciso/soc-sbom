#!/usr/bin/env python3
"""
SBOMguard — SQLite database layer.
"""

import json
import os
import sqlite3
import threading

DB_PATH = os.environ.get("SBOMGUARD_DB", os.path.join(os.path.dirname(__file__), "sbomguard.db"))
_local = threading.local()


def _get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def _migrate(conn):
    """Add columns introduced after initial schema creation."""
    sbom_cols = {r[1] for r in conn.execute("PRAGMA table_info(sbom_items)").fetchall()}
    if "verified_at" not in sbom_cols:
        conn.execute("ALTER TABLE sbom_items ADD COLUMN verified_at TEXT")
        conn.commit()

    cve_cols = {r[1] for r in conn.execute("PRAGMA table_info(cves)").fetchall()}
    if "epss" not in cve_cols:
        conn.execute("ALTER TABLE cves ADD COLUMN epss REAL NOT NULL DEFAULT 0.0")
        conn.commit()
    if "epss_percentile" not in cve_cols:
        conn.execute("ALTER TABLE cves ADD COLUMN epss_percentile REAL NOT NULL DEFAULT 0.0")
        conn.commit()

    if "purl" not in sbom_cols:
        conn.execute("ALTER TABLE sbom_items ADD COLUMN purl TEXT NOT NULL DEFAULT ''")
        conn.commit()

    if "host" not in sbom_cols:
        conn.execute("ALTER TABLE sbom_items ADD COLUMN host TEXT NOT NULL DEFAULT ''")
        conn.commit()


def init_db():
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sbom_items (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                vendor      TEXT NOT NULL DEFAULT '',
                version     TEXT NOT NULL DEFAULT '',
                item_type   TEXT NOT NULL DEFAULT 'application',
                cpe         TEXT NOT NULL DEFAULT '',
                notes       TEXT NOT NULL DEFAULT '',
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                verified_at TEXT
            );

            CREATE TABLE IF NOT EXISTS cves (
                cve_id      TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                cvss_score  REAL NOT NULL DEFAULT 0.0,
                cvss_version TEXT NOT NULL DEFAULT '',
                severity    TEXT NOT NULL DEFAULT '',
                published   TEXT NOT NULL DEFAULT '',
                modified    TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'nvd',
                kev         INTEGER NOT NULL DEFAULT 0,
                cpe_list    TEXT NOT NULL DEFAULT '[]',
                products    TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS matches (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sbom_item_id    INTEGER NOT NULL REFERENCES sbom_items(id) ON DELETE CASCADE,
                cve_id          TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
                match_reason    TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'new',
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(sbom_item_id, cve_id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_matches_status   ON matches(status);
            CREATE INDEX IF NOT EXISTS idx_matches_sbom     ON matches(sbom_item_id);
            CREATE INDEX IF NOT EXISTS idx_cves_score       ON cves(cvss_score DESC);
            CREATE INDEX IF NOT EXISTS idx_cves_kev         ON cves(kev);
        """)
        conn.commit()
    _migrate(_get_conn())


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def get_setting(key, default=None):
    row = _get_conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    with _get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))
        conn.commit()


# ---------------------------------------------------------------------------
# SBOM items
# ---------------------------------------------------------------------------

def get_sbom_items(active_only=False, host=None):
    conditions = []
    params = []
    if active_only:
        conditions.append("active=1")
    if host:
        conditions.append("host=?")
        params.append(host)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    q = f"SELECT * FROM sbom_items {where} ORDER BY host, vendor, name"
    return [dict(r) for r in _get_conn().execute(q, params).fetchall()]


def get_sbom_item(item_id):
    row = _get_conn().execute("SELECT * FROM sbom_items WHERE id=?", (item_id,)).fetchone()
    return dict(row) if row else None


def add_sbom_item(name, vendor, version, item_type, cpe, purl, host, notes):
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO sbom_items (name, vendor, version, item_type, cpe, purl, host, notes) VALUES (?,?,?,?,?,?,?,?)",
            (name.strip(), vendor.strip(), version.strip(), item_type.strip(), cpe.strip(), purl.strip(), host.strip(), notes.strip())
        )
        conn.commit()
        return cur.lastrowid


def update_sbom_item(item_id, name, vendor, version, item_type, cpe, purl, host, notes):
    with _get_conn() as conn:
        conn.execute(
            "UPDATE sbom_items SET name=?, vendor=?, version=?, item_type=?, cpe=?, purl=?, host=?, notes=?, updated_at=datetime('now') WHERE id=?",
            (name.strip(), vendor.strip(), version.strip(), item_type.strip(), cpe.strip(), purl.strip(), host.strip(), notes.strip(), item_id)
        )
        conn.commit()


def get_sbom_items_with_purl():
    rows = _get_conn().execute(
        "SELECT * FROM sbom_items WHERE active=1 AND purl != '' ORDER BY vendor, name"
    ).fetchall()
    return [dict(r) for r in rows]


def get_hosts():
    """Return distinct non-empty host values."""
    rows = _get_conn().execute(
        "SELECT DISTINCT host FROM sbom_items WHERE host != '' ORDER BY host"
    ).fetchall()
    return [r[0] for r in rows]


def delete_sbom_item(item_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM sbom_items WHERE id=?", (item_id,))
        conn.commit()


def toggle_sbom_item(item_id, active):
    with _get_conn() as conn:
        conn.execute("UPDATE sbom_items SET active=?, updated_at=datetime('now') WHERE id=?", (1 if active else 0, item_id))
        conn.commit()


def verify_sbom_item(item_id):
    with _get_conn() as conn:
        conn.execute("UPDATE sbom_items SET verified_at=datetime('now') WHERE id=?", (item_id,))
        conn.commit()


def verify_all_sbom_items():
    with _get_conn() as conn:
        conn.execute("UPDATE sbom_items SET verified_at=datetime('now')")
        conn.commit()


def update_epss_scores(scores: dict):
    """Bulk-update EPSS scores for CVEs already in the DB.
    scores: {cve_id: (epss_score, epss_percentile)}
    """
    with _get_conn() as conn:
        conn.executemany(
            "UPDATE cves SET epss=?, epss_percentile=? WHERE cve_id=?",
            [(epss, pct, cve_id) for cve_id, (epss, pct) in scores.items()]
        )
        conn.commit()


# ---------------------------------------------------------------------------
# CVEs
# ---------------------------------------------------------------------------

def upsert_cve(cve_id, description, cvss_score, cvss_version, severity, published, modified, source, kev, cpe_list, products):
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO cves (cve_id, description, cvss_score, cvss_version, severity, published, modified, source, kev, cpe_list, products)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_version=excluded.cvss_version,
                severity=excluded.severity,
                modified=excluded.modified,
                kev=MAX(kev, excluded.kev),
                cpe_list=excluded.cpe_list,
                products=excluded.products
        """, (cve_id, description, cvss_score, cvss_version, severity, published, modified, source,
              1 if kev else 0, json.dumps(cpe_list), json.dumps(products)))
        conn.commit()


def get_cves(min_score=0.0, kev_only=False, limit=200):
    conditions = ["cvss_score >= ?"]
    params = [min_score]
    if kev_only:
        conditions.append("kev=1")
    where = "WHERE " + " AND ".join(conditions)
    rows = _get_conn().execute(
        f"SELECT * FROM cves {where} ORDER BY kev DESC, cvss_score DESC LIMIT ?",
        (*params, limit)
    ).fetchall()
    return [dict(r) for r in rows]


def get_cve(cve_id):
    row = _get_conn().execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Matches
# ---------------------------------------------------------------------------

def add_match(sbom_item_id, cve_id, match_reason):
    with _get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO matches (sbom_item_id, cve_id, match_reason) VALUES (?,?,?)",
                (sbom_item_id, cve_id, match_reason)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # already exists


def get_matches(status=None, limit=300):
    conditions = []
    params = []
    if status and status != "all":
        conditions.append("m.status=?")
        params.append(status)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = _get_conn().execute(f"""
        SELECT m.*, s.name as item_name, s.vendor as item_vendor, s.version as item_version,
               s.item_type, s.host as item_host, c.cvss_score, c.severity, c.description as cve_description,
               c.kev, c.published, c.epss, c.epss_percentile
        FROM matches m
        JOIN sbom_items s ON m.sbom_item_id = s.id
        JOIN cves c ON m.cve_id = c.cve_id
        {where}
        ORDER BY c.kev DESC, c.cvss_score DESC, m.created_at DESC
        LIMIT ?
    """, (*params, limit)).fetchall()
    return [dict(r) for r in rows]


def update_match_status(match_id, status):
    with _get_conn() as conn:
        conn.execute(
            "UPDATE matches SET status=?, updated_at=datetime('now') WHERE id=?",
            (status, match_id)
        )
        conn.commit()


def get_stats():
    conn = _get_conn()
    total_sbom    = conn.execute("SELECT COUNT(*) FROM sbom_items WHERE active=1").fetchone()[0]
    total_cves    = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    new_matches   = conn.execute("SELECT COUNT(*) FROM matches WHERE status='new'").fetchone()[0]
    kev_matches   = conn.execute("SELECT COUNT(*) FROM matches m JOIN cves c ON m.cve_id=c.cve_id WHERE m.status='new' AND c.kev=1").fetchone()[0]
    critical      = conn.execute("SELECT COUNT(*) FROM matches m JOIN cves c ON m.cve_id=c.cve_id WHERE m.status='new' AND c.cvss_score>=9.0").fetchone()[0]
    return {
        "total_sbom":   total_sbom,
        "total_cves":   total_cves,
        "new_matches":  new_matches,
        "kev_matches":  kev_matches,
        "critical":     critical,
    }
