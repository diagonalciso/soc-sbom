#!/usr/bin/env python3
"""
SBOMguard — SBOM vulnerability monitoring dashboard.
"""

import http.server
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

import db
import feeds

PORT = int(os.environ.get("SBOMGUARD_PORT", "8082"))
FEED_INTERVAL = int(os.environ.get("FEED_INTERVAL", "21600"))  # 6h default


# ---------------------------------------------------------------------------
# Background feed runner
# ---------------------------------------------------------------------------

def _feed_worker():
    print("[feeds] starting — initial run in 10s")
    time.sleep(10)
    while True:
        try:
            feeds.run_all()
        except Exception as e:
            print(f"[feeds] error: {e}")
        time.sleep(FEED_INTERVAL)


# ---------------------------------------------------------------------------
# HTTP handler helpers
# ---------------------------------------------------------------------------

def _params(path):
    if "?" in path:
        path, qs = path.split("?", 1)
        p = {}
        for part in qs.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                p[k] = v
        return path, p
    return path, {}


def _parse_sbom(data, host):
    """Parse CycloneDX JSON, SPDX JSON, or a plain list into SBOM item dicts."""
    items = []

    # --- CycloneDX ---
    if isinstance(data, dict) and (data.get("bomFormat") == "CycloneDX" or "components" in data):
        def _walk(components):
            for c in components or []:
                vendor = ""
                for key in ("supplier", "manufacturer", "publisher"):
                    v = c.get(key)
                    if isinstance(v, dict):
                        vendor = v.get("name", "")
                    elif isinstance(v, str):
                        vendor = v
                    if vendor:
                        break
                items.append({
                    "name":      c.get("name", ""),
                    "vendor":    vendor,
                    "version":   c.get("version", ""),
                    "item_type": c.get("type", "library"),
                    "cpe":       c.get("cpe", ""),
                    "purl":      c.get("purl", ""),
                    "notes":     c.get("description", ""),
                })
                _walk(c.get("components", []))  # nested components
        _walk(data.get("components", []))

    # --- SPDX ---
    elif isinstance(data, dict) and "spdxVersion" in data:
        for pkg in data.get("packages", []):
            purl = ""
            cpe  = ""
            for ref in pkg.get("externalRefs", []):
                rt = ref.get("referenceType", "")
                rl = ref.get("referenceLocator", "")
                if rt == "purl":
                    purl = rl
                elif "cpe" in rt.lower():
                    cpe = rl
            supplier = pkg.get("supplier", "")
            for prefix in ("Organization:", "Person:", "Tool:"):
                if supplier.startswith(prefix):
                    supplier = supplier[len(prefix):].strip()
                    break
            items.append({
                "name":      pkg.get("name", ""),
                "vendor":    supplier,
                "version":   pkg.get("versionInfo", ""),
                "item_type": "library",
                "cpe":       cpe,
                "purl":      purl,
                "notes":     pkg.get("comment", ""),
            })

    # --- plain list [{name, version, ...}] ---
    elif isinstance(data, list):
        for c in data:
            if not isinstance(c, dict):
                continue
            items.append({
                "name":      c.get("name", c.get("product", "")),
                "vendor":    c.get("vendor", c.get("supplier", c.get("manufacturer", ""))),
                "version":   c.get("version", ""),
                "item_type": c.get("type", c.get("item_type", "library")),
                "cpe":       c.get("cpe", ""),
                "purl":      c.get("purl", ""),
                "notes":     c.get("notes", c.get("description", "")),
            })

    return items


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(b))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, default=str), "application/json")

    def do_GET(self):
        path, params = _params(self.path)

        if path == "/":
            self._send(200, _page_dashboard())
        elif path == "/sbom":
            self._send(200, _page_sbom())
        elif path == "/cves":
            self._send(200, _page_cves())
        elif path == "/matches":
            self._send(200, _page_matches())

        elif path == "/api/stats":
            self._json(200, db.get_stats())

        elif path == "/api/sbom":
            host_filter = params.get("host", "")
            self._json(200, db.get_sbom_items(host=host_filter))

        elif path == "/api/hosts":
            self._json(200, db.get_hosts())

        elif path == "/api/hosts/delete":
            name = params.get("name", "")
            if name:
                db.delete_host(name)
            self._json(200, {"ok": True})

        elif path == "/api/cves":
            min_score = float(params.get("min_score", "0"))
            kev_only  = params.get("kev") == "1"
            self._json(200, db.get_cves(min_score=min_score, kev_only=kev_only))

        elif path == "/api/matches":
            status = params.get("status", "all")
            self._json(200, db.get_matches(status=status))

        elif path == "/api/feed-status":
            self._json(200, {
                "last_feed_run": db.get_setting("last_feed_run", "never"),
                "nvd_last_run":  db.get_setting("nvd_last_run",  "never"),
                "kev_last_run":  db.get_setting("kev_last_run",  "never"),
                "epss_last_run": db.get_setting("epss_last_run", "never"),
                "osv_last_run":  db.get_setting("osv_last_run",  "never"),
            })

        else:
            self._send(404, "Not found")

    def do_POST(self):
        path, _ = _params(self.path)
        length  = int(self.headers.get("Content-Length", 0))
        body    = json.loads(self.rfile.read(length) or b"{}") if length else {}

        if path == "/api/sbom":
            item_id = db.add_sbom_item(
                body.get("name", ""),
                body.get("vendor", ""),
                body.get("version", ""),
                body.get("item_type", "application"),
                body.get("cpe", ""),
                body.get("purl", ""),
                body.get("host", ""),
                body.get("notes", ""),
            )
            feeds.run_matcher()
            self._json(201, {"id": item_id})

        elif re.match(r"^/api/sbom/\d+$", path):
            item_id = int(path.split("/")[-1])
            db.update_sbom_item(
                item_id,
                body.get("name", ""),
                body.get("vendor", ""),
                body.get("version", ""),
                body.get("item_type", "application"),
                body.get("cpe", ""),
                body.get("purl", ""),
                body.get("host", ""),
                body.get("notes", ""),
            )
            feeds.run_matcher()
            self._json(200, {"ok": True})

        elif re.match(r"^/api/matches/\d+/action$", path):
            match_id = int(path.split("/")[-2])
            action   = body.get("action", "")
            if action in ("ack", "fp", "reopen"):
                status = "new" if action == "reopen" else action
                db.update_match_status(match_id, status)
                self._json(200, {"ok": True})
            else:
                self._json(400, {"error": "invalid action"})

        elif re.match(r"^/api/sbom/\d+/fp-all$", path):
            item_id = int(path.split("/")[-2])
            n = db.bulk_update_matches_for_item(item_id, "new", "fp")
            self._json(200, {"marked": n})

        elif path == "/api/hosts":
            name = body.get("name", "").strip()
            if name:
                db.add_host(name)
            self._json(200, {"ok": True})

        elif path == "/api/sbom/verify-all":
            db.verify_all_sbom_items()
            self._json(200, {"ok": True})

        elif re.match(r"^/api/sbom/\d+/verify$", path):
            item_id = int(path.split("/")[-2])
            db.verify_sbom_item(item_id)
            self._json(200, {"ok": True})

        elif path == "/api/sbom/import":
            host     = body.get("host", "").strip()
            sbom     = body.get("sbom", {})
            filepath = body.get("file", "").strip()
            if filepath:
                # Validate the user-provided path to prevent directory traversal / arbitrary file access.
                # Only allow non-absolute, normalized paths that do not traverse upwards.
                if os.path.isabs(filepath):
                    self._json(400, {"error": "Absolute paths are not allowed"}); return
                normalized = os.path.normpath(filepath)
                if normalized.startswith("..") or "/.." in normalized or "\\.." in normalized:
                    self._json(400, {"error": "Path traversal is not allowed"}); return
                try:
                    with open(normalized, "r", encoding="utf-8") as f:
                        sbom = json.load(f)
                except FileNotFoundError:
                    self._json(404, {"error": f"File not found: {normalized}"}); return
                except Exception as e:
                    self._json(400, {"error": str(e)}); return
            items    = _parse_sbom(sbom, host)
            imported = 0
            for it in items:
                if not it.get("name"):
                    continue
                db.add_sbom_item(
                    it["name"], it["vendor"], it["version"],
                    it["item_type"], it["cpe"], it["purl"], host, it["notes"]
                )
                imported += 1
            if host:
                db.add_host(host)
            threading.Thread(target=feeds.run_matcher, daemon=True).start()
            self._json(200, {"imported": imported})

        elif path == "/api/feed/run":
            threading.Thread(target=feeds.run_all, daemon=True).start()
            self._json(200, {"ok": True})

        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self):
        path, _ = _params(self.path)

        if re.match(r"^/api/sbom/\d+$", path):
            item_id = int(path.split("/")[-1])
            db.delete_sbom_item(item_id)
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Common CSS / nav
# ---------------------------------------------------------------------------

CSS = """
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--yellow:#d29922;--orange:#f0883e;--red:#f85149;
  --critical:#ff4444;--high:#f0883e;--medium:#d29922;--low:#3fb950;
  --purple:#bc8cff;--r:8px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;min-height:100vh;}
header{background:#0d1117;border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;}
.logo{width:32px;height:32px;background:linear-gradient(135deg,#f85149,#f0883e);border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:15px;color:#fff;}
.app-name{font-size:16px;font-weight:700;}
.app-sub{font-size:11px;color:var(--muted);}
nav{display:flex;gap:4px;margin-left:8px;}
nav a{padding:5px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;transition:.15s;}
nav a:hover{background:var(--surface2);color:var(--text);}
nav a.active{background:var(--surface2);color:var(--accent);border:1px solid var(--border);}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:12px;color:var(--muted);}
main{padding:20px 24px;max-width:1400px;margin:0 auto;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px;}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;position:relative;overflow:hidden;}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;}
.kpi.c-red::before{background:var(--red);}.kpi.c-orange::before{background:var(--orange);}
.kpi.c-blue::before{background:var(--accent);}.kpi.c-green::before{background:var(--green);}
.kpi.c-yellow::before{background:var(--yellow);}
.kpi-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:10px;}
.kpi-value{font-size:28px;font-weight:800;line-height:1;}
.kpi-sub{font-size:11px;color:var(--muted);margin-top:6px;}.kpi-sub span{color:var(--text);font-weight:600;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;margin-bottom:16px;}
.card-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:8px 10px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);border-bottom:1px solid var(--border);}
td{padding:9px 10px;border-bottom:1px solid var(--border);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:var(--surface2);}
.badge{display:inline-block;border-radius:4px;padding:2px 7px;font-size:11px;font-weight:700;}
.badge.critical{background:rgba(255,68,68,.15);color:var(--critical);}
.badge.high{background:rgba(240,136,62,.15);color:var(--high);}
.badge.medium{background:rgba(210,153,34,.15);color:var(--medium);}
.badge.low{background:rgba(63,185,80,.15);color:var(--low);}
.badge.kev{background:rgba(248,81,73,.2);color:#ff6b6b;border:1px solid #f8514944;}
.badge.new{background:rgba(88,166,255,.15);color:var(--accent);}
.badge.ack{background:rgba(63,185,80,.15);color:var(--green);}
.badge.fp{background:rgba(139,148,158,.15);color:var(--muted);}
.btn{padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:12px;cursor:pointer;font-weight:600;}
.btn:hover{background:var(--border);}
.btn.primary{background:var(--accent);color:#0d1117;border-color:var(--accent);}
.btn.primary:hover{opacity:.85;}
.btn.danger{background:rgba(248,81,73,.15);color:var(--red);border-color:var(--red);}
.btn.danger:hover{background:rgba(248,81,73,.25);}
.btn.small{padding:3px 9px;font-size:11px;}
input,select,textarea{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 10px;font-size:13px;width:100%;}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);}
.form-row{margin-bottom:12px;}
.form-row label{display:block;font-size:11px;font-weight:600;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px;}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px;}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center;}
.modal-overlay.show{display:flex;}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:24px;width:520px;max-width:95vw;max-height:90vh;overflow-y:auto;}
.modal h2{font-size:15px;font-weight:700;margin-bottom:16px;}
.empty{color:var(--muted);font-size:13px;padding:20px;text-align:center;}
.feed-status{font-size:11px;color:var(--muted);}
.score{font-weight:700;}
.score.critical{color:var(--critical);}
.score.high{color:var(--high);}
.score.medium{color:var(--medium);}
.score.low{color:var(--low);}
.type-badge{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:10px;color:var(--muted);font-weight:600;text-transform:uppercase;}
.cve-link{color:var(--accent);text-decoration:none;font-size:12px;font-weight:600;}
.cve-link:hover{text-decoration:underline;}
"""


def _nav(active):
    links = [("Dashboard", "/"), ("SBOM", "/sbom"), ("CVEs", "/cves"), ("Matches", "/matches")]
    items = "".join(
        f'<a href="{u}" class="{"active" if n == active else ""}">{n}</a>'
        for n, u in links
    )
    return f"""
<header>
  <div class="logo">SG</div>
  <div><div class="app-name">SBOMguard</div><div class="app-sub">Vulnerability Monitor</div></div>
  <nav>{items}</nav>
  <div class="hdr-right">
    <span id="feed-status" class="feed-status">Loading…</span>
    <button class="btn small" onclick="runFeed()" title="Run feed now">↻ Refresh</button>
  </div>
</header>"""


FOOTER = """
<script>
function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML;}
function fmtScore(n){const cls=n>=9?'critical':n>=7?'high':n>=4?'medium':'low';return`<span class="score ${cls}">${n.toFixed(1)}</span>`;}
function fmtEpss(n){if(!n)return'<span style="color:var(--muted)">—</span>';const pct=Math.round(n*100);const cls=n>=0.5?'color:var(--red)':n>=0.2?'color:var(--orange)':'color:var(--muted)';return`<span style="font-weight:700;${cls}">${pct}%</span>`;}

function _parsever(v){
  if(!v)return[];
  return String(v).split(/[.\-_]/).map(p=>{const n=parseInt(p);return isNaN(n)?0:n;});
}
function _vercmp(a,b){
  const av=_parsever(a),bv=_parsever(b);
  const len=Math.max(av.length,bv.length);
  for(let i=0;i<len;i++){const d=(av[i]||0)-(bv[i]||0);if(d!==0)return d;}
  return 0;
}
function fmtVerdict(itemVersion, fixVersionsJson){
  if(!itemVersion)return'<span style="font-size:10px;color:var(--muted)" title="Add version to SBOM item to check">? No version</span>';
  let fixes=[];
  try{fixes=JSON.parse(fixVersionsJson||'[]');}catch(e){}
  if(!fixes.length)return'<span style="font-size:10px;color:var(--muted)" title="NVD has no version range data for this CVE">? Unknown</span>';
  // If installed version >= fix_version on any range → patched
  const patched=fixes.some(f=>f.exclusive?_vercmp(itemVersion,f.fix_version)>=0:_vercmp(itemVersion,f.fix_version)>0);
  const fixStr=fixes.map(f=>f.fix_version).filter((v,i,a)=>a.indexOf(v)===i).join(', ');
  if(patched)return`<span style="font-size:10px;color:var(--green);font-weight:700" title="Fixed in ${fixStr} — your version ${itemVersion} is newer">✓ Patched</span>`;
  return`<span style="font-size:10px;color:var(--red);font-weight:700" title="Fix version: ${fixStr} — your version ${itemVersion}">✗ Affected</span>`;
}
function sevCls(s){return(s||'').toLowerCase();}
function runFeed(){
  fetch('/api/feed/run',{method:'POST'}).then(()=>{
    document.getElementById('feed-status').textContent='Feed running…';
  });
}
function loadFeedStatus(){
  fetch('/api/feed-status').then(r=>r.json()).then(d=>{
    const el=document.getElementById('feed-status');
    if(d.last_feed_run&&d.last_feed_run!=='never'){
      const dt=new Date(d.last_feed_run);
      el.textContent='Last run: '+dt.toLocaleTimeString();
    } else {
      el.textContent='No feed run yet';
    }
  }).catch(()=>{});
}
document.addEventListener('DOMContentLoaded', loadFeedStatus);
</script>
</body></html>"""


def _page_head(title):
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SBOMguard — {title}</title>
<style>{CSS}</style>
</head><body>"""


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

def _page_dashboard():
    return _page_head("Dashboard") + _nav("Dashboard") + """
<main>
  <div class="kpi-grid" id="kpis"><div class="empty">Loading…</div></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <div class="card">
      <div class="card-title">Recent Matches</div>
      <div id="recent-matches"><div class="empty">Loading…</div></div>
    </div>
    <div class="card">
      <div class="card-title">CISA KEV Matches</div>
      <div id="kev-matches"><div class="empty">Loading…</div></div>
    </div>
  </div>
</main>
<script>
function loadDashboard(){
  fetch('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('kpis').innerHTML=`
      <div class="kpi c-blue"><div class="kpi-label">SBOM Items</div><div class="kpi-value">${d.total_sbom}</div></div>
      <div class="kpi c-red"><div class="kpi-label">Open Matches</div><div class="kpi-value">${d.new_matches}</div><div class="kpi-sub">Critical: <span>${d.critical}</span></div></div>
      <div class="kpi c-orange"><div class="kpi-label">KEV Matches</div><div class="kpi-value">${d.kev_matches}</div><div class="kpi-sub">Actively exploited</div></div>
      <div class="kpi c-yellow"><div class="kpi-label">CVEs Tracked</div><div class="kpi-value">${d.total_cves}</div></div>
    `;
  });
  fetch('/api/matches?status=new').then(r=>r.json()).then(rows=>{
    const el=document.getElementById('recent-matches');
    if(!rows.length){el.innerHTML='<div class="empty">No open matches.</div>';return;}
    el.innerHTML=`<table><thead><tr><th>Item</th><th>CVE</th><th>Score</th><th>KEV</th></tr></thead><tbody>`+
      rows.slice(0,10).map(r=>`<tr>
        <td><a href="/matches" style="color:var(--text);text-decoration:none">${esc(r.item_name)}<br><span style="font-size:11px;color:var(--muted)">${esc(r.item_vendor)} ${esc(r.item_version)}</span></td>
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank">${esc(r.cve_id)}</a></td>
        <td>${fmtScore(r.cvss_score)}</td>
        <td>${r.kev?'<span class="badge kev">KEV</span>':''}</td>
      </tr>`).join('')+'</tbody></table>';
  });
  fetch('/api/matches?status=new').then(r=>r.json()).then(rows=>{
    const kev=rows.filter(r=>r.kev);
    const el=document.getElementById('kev-matches');
    if(!kev.length){el.innerHTML='<div class="empty">No KEV matches.</div>';return;}
    el.innerHTML=`<table><thead><tr><th>Item</th><th>CVE</th><th>Score</th></tr></thead><tbody>`+
      kev.map(r=>`<tr>
        <td>${esc(r.item_name)}<br><span style="font-size:11px;color:var(--muted)">${esc(r.item_vendor)}</span></td>
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank">${esc(r.cve_id)}</a></td>
        <td>${fmtScore(r.cvss_score)}</td>
      </tr>`).join('')+'</tbody></table>';
  });
}
document.addEventListener('DOMContentLoaded', loadDashboard);
setInterval(loadDashboard, 60000);
</script>
""" + FOOTER


# ---------------------------------------------------------------------------
# SBOM page
# ---------------------------------------------------------------------------

def _page_sbom():
    return _page_head("SBOM") + _nav("SBOM") + """
<main>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
    <h2 style="font-size:16px;font-weight:700;">Software Bill of Materials</h2>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <select id="host-filter" onchange="loadSBOM()" style="width:auto;font-size:12px;">
        <option value="">All devices</option>
      </select>
      <button class="btn" onclick="verifyAll()">✓ Mark All Up to Date</button>
      <button class="btn" onclick="openImport()">⬆ Import SBOM</button>
      <button class="btn primary" onclick="openAdd()">+ Add Item</button>
    </div>
  </div>

  <div class="card" style="margin-bottom:16px;padding:12px 18px;">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);">Devices</span>
      <div id="host-chips" style="display:flex;flex-wrap:wrap;gap:6px;flex:1;"></div>
      <div style="display:flex;gap:6px;">
        <input id="new-host" placeholder="Add device…" style="width:180px;padding:5px 10px;font-size:12px;" onkeydown="if(event.key==='Enter')addHost()"/>
        <button class="btn small primary" onclick="addHost()">Add</button>
      </div>
    </div>
  </div>

  <datalist id="host-list"></datalist>
  <div class="card">
    <div id="sbom-table"><div class="empty">Loading…</div></div>
  </div>
</main>

<!-- Add/Edit modal -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <h2 id="modal-title">Add SBOM Item</h2>
    <input type="hidden" id="edit-id"/>
    <div class="form-row"><label>Name *</label><input id="f-name" placeholder="e.g. Apache HTTP Server"/></div>
    <div class="form-row"><label>Vendor *</label><input id="f-vendor" placeholder="e.g. Apache Software Foundation"/></div>
    <div class="form-row"><label>Version</label><input id="f-version" placeholder="e.g. 2.4.51"/></div>
    <div class="form-row"><label>Type</label>
      <select id="f-type">
        <option value="application">Application</option>
        <option value="library">Library</option>
        <option value="os">Operating System</option>
        <option value="firmware">Firmware</option>
        <option value="device">Device</option>
        <option value="other">Other</option>
      </select>
    </div>
    <div class="form-row"><label>Host / Device</label><input id="f-host" list="host-list" placeholder="e.g. dc01, fw-panos-01, workstation-finance"/></div>
    <div class="form-row"><label>CPE (optional — improves matching for commercial software)</label><input id="f-cpe" placeholder="e.g. cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"/></div>
    <div class="form-row"><label>purl (optional — improves matching for open source packages)</label><input id="f-purl" placeholder="e.g. pkg:pypi/requests@2.28.0 or pkg:npm/lodash@4.17.21"/></div>
    <div class="form-row"><label>Notes</label><textarea id="f-notes" rows="2" placeholder="Optional notes"></textarea></div>
    <div class="form-actions">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn primary" onclick="saveItem()">Save</button>
    </div>
  </div>
</div>

<!-- Import modal -->
<div class="modal-overlay" id="import-modal">
  <div class="modal" style="width:600px;">
    <h2>Import SBOM</h2>
    <div class="form-row">
      <label>Host / Device *</label>
      <select id="import-host-sel" onchange="importHostChange()" style="margin-bottom:6px;">
        <option value="">— select a device —</option>
      </select>
      <input id="import-host-new" placeholder="Type new hostname…" style="display:none;"/>
    </div>
    <div style="display:flex;gap:0;margin-bottom:12px;border-bottom:1px solid var(--border);">
      <button class="import-tab active" data-tab="file" onclick="switchTab('file')" style="padding:6px 16px;background:none;border:none;border-bottom:2px solid var(--accent);color:var(--accent);cursor:pointer;font-size:13px;font-weight:600;">File Path</button>
      <button class="import-tab" data-tab="paste" onclick="switchTab('paste')" style="padding:6px 16px;background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);cursor:pointer;font-size:13px;font-weight:600;">Paste JSON</button>
    </div>
    <div id="tab-file" class="form-row">
      <label>Path to SBOM file on this machine</label>
      <input id="import-path" placeholder="/home/user/sbom.json" oninput="previewImport()"/>
    </div>
    <div id="tab-paste" class="form-row" style="display:none;">
      <label>SBOM JSON — CycloneDX, SPDX, or plain array</label>
      <textarea id="import-json" rows="10" placeholder='{"bomFormat":"CycloneDX","components":[...]}'
        style="font-family:monospace;font-size:12px;" oninput="previewImport()"></textarea>
    </div>
    <div id="import-preview" style="font-size:12px;color:var(--muted);margin-bottom:12px;min-height:18px;"></div>
    <div class="form-actions">
      <button class="btn" onclick="closeImport()">Cancel</button>
      <button class="btn primary" id="import-btn" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<script>
let _editId = null;

function loadHosts(){
  fetch('/api/hosts').then(r=>r.json()).then(hosts=>{
    // filter dropdown
    const sel=document.getElementById('host-filter');
    const cur=sel.value;
    sel.innerHTML='<option value="">All devices</option>'+hosts.map(h=>`<option value="${esc(h)}"${h===cur?' selected':''}>${esc(h)}</option>`).join('');
    // chips
    const chips=document.getElementById('host-chips');
    chips.innerHTML=hosts.length?hosts.map(h=>`<span style="display:inline-flex;align-items:center;gap:4px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:12px;">
      <span style="color:var(--accent);cursor:pointer" onclick="filterHost('${esc(h)}')">${esc(h)}</span>
      <span style="color:var(--muted);cursor:pointer;font-size:10px" onclick="removeHost('${esc(h)}')" title="Remove">✕</span>
    </span>`).join(''):'<span style="font-size:12px;color:var(--muted)">No devices added yet.</span>';
    // datalist for form autocomplete
    document.getElementById('host-list').innerHTML=hosts.map(h=>`<option value="${esc(h)}">`).join('');
  });
}

function addHost(){
  const inp=document.getElementById('new-host');
  const name=inp.value.trim();
  if(!name)return;
  fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})})
    .then(()=>{inp.value='';loadHosts();});
}

function removeHost(name){
  if(!confirm('Remove device "'+name+'"? This does not remove it from SBOM items.'))return;
  fetch('/api/hosts/delete?name='+encodeURIComponent(name))
    .then(()=>loadHosts());
}

function filterHost(name){
  document.getElementById('host-filter').value=name;
  loadSBOM();
}

function loadSBOM(){
  const host=document.getElementById('host-filter').value;
  const url='/api/sbom'+(host?'?host='+encodeURIComponent(host):'');
  fetch(url).then(r=>r.json()).then(rows=>{
    const el=document.getElementById('sbom-table');
    if(!rows.length){el.innerHTML='<div class="empty">No items found.</div>';return;}
    el.innerHTML=`<table><thead><tr><th>Name</th><th>Vendor</th><th>Version</th><th>Type</th><th>Host</th><th>CPE / purl</th><th>Notes</th><th>Verified</th><th></th></tr></thead><tbody>`+
      rows.map(r=>{
        const verified=r.verified_at?(new Date(r.verified_at+'Z').toLocaleDateString()):'<span style="color:var(--red);font-weight:700">Never</span>';
        const ident=r.purl?`<span title="${esc(r.purl)}" style="color:var(--purple)">${esc(r.purl.substring(0,40))}${r.purl.length>40?'…':''}</span>`:
                    r.cpe ?`<span title="${esc(r.cpe)}"  style="color:var(--muted)">${esc(r.cpe.substring(0,40))}${r.cpe.length>40?'…':''}</span>`:'—';
        return`<tr>
        <td><strong>${esc(r.name)}</strong></td>
        <td style="color:var(--muted)">${esc(r.vendor)}</td>
        <td style="font-size:12px">${esc(r.version)||'—'}</td>
        <td><span class="type-badge">${esc(r.item_type)}</span></td>
        <td style="font-size:12px;color:var(--accent)">${r.host?esc(r.host):'<span style="color:var(--muted)">—</span>'}</td>
        <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ident}</td>
        <td style="font-size:12px;color:var(--muted)">${esc(r.notes)||'—'}</td>
        <td style="font-size:11px;white-space:nowrap">${verified}</td>
        <td style="white-space:nowrap">
          <button class="btn small" onclick="verifyItem(${r.id})">✓</button>
          <button class="btn small" onclick="openEdit(${r.id},'${esc(r.name)}','${esc(r.vendor)}','${esc(r.version)}','${r.item_type}','${esc(r.cpe)}','${esc(r.purl||'')}','${esc(r.host||'')}','${esc(r.notes)}')">Edit</button>
          <button class="btn small danger" onclick="delItem(${r.id})">Delete</button>
        </td>
      </tr>`;}).join('')+'</tbody></table>';
  });
}

function openAdd(){
  _editId=null;
  document.getElementById('modal-title').textContent='Add SBOM Item';
  ['name','vendor','version','cpe','purl','host','notes'].forEach(f=>document.getElementById('f-'+f).value='');
  document.getElementById('f-type').value='application';
  document.getElementById('edit-id').value='';
  document.getElementById('modal').classList.add('show');
  document.getElementById('f-name').focus();
}

function openEdit(id,name,vendor,version,type,cpe,purl,host,notes){
  _editId=id;
  document.getElementById('modal-title').textContent='Edit SBOM Item';
  document.getElementById('f-name').value=name;
  document.getElementById('f-vendor').value=vendor;
  document.getElementById('f-version').value=version;
  document.getElementById('f-type').value=type;
  document.getElementById('f-cpe').value=cpe;
  document.getElementById('f-purl').value=purl;
  document.getElementById('f-host').value=host;
  document.getElementById('f-notes').value=notes;
  document.getElementById('modal').classList.add('show');
}

function closeModal(){document.getElementById('modal').classList.remove('show');}

function saveItem(){
  const payload={
    name:document.getElementById('f-name').value.trim(),
    vendor:document.getElementById('f-vendor').value.trim(),
    version:document.getElementById('f-version').value.trim(),
    item_type:document.getElementById('f-type').value,
    cpe:document.getElementById('f-cpe').value.trim(),
    purl:document.getElementById('f-purl').value.trim(),
    host:document.getElementById('f-host').value.trim(),
    notes:document.getElementById('f-notes').value.trim(),
  };
  if(!payload.name||!payload.vendor){alert('Name and vendor are required.');return;}
  const url=_editId?'/api/sbom/'+_editId:'/api/sbom';
  const method=_editId?'POST':'POST';
  fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(()=>{closeModal();loadSBOM();});
}

function delItem(id){
  if(!confirm('Delete this SBOM item and all its matches?'))return;
  fetch('/api/sbom/'+id,{method:'DELETE'}).then(()=>loadSBOM());
}

function verifyItem(id){
  fetch('/api/sbom/'+id+'/verify',{method:'POST'}).then(()=>loadSBOM());
}

function verifyAll(){
  fetch('/api/sbom/verify-all',{method:'POST'}).then(()=>loadSBOM());
}

let _importTab = 'file';

function switchTab(tab){
  _importTab=tab;
  document.querySelectorAll('.import-tab').forEach(b=>{
    const active=b.dataset.tab===tab;
    b.style.color=active?'var(--accent)':'var(--muted)';
    b.style.borderBottom=active?'2px solid var(--accent)':'2px solid transparent';
  });
  document.getElementById('tab-file').style.display=tab==='file'?'':'none';
  document.getElementById('tab-paste').style.display=tab==='paste'?'':'none';
  document.getElementById('import-preview').textContent='';
}

function importHostChange(){
  const sel=document.getElementById('import-host-sel');
  const inp=document.getElementById('import-host-new');
  inp.style.display=sel.value==='__new__'?'':'none';
  if(sel.value==='__new__')inp.focus();
}

function _importHostValue(){
  const sel=document.getElementById('import-host-sel');
  if(sel.value==='__new__') return document.getElementById('import-host-new').value.trim();
  return sel.value;
}

function openImport(){
  document.getElementById('import-json').value='';
  document.getElementById('import-path').value='';
  document.getElementById('import-host-new').value='';
  document.getElementById('import-host-new').style.display='none';
  document.getElementById('import-preview').textContent='';
  // populate host select
  fetch('/api/hosts').then(r=>r.json()).then(hosts=>{
    const sel=document.getElementById('import-host-sel');
    sel.innerHTML='<option value="">— select a device —</option>'+
      hosts.map(h=>`<option value="${esc(h)}">${esc(h)}</option>`).join('')+
      '<option value="__new__">+ New device…</option>';
    sel.value='';
  });
  switchTab('file');
  document.getElementById('import-modal').classList.add('show');
  document.getElementById('import-host-sel').focus();
}

function closeImport(){document.getElementById('import-modal').classList.remove('show');}

function previewImport(){
  const prev=document.getElementById('import-preview');
  if(_importTab==='file'){
    const p=document.getElementById('import-path').value.trim();
    prev.innerHTML=p?'<span style="color:var(--muted)">File will be read from server on import.</span>':'';
    return;
  }
  const raw=document.getElementById('import-json').value.trim();
  if(!raw){prev.textContent='';return;}
  try{
    const data=JSON.parse(raw);
    let count=0, fmt='';
    if(data.bomFormat==='CycloneDX'||(data.components&&Array.isArray(data.components))){
      count=(data.components||[]).length; fmt='CycloneDX';
    } else if(data.spdxVersion){
      count=(data.packages||[]).length; fmt='SPDX';
    } else if(Array.isArray(data)){
      count=data.length; fmt='Plain array';
    } else {
      prev.innerHTML='<span style="color:var(--orange)">⚠ Unrecognised format — will attempt import</span>'; return;
    }
    prev.innerHTML=`<span style="color:var(--green)">✓ ${fmt} — ${count} component(s) found</span>`;
  } catch(e){
    prev.innerHTML='<span style="color:var(--red)">✗ Invalid JSON: '+esc(e.message)+'</span>';
  }
}

function doImport(){
  const host=_importHostValue();
  if(!host){alert('Please select or enter a host / device name.');return;}
  const btn=document.getElementById('import-btn');
  const prev=document.getElementById('import-preview');
  btn.disabled=true;
  prev.innerHTML='<span style="color:var(--muted)">Importing…</span>';

  let payload={host};
  if(_importTab==='file'){
    const fp=document.getElementById('import-path').value.trim();
    if(!fp){alert('Please enter a file path.');btn.disabled=false;return;}
    payload.file=fp;
  } else {
    const raw=document.getElementById('import-json').value.trim();
    try{payload.sbom=JSON.parse(raw);}catch(e){alert('Invalid JSON.');btn.disabled=false;return;}
  }

  fetch('/api/sbom/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(r=>r.json()).then(d=>{
      btn.disabled=false;
      if(d.error){prev.innerHTML=`<span style="color:var(--red)">✗ ${esc(d.error)}</span>`;return;}
      closeImport();
      loadHosts();
      loadSBOM();
      alert(`Imported ${d.imported} item(s) to "${host}".`);
    });
}

document.addEventListener('DOMContentLoaded', ()=>{loadHosts();loadSBOM();});
document.getElementById('modal').addEventListener('click', function(e){if(e.target===this)closeModal();});
document.getElementById('import-modal').addEventListener('click', function(e){if(e.target===this)closeImport();});
</script>
""" + FOOTER


# ---------------------------------------------------------------------------
# CVEs page
# ---------------------------------------------------------------------------

def _page_cves():
    return _page_head("CVEs") + _nav("CVEs") + """
<main>
  <div style="display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">
    <h2 style="font-size:16px;font-weight:700;flex:1">CVE Database</h2>
    <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
      <input type="checkbox" id="kev-filter" onchange="loadCVEs()"> KEV only
    </label>
    <select id="score-filter" onchange="loadCVEs()" style="width:auto">
      <option value="0">All scores</option>
      <option value="7.8" selected>≥ 7.8 (High+)</option>
      <option value="9.0">≥ 9.0 (Critical)</option>
    </select>
  </div>
  <div class="card">
    <div id="cve-table"><div class="empty">Loading…</div></div>
  </div>
</main>
<script>
function loadCVEs(){
  const minScore=document.getElementById('score-filter').value;
  const kevOnly=document.getElementById('kev-filter').checked?'1':'0';
  fetch(`/api/cves?min_score=${minScore}&kev=${kevOnly}`).then(r=>r.json()).then(rows=>{
    const el=document.getElementById('cve-table');
    if(!rows.length){el.innerHTML='<div class="empty">No CVEs found.</div>';return;}
    el.innerHTML=`<table><thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Severity</th><th>KEV</th><th>Published</th><th>Description</th></tr></thead><tbody>`+
      rows.map(r=>`<tr>
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank">${esc(r.cve_id)}</a></td>
        <td>${fmtScore(r.cvss_score)}</td>
        <td>${fmtEpss(r.epss)}</td>
        <td><span class="badge ${sevCls(r.severity)}">${r.severity||'—'}</span></td>
        <td>${r.kev?'<span class="badge kev">KEV</span>':''}</td>
        <td style="white-space:nowrap;font-size:11px;color:var(--muted)">${(r.published||'').substring(0,10)}</td>
        <td style="font-size:12px;color:var(--muted);max-width:400px">${esc((r.description||'').substring(0,160))}${r.description&&r.description.length>160?'…':''}</td>
      </tr>`).join('')+'</tbody></table>';
  });
}
document.addEventListener('DOMContentLoaded', loadCVEs);
</script>
""" + FOOTER


# ---------------------------------------------------------------------------
# Matches page
# ---------------------------------------------------------------------------

def _page_matches():
    return _page_head("Matches") + _nav("Matches") + """
<main>
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">
    <h2 style="font-size:16px;font-weight:700;flex:1">Vulnerability Matches</h2>
    <button class="filter-btn active" data-f="new"       onclick="setFilter('new')">Open</button>
    <button class="filter-btn"        data-f="all"       onclick="setFilter('all')">All</button>
    <button class="filter-btn"        data-f="ack"       onclick="setFilter('ack')">Acked</button>
    <button class="filter-btn"        data-f="fp"        onclick="setFilter('fp')">FP</button>
  </div>
  <div class="card">
    <div id="match-table"><div class="empty">Loading…</div></div>
  </div>
</main>
<style>
.filter-btn{padding:5px 12px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:12px;cursor:pointer;font-weight:600;}
.filter-btn.active{background:var(--surface2);color:var(--accent);border-color:var(--accent);}
</style>
<script>
let _filter='new';
function setFilter(f){
  _filter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.toggle('active',b.dataset.f===f));
  loadMatches();
}
function action(id,act){
  fetch(`/api/matches/${id}/action`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:act})})
    .then(()=>loadMatches());
}
function loadMatches(){
  fetch('/api/matches?status='+_filter).then(r=>r.json()).then(rows=>{
    const el=document.getElementById('match-table');
    if(!rows.length){el.innerHTML='<div class="empty">No matches.</div>';return;}

    // Group by sbom_item_id
    const groups={};
    rows.forEach(r=>{
      if(!groups[r.sbom_item_id]) groups[r.sbom_item_id]={item:r,rows:[]};
      groups[r.sbom_item_id].rows.push(r);
    });

    let html=`<table><thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Severity</th><th>KEV</th><th>Relevance</th><th>Match Reason</th><th>Status</th><th></th></tr></thead><tbody>`;
    Object.values(groups).forEach(g=>{
      const r0=g.item;
      const hasNew=g.rows.some(r=>r.status==='new');
      html+=`<tr style="background:var(--surface2);">
        <td colspan="8" style="padding:8px 10px;">
          <strong>${esc(r0.item_name)}</strong>
          <span style="font-size:11px;color:var(--muted);margin-left:8px;">${esc(r0.item_vendor)} ${esc(r0.item_version)}</span>
          ${r0.item_host?`<span style="font-size:11px;color:var(--accent);margin-left:8px;">@ ${esc(r0.item_host)}</span>`:''}
        </td>
        <td style="background:var(--surface2);text-align:right;padding-right:8px;">
          ${hasNew&&_filter!=='fp'?`<button class="btn small danger" onclick="fpAll(${r0.sbom_item_id})" title="Mark all open matches for this item as FP (item is patched)">FP All</button>`:''}
        </td>
      </tr>`;
      g.rows.forEach(r=>{
        html+=`<tr>
          <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank">${esc(r.cve_id)}</a></td>
          <td>${fmtScore(r.cvss_score)}</td>
          <td>${fmtEpss(r.epss)}</td>
          <td><span class="badge ${sevCls(r.severity)}">${r.severity||'—'}</span></td>
          <td>${r.kev?'<span class="badge kev">KEV</span>':''}</td>
          <td>${fmtVerdict(r.item_version, r.fix_versions)}</td>
          <td style="font-size:11px;color:var(--muted)">${esc(r.match_reason)}</td>
          <td><span class="badge ${r.status}">${r.status}</span></td>
          <td style="white-space:nowrap">
            ${r.status==='new'?`<button class="btn small" onclick="action(${r.id},'ack')">Ack</button>
            <button class="btn small" onclick="action(${r.id},'fp')">FP</button>`:''}
            ${r.status!=='new'?`<button class="btn small" onclick="action(${r.id},'reopen')">Reopen</button>`:''}
          </td>
        </tr>`;
      });
    });
    html+='</tbody></table>';
    el.innerHTML=html;
  }).catch(e=>{
    const el=document.getElementById('match-table');
    if(el)el.innerHTML='<div class="empty">Error loading matches: '+e.message+'</div>';
  });
}

function fpAll(itemId){
  if(!confirm('Mark all open matches for this item as False Positive? Use this when the software is fully patched.'))return;
  fetch(`/api/sbom/${itemId}/fp-all`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(r=>r.json()).then(d=>loadMatches());
}
document.addEventListener('DOMContentLoaded', loadMatches);
</script>
""" + FOOTER


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    db.init_db()
    threading.Thread(target=_feed_worker, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"SBOMguard running on http://0.0.0.0:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
