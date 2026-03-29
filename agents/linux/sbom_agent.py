#!/usr/bin/env python3
"""SBOMGuard Linux agent — generates a CycloneDX 1.4 SBOM and uploads it.

Usage:
  python3 sbom_agent.py [--server URL] [--output FILE] [--dry-run]

Defaults:
  server:  http://10.10.0.40:8082/api/sbom  (or SBOMGUARD_SERVER env var)

Supported package managers: dpkg, rpm, apk, pacman
No third-party dependencies required.
"""
import datetime
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

DEFAULT_SERVER = os.environ.get("SBOMGUARD_SERVER", "http://10.10.0.40:8082/api/sbom/import")


# ── OS info ──────────────────────────────────────────────────────────────────

def os_release() -> dict:
    info = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k] = v.strip('"')
    except FileNotFoundError:
        pass
    return info


# ── Package enumeration ───────────────────────────────────────────────────────

def _run(cmd: list) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _collect_dpkg() -> list:
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"])
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1]:
            pkgs.append((parts[0], parts[1], parts[2] if len(parts) > 2 else "", "deb"))
    return pkgs


def _collect_rpm() -> list:
    out = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"])
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            pkgs.append((parts[0], parts[1], parts[2] if len(parts) > 2 else "", "rpm"))
    return pkgs


def _collect_apk() -> list:
    # output: name-version-rN {group} [arch] installed
    out = _run(["apk", "list", "--installed"])
    pkgs = []
    for line in out.splitlines():
        m = re.match(r'^(\S+?)-([\d][\d\.\-r]+)\s', line)
        if m:
            pkgs.append((m.group(1), m.group(2), "", "apk"))
    return pkgs


def _collect_pacman() -> list:
    out = _run(["pacman", "-Q"])
    pkgs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append((parts[0], parts[1], "", "alpm"))
    return pkgs


def detect_packages() -> list:
    """Return [(name, version, arch, pkg_type), ...]."""
    for collector, binary in [
        (_collect_dpkg,  "/usr/bin/dpkg-query"),
        (_collect_rpm,   "/usr/bin/rpm"),
        (_collect_apk,   "/sbin/apk"),
        (_collect_pacman, "/usr/bin/pacman"),
    ]:
        if os.path.exists(binary):
            pkgs = collector()
            if pkgs:
                return pkgs
    return []


# ── PURL ─────────────────────────────────────────────────────────────────────

def make_purl(name: str, version: str, pkg_type: str, distro_id: str, arch: str) -> str:
    v = version or "unknown"
    a = f"?arch={arch}" if arch else ""
    if pkg_type == "deb":
        return f"pkg:deb/{distro_id}/{name}@{v}{a}"
    if pkg_type == "rpm":
        return f"pkg:rpm/{distro_id}/{name}@{v}{a}"
    if pkg_type == "apk":
        return f"pkg:apk/alpine/{name}@{v}"
    if pkg_type == "alpm":
        return f"pkg:alpm/arch/{name}@{v}"
    return f"pkg:generic/{name}@{v}"


# ── SBOM assembly ─────────────────────────────────────────────────────────────

def build_sbom() -> dict:
    rel = os_release()
    distro_id = rel.get("ID", "linux")
    os_version = rel.get("PRETTY_NAME") or rel.get("NAME", "Linux")
    if rel.get("VERSION_ID"):
        os_version = f"{rel.get('NAME', 'Linux')} {rel['VERSION_ID']}"
    if rel.get("PRETTY_NAME"):
        os_version = rel["PRETTY_NAME"]

    hostname = platform.node()
    kernel = platform.release()

    packages = detect_packages()
    if not packages:
        print("WARNING: no packages detected — check package manager", file=sys.stderr)

    components = []
    for name, version, arch, pkg_type in packages:
        purl = make_purl(name, version, pkg_type, distro_id, arch)
        comp = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }
        if arch:
            comp["properties"] = [{"name": "arch", "value": arch}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "SBOMGuard", "name": "linux-agent", "version": "1.0"}],
            "component": {
                "type": "operating-system",
                "bom-ref": "host",
                "name": hostname,
                "version": os_version,
                "properties": [
                    {"name": "distro_id", "value": distro_id},
                    {"name": "kernel", "value": kernel},
                ],
            },
        },
        "components": components,
    }


# ── Upload ────────────────────────────────────────────────────────────────────

def upload(sbom: dict, url: str) -> bool:
    hostname = platform.node()
    payload = {"host": hostname, "sbom": sbom}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(data)),
            "User-Agent": "sbomguard-linux-agent/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            print(f"Uploaded OK  status={resp.status}  {body}")
            return True
    except urllib.error.HTTPError as e:
        print(f"Upload failed: HTTP {e.code}  {e.read().decode()}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"Upload failed: {e.reason}", file=sys.stderr)
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    server = DEFAULT_SERVER
    output = None
    dry_run = False
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--server" and i + 1 < len(args):
            server = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output = args[i + 1]
            i += 2
        elif args[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            print(f"Unknown argument: {args[i]}", file=sys.stderr)
            i += 1
    return server, output, dry_run


def main():
    server, output, dry_run = parse_args()

    print(f"Generating SBOM for {platform.node()} ...")
    sbom = build_sbom()
    print(f"Found {len(sbom['components'])} packages")

    if dry_run:
        print(json.dumps(sbom, indent=2))
        return

    if output:
        with open(output, "w") as fh:
            json.dump(sbom, fh, indent=2)
        print(f"Written to {output}")
        return

    print(f"Uploading to {server} ...")
    if not upload(sbom, server):
        sys.exit(1)


if __name__ == "__main__":
    main()
