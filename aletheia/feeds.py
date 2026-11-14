"""Download free threat-intelligence feeds into ~/.aletheia/feeds (explicit user action only).

Scans themselves never touch the network. Feeds are fetched over HTTPS with TLS
verification, and each download's SHA-256 + timestamp is recorded in feeds.json so
the exact intelligence used in a case can be reproduced.
"""

from __future__ import annotations

import json
import os
import urllib.request

from aletheia import __version__
from aletheia.core.util import sha256_bytes, utc_now

FEEDS = {
    "feodotracker_ips.txt": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "desc": "abuse.ch Feodo Tracker - botnet C2 IP blocklist (CC0)",
    },
    "urlhaus_online.txt": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "desc": "abuse.ch URLhaus - active malware distribution URLs (CC0)",
    },
    "malwarebazaar_recent_sha256.txt": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "desc": "abuse.ch MalwareBazaar - recent malware SHA-256 (CC0)",
    },
    "threatfox_recent.csv": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "desc": "abuse.ch ThreatFox - recent IOCs (CC0)",
    },
    "sslbl_ips.txt": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "desc": "abuse.ch SSLBL - botnet C2 IPs (CC0)",
    },
}


def feeds_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".aletheia", "feeds")
    os.makedirs(d, exist_ok=True)
    return d


def update(log=print, only=None) -> dict:
    d = feeds_dir()
    manifest_path = os.path.join(d, "feeds.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    for name, meta in FEEDS.items():
        if only and name not in only:
            continue
        req = urllib.request.Request(meta["url"], headers={"User-Agent": f"aletheia-dfir/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
        except Exception as exc:
            log(f"  [!] {name}: {exc}")
            manifest[name] = {**meta, "error": str(exc), "attempted_utc": utc_now()}
            continue
        if data[:2] == b"PK":  # zipped export
            import io
            import zipfile

            with zipfile.ZipFile(io.BytesIO(data)) as z:
                data = z.read(z.namelist()[0])
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(data)
        manifest[name] = {**meta, "sha256": sha256_bytes(data), "bytes": len(data), "downloaded_utc": utc_now()}
        log(f"  [+] {name}: {len(data):,} bytes")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def snapshot() -> dict:
    p = os.path.join(feeds_dir(), "feeds.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {}
