"""Indicator-of-Compromise database and matcher.

Supported input formats (auto-detected per file):
  * plain text - one indicator per line, type auto-detected, '#' comments
  * CSV        - any column containing indicators (abuse.ch / ThreatFox / custom)
  * JSON       - list of strings or objects with value/type, MISP event export
  * STIX 2.1   - bundle of `indicator` objects with simple equality patterns
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
from typing import Iterable, Optional

from aletheia.core.util import RE_DOMAIN, RE_IPV4, RE_MD5, RE_SHA1, RE_SHA256, RE_URL, read_text

TYPES = ("md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url", "filename", "string")

STIX_PATTERN = re.compile(
    r"\[(file:hashes\.'?(SHA-256|SHA-1|MD5)'?|ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|"
    r"file:name)\s*=\s*'([^']+)'\]", re.I)

MISP_TYPES = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "ip-dst": "ipv4", "ip-src": "ipv4",
              "domain": "domain", "hostname": "domain", "url": "url", "filename": "filename",
              "ip-dst|port": "ipv4", "ip-src|port": "ipv4"}

BENIGN_DOMAINS = {"localhost", "example.com", "example.org", "example.net"}


def classify(value: str) -> Optional[str]:
    v = value.strip().strip('"').strip("'")
    if not v:
        return None
    if RE_SHA256.match(v):
        return "sha256"
    if RE_SHA1.match(v):
        return "sha1"
    if RE_MD5.match(v):
        return "md5"
    if v.lower().startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    host = v.split(":")[0] if v.count(":") == 1 else v
    try:
        ip = ipaddress.ip_address(host)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if RE_DOMAIN.fullmatch(v.lower()):
        return "domain"
    return None


def refang(v: str) -> str:
    return (v.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http").replace("[:]", ":")
            .replace("[://]", "://").strip())


class IOCDatabase:
    def __init__(self):
        self.iocs: dict = {t: {} for t in TYPES}  # type -> value -> meta
        self.sources: list = []

    def __len__(self):
        return sum(len(v) for v in self.iocs.values())

    def add(self, value: str, ioc_type: Optional[str] = None, source: str = "", description: str = "",
            threat: str = "") -> bool:
        value = refang(str(value))
        ioc_type = ioc_type or classify(value)
        if not ioc_type or ioc_type not in self.iocs:
            return False
        if ioc_type in ("md5", "sha1", "sha256", "domain"):
            value = value.lower()
        if ioc_type == "ipv4" and ":" in value:  # strip ip:port
            value = value.split(":")[0]
        if ioc_type == "domain" and value in BENIGN_DOMAINS:
            return False
        self.iocs[ioc_type].setdefault(value, {"source": source, "description": description, "threat": threat})
        return True

    # ---------------------------------------------------------------- loading
    def load_path(self, path: str) -> int:
        if os.path.isdir(path):
            return sum(self.load_path(os.path.join(path, f)) for f in sorted(os.listdir(path))
                       if not f.startswith(".") and f != "feeds.json")
        text = read_text(path, max_bytes=256 * 1024 * 1024)
        if text is None:
            return 0
        before = len(self)
        name = os.path.basename(path)
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                self._load_json(json.loads(text), name)
            except ValueError:
                self._load_text(text, name)
        elif path.lower().endswith(".csv"):
            self._load_csv(text, name)
        else:
            self._load_text(text, name)
        added = len(self) - before
        self.sources.append({"source": path, "indicators_added": added})
        return added

    def _load_text(self, text: str, source: str) -> None:
        for raw in text.splitlines():
            line, _, comment = raw.partition("#")
            line, comment = line.strip(), comment.strip()
            if not line:
                continue
            token = line.split()[0].split(",")[0]
            if token.lower().startswith("filename:"):
                self.add(token.split(":", 1)[1], "filename", source, comment, comment)
            else:
                self.add(token, None, source, comment, comment)

    def _load_csv(self, text: str, source: str) -> None:
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        for row in csv.reader(io.StringIO("\n".join(lines))):
            for cell in row:
                cell = cell.strip().strip('"')
                if classify(refang(cell)):
                    self.add(cell, None, source, threat=row[-1] if len(row) > 1 else "")

    def _load_json(self, obj, source: str) -> None:
        if isinstance(obj, dict) and obj.get("type") == "bundle":
            for o in obj.get("objects", []):
                if o.get("type") == "indicator":
                    for m in STIX_PATTERN.finditer(o.get("pattern", "")):
                        field, hashname, value = m.group(1).lower(), (m.group(2) or "").lower(), m.group(3)
                        t = {"sha-256": "sha256", "sha-1": "sha1", "md5": "md5"}.get(hashname) if hashname else None
                        if not t:
                            t = {"ipv4-addr:value": "ipv4", "ipv6-addr:value": "ipv6", "domain-name:value": "domain",
                                 "url:value": "url", "file:name": "filename"}.get(field)
                        self.add(value, t, source, o.get("name", ""), ",".join(o.get("labels", [])))
            return
        if isinstance(obj, dict) and ("Event" in obj or "Attribute" in obj):
            ev = obj.get("Event", obj)
            attrs = list(ev.get("Attribute", []))
            for o in ev.get("Object", []):
                attrs += o.get("Attribute", [])
            for a in attrs:
                t = MISP_TYPES.get(a.get("type", ""))
                if t:
                    self.add(str(a.get("value", "")).split("|")[0], t, source, a.get("comment", ""),
                             ev.get("info", ""))
            return
        if isinstance(obj, dict):
            obj = obj.get("indicators") or obj.get("data") or list(obj.values())
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    self.add(item, None, source)
                elif isinstance(item, dict):
                    val = item.get("value") or item.get("ioc") or item.get("indicator") or item.get("sha256_hash")
                    if val:
                        self.add(str(val), item.get("type") if item.get("type") in TYPES else None, source,
                                 item.get("description", ""), item.get("threat", item.get("malware", "")))

    # --------------------------------------------------------------- matching
    def match_hash(self, *hashes: Optional[str]) -> Optional[dict]:
        for h in hashes:
            if not h:
                continue
            h = h.lower()
            for t in ("sha256", "sha1", "md5"):
                if h in self.iocs[t]:
                    return {"type": t, "value": h, **self.iocs[t][h]}
        return None

    def match_ip(self, ip: str) -> Optional[dict]:
        for t in ("ipv4", "ipv6"):
            if ip in self.iocs[t]:
                return {"type": t, "value": ip, **self.iocs[t][ip]}
        return None

    def match_domain(self, name: str) -> Optional[dict]:
        name = name.lower().rstrip(".")
        parts = name.split(".")
        for i in range(len(parts) - 1):  # match the domain and any parent domain
            cand = ".".join(parts[i:])
            if cand in self.iocs["domain"]:
                return {"type": "domain", "value": cand, **self.iocs["domain"][cand]}
        return None

    def match_filename(self, name: str) -> Optional[dict]:
        n = name.lower()
        for v, meta in self.iocs["filename"].items():
            if v.lower() == n:
                return {"type": "filename", "value": v, **meta}
        return None

    def scan_text(self, text: str) -> list:
        """Find any IOC (url, domain, ip, hash) embedded in arbitrary text."""
        hits = []
        if not text:
            return hits
        low = text.lower()
        for url in RE_URL.findall(text):
            if url in self.iocs["url"] or url.rstrip("/") in self.iocs["url"]:
                hits.append({"type": "url", "value": url, **self.iocs["url"].get(url, self.iocs["url"].get(url.rstrip("/"), {}))})
        for ip in set(RE_IPV4.findall(text)):
            m = self.match_ip(ip)
            if m:
                hits.append(m)
        for dom in set(RE_DOMAIN.findall(low)):
            m = self.match_domain(dom)
            if m:
                hits.append(m)
        for token in set(re.findall(r"\b[a-f0-9]{32,64}\b", low)):
            m = self.match_hash(token)
            if m:
                hits.append(m)
        return hits

    def stats(self) -> dict:
        return {t: len(v) for t, v in self.iocs.items() if v}


def builtin_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ioc")


def load_database(sources: Iterable[str], include_builtin: bool = True) -> IOCDatabase:
    db = IOCDatabase()
    paths = ([builtin_path()] if include_builtin else []) + list(sources)
    feeds_dir = os.path.join(os.path.expanduser("~"), ".aletheia", "feeds")
    if include_builtin and os.path.isdir(feeds_dir):
        paths.append(feeds_dir)
    for p in paths:
        if os.path.exists(p):
            db.load_path(p)
    return db
