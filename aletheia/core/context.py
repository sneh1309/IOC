"""Scan context shared by collectors, detectors and reporters."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

PROFILES = {
    # max files hashed, max file size hashed (bytes), recurse depth, log lines
    "quick": {"max_files": 5_000, "max_hash_size": 25 * 1024 * 1024, "max_depth": 4, "log_events": 300},
    "standard": {"max_files": 50_000, "max_hash_size": 100 * 1024 * 1024, "max_depth": 8, "log_events": 2_000},
    "deep": {"max_files": 500_000, "max_hash_size": 512 * 1024 * 1024, "max_depth": 32, "log_events": 10_000},
}


@dataclass
class CaseInfo:
    case_id: str
    examiner: str
    organization: str = ""
    client: str = ""
    purpose: str = ""
    evidence_item: str = ""
    notes: str = ""
    timezone_note: str = "All timestamps are UTC (ISO-8601) unless stated otherwise."


@dataclass
class ScanContext:
    case: CaseInfo
    case_dir: str
    profile: str = "standard"
    extra_paths: list = field(default_factory=list)
    ioc_sources: list = field(default_factory=list)
    yara_sources: list = field(default_factory=list)
    external_tools: list = field(default_factory=list)  # names explicitly enabled
    allow_tool_footprint: bool = False
    audit: Any = None
    store: Any = None
    runner: Any = None
    artifacts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    tool_runs: list = field(default_factory=list)
    log: Any = print

    @property
    def limits(self) -> dict:
        return PROFILES.get(self.profile, PROFILES["standard"])

    def add_artifact(self, name: str, data: Any, description: str = "") -> dict:
        self.artifacts[name] = data
        rec = self.store.save_json(name, {"artifact": name, "description": description, "data": data})
        self.audit.record("artifact_preserved", {"artifact": name, "file": rec["path"], "sha256": rec["sha256"]})
        return rec

    def error(self, where: str, exc: Any) -> None:
        msg = {"where": where, "error": str(exc)}
        self.errors.append(msg)
        if self.audit is not None:
            self.audit.record("collection_error", msg)

    def is_inside_case_dir(self, path: str) -> bool:
        try:
            return os.path.commonpath([os.path.abspath(path), self.case_dir]) == self.case_dir
        except ValueError:
            return False


def get(artifacts: dict, name: str, default: Optional[Any] = None):
    val = artifacts.get(name)
    return default if val is None else val
