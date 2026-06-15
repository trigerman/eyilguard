"""Shared data models. These shapes match what the Eyil dashboard expects, so
the UI consumes engine output without transformation."""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import time


class Severity(str, Enum):
    safe = "safe"
    watch = "watch"
    risk = "risk"


class Finding(BaseModel):
    """A single detection hit from one scanner."""
    source: str                 # "clamav" | "yara" | "hashfeed" | "behavior"
    name: str                   # signature / rule name
    severity: Severity
    detail: str = ""


class Event(BaseModel):
    """A raw activity event from the minifilter or Sysmon, tagged with its process."""
    ts: float = Field(default_factory=time.time)
    pid: int
    process: str
    op: str                     # READ | WRITE | EXECUTE | ENCRYPT | DELETE | CONNECT
    path: str = ""              # file path, or IP:port for CONNECT
    signed: bool = True
    parent: str = ""


class Verdict(BaseModel):
    """The fused conclusion the dashboard renders."""
    severity: Severity = Severity.safe
    confidence: int = 0         # 0-100
    why: str = ""               # plain-language explanation ("why this matters")
    findings: list[Finding] = []


class MonitoredObject(BaseModel):
    """A file/process the engine is tracking, with both views' data."""
    id: str
    name: str
    path: str
    pid: Optional[int] = None
    parent: str = ""
    signer: str = "unknown"
    sha256: str = ""
    size_bytes: Optional[int] = None
    verdict: Verdict = Verdict()
    status: str = "active"      # active | allowed | quarantined — set by user action
    ops: list[dict] = []
    net: list[dict] = []
    services: list[str] = []
    logs: list[dict] = []


class Health(BaseModel):
    """Update-health + protection status — surfaced directly in the dashboard."""
    clam_version: str = "unknown"
    signatures_age_seconds: Optional[float] = None
    feeds_age_seconds: Optional[float] = None
    signatures_stale: bool = True
    feeds_stale: bool = True
    hash_feed_count: int = 0
    c2_count: int = 0                   # known botnet C2 IPs (Feodo Tracker)
    yara_rule_count: int = 0            # compiled YARA rule files
    ok: bool = False
    # real-time protection status (honest about which layer is active)
    realtime_active: bool = False
    realtime_mode: str = "off"          # "user-mode (detect & react)" | "off"
    watching: list[str] = []
