"""Behavioral correlation. This is the part commercial AV spent years on and the
single biggest source of *new*-threat detection. We watch a sliding window of
events per process and apply rules that produce a severity, a confidence, and a
plain-language explanation the dashboard shows verbatim.

Rules here are hand-written; the same idea maps onto open Sigma rules, which you
can load and translate into this evaluator later."""

from __future__ import annotations
import time
from collections import defaultdict, deque
from pathlib import Path

from .models import Event, Finding, Verdict, Severity

_DATA = Path(__file__).resolve().parent.parent / "data"
C2_FILES = (_DATA / "c2_ips.txt",          # abuse.ch Feodo Tracker
            _DATA / "threatfox_ips.txt")   # abuse.ch ThreatFox C2 IPs


def _load_c2() -> set[str]:
    """Load the known-bad C2 IP blocklists (engine/feeds.py keeps them fresh)."""
    ips: set[str] = set()
    for f in C2_FILES:
        if f.exists():
            try:
                ips |= {l.strip() for l in f.read_text(
                    encoding="utf-8", errors="ignore").splitlines() if l.strip()}
            except OSError:
                pass
    return ips

# Directories whose mass modification is a strong ransomware signal.
USER_DOC_HINTS = ("\\documents\\", "\\pictures\\", "\\desktop\\", "\\downloads\\",
                  "/documents/", "/pictures/", "/desktop/", "/downloads/")
SHADOW_HINTS = ("shadow", "vssadmin", "volume shadow")
TEMP_HINTS = ("\\temp\\", "/tmp/", "\\appdata\\local\\temp\\")
SYSTEM_READ_HINTS = ("\\system32\\config", "/etc/shadow", "lsass")
OFFICE_PARENTS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
SHELL_NAMES = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")

WINDOW_SECONDS = 30
MASS_WRITE_THRESHOLD = 25   # files written/encrypted in the window


class BehaviorEngine:
    def __init__(self, window: int = WINDOW_SECONDS):
        self.window = window
        self.events: dict[int, deque[Event]] = defaultdict(deque)
        self.c2: set[str] = _load_c2()

    def reload_c2(self) -> None:
        """Pick up a freshly-updated C2 blocklist without a restart."""
        self.c2 = _load_c2()

    def record(self, ev: Event) -> None:
        buf = self.events[ev.pid]
        buf.append(ev)
        cutoff = time.time() - self.window
        while buf and buf[0].ts < cutoff:
            buf.popleft()

    # --- individual rules: each returns a Finding or None ---

    def _rule_ransomware(self, pid: int) -> Finding | None:
        buf = self.events[pid]
        writes = [e for e in buf if e.op in ("WRITE", "ENCRYPT", "DELETE")
                  and any(h in e.path.lower() for h in USER_DOC_HINTS)]
        touched_shadow = any(
            any(h in (e.path + " " + e.op).lower() for h in SHADOW_HINTS) for e in buf
        )
        mass = len(writes) >= MASS_WRITE_THRESHOLD or any(e.op == "ENCRYPT" for e in buf)
        if mass and touched_shadow:
            return Finding(
                source="behavior", name="ransomware-pattern", severity=Severity.risk,
                detail=("It is rapidly modifying your personal files and deleting "
                        "backups (Volume Shadow Copies) — the signature behavior of "
                        "ransomware mid-execution."))
        if mass:
            return Finding(
                source="behavior", name="mass-file-modification", severity=Severity.watch,
                detail=("It is modifying many of your documents very quickly. This can "
                        "be normal for some tools, but is also how ransomware behaves."))
        return None

    def _rule_temp_unsigned(self, pid: int) -> Finding | None:
        buf = self.events[pid]
        from_temp = any(any(h in e.path.lower() for h in TEMP_HINTS)
                        and e.op == "EXECUTE" for e in buf)
        unsigned = any(not e.signed for e in buf)
        reads_system = any(any(h in e.path.lower() for h in SYSTEM_READ_HINTS)
                           for e in buf)
        if from_temp and unsigned and reads_system:
            return Finding(
                source="behavior", name="unsigned-temp-system-read", severity=Severity.watch,
                detail=("An unsigned program running from a temporary folder is reading "
                        "protected system files. Worth keeping an eye on."))
        return None

    def _rule_office_shell(self, pid: int) -> Finding | None:
        buf = self.events[pid]
        for e in buf:
            if (e.process.lower() in SHELL_NAMES
                    and e.parent.lower() in OFFICE_PARENTS):
                return Finding(
                    source="behavior", name="office-spawned-shell", severity=Severity.watch,
                    detail=("A document just launched a hidden command shell — a common "
                            "way malicious attachments gain a foothold."))
        return None

    def _rule_c2_connection(self, pid: int) -> Finding | None:
        if not self.c2:
            return None
        for e in self.events[pid]:
            if e.op == "CONNECT" and e.path:
                ip = e.path.rsplit(":", 1)[0].strip()
                if ip in self.c2:
                    return Finding(
                        source="netfeed", name="known-c2-connection", severity=Severity.risk,
                        detail=(f"It connected to {ip} — a server on a known botnet "
                                "command-and-control blocklist (abuse.ch Feodo Tracker + "
                                "ThreatFox). Programs talk to C2 servers to take orders or "
                                "exfiltrate data."))
        return None

    RULES = (_rule_ransomware, _rule_temp_unsigned, _rule_office_shell, _rule_c2_connection)

    def evaluate(self, pid: int) -> list[Finding]:
        out = []
        for rule in self.RULES:
            f = rule(self, pid)
            if f:
                out.append(f)
        return out


def fuse(findings: list[Finding]) -> Verdict:
    """Combine findings from all scanners + behavior into one verdict.
    Worst severity wins; confidence rises with corroborating sources."""
    if not findings:
        return Verdict(severity=Severity.safe, confidence=99,
                       why="Nothing unusual. Behaving exactly as expected.")

    order = {Severity.safe: 0, Severity.watch: 1, Severity.risk: 2}
    worst = max(findings, key=lambda f: order[f.severity])
    sources = {f.source for f in findings}

    # More independent sources agreeing => higher confidence.
    base = {Severity.risk: 80, Severity.watch: 55, Severity.safe: 99}[worst.severity]
    confidence = min(99, base + 6 * (len(sources) - 1))

    # Prefer the behavioral explanation for "why" — it's the most human.
    behavior = next((f for f in findings if f.source == "behavior"), None)
    why = (behavior or worst).detail

    return Verdict(severity=worst.severity, confidence=confidence,
                   why=why, findings=findings)
