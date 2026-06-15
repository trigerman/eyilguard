"""Detection scanners. Each returns Findings for a file path. The composite
Engine runs all of them and the worst severity wins."""

from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path

from .models import Finding, Severity

# Optional deps: import lazily so the module loads even if a scanner is absent.
try:
    import clamd
    _HAVE_CLAMD = True
except ImportError:
    _HAVE_CLAMD = False

# Prefer yara-x (Rust engine, ships modern wheels); fall back to yara-python.
try:
    import yara_x
    _HAVE_YARAX = True
except ImportError:
    _HAVE_YARAX = False

try:
    import yara
    _HAVE_YARA = True
except ImportError:
    _HAVE_YARA = False

DATA = Path(__file__).resolve().parent.parent / "data"
HASH_FILE = DATA / "hashes.txt"
YARA_DIR = DATA / "yara"                                   # user / Malpedia rules
BUILTIN_YARA_DIR = Path(__file__).resolve().parent / "yara_builtin"   # shipped rules

_YARA_MAX_BYTES = 256 * 1024 * 1024     # don't read enormous files into memory
_RULE_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", re.M)
_SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta",
    ".wsf", ".wsh", ".php", ".asp", ".aspx", ".jsp", ".txt",
}
_SCRIPT_ONLY_RULES = {
    "Suspicious_PowerShell_DownloadCradle",
}


def sha256_of(path: str, chunk: int = 65536) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
    except (OSError, PermissionError):
        return None
    return h.hexdigest()


class ClamScanner:
    """Talks to a running clamd daemon. Real ClamAV signatures, kept fresh by
    freshclam — we don't manage the database ourselves."""

    def __init__(self):
        self.cd = None
        if not _HAVE_CLAMD:
            return
        # Try the common transports; users on Windows usually have the TCP socket.
        for factory in (
            lambda: clamd.ClamdUnixSocket(),
            lambda: clamd.ClamdNetworkSocket("127.0.0.1", 3310),
        ):
            try:
                cd = factory()
                cd.ping()
                self.cd = cd
                break
            except Exception:
                continue

    @property
    def available(self) -> bool:
        return self.cd is not None

    def version(self) -> str:
        try:
            return self.cd.version() if self.cd else "unavailable"
        except Exception:
            return "unavailable"

    def scan(self, path: str) -> list[Finding]:
        if not self.cd:
            return []
        status, sig = self._scan(path)
        if status == "FOUND":
            return [Finding(source="clamav", name=sig or "unknown",
                            severity=Severity.risk,
                            detail="Matched a ClamAV signature.")]
        return []

    def _scan(self, path: str) -> tuple[str | None, str | None]:
        """Get a (status, signature) for a path. Prefer INSTREAM — the engine
        reads the bytes and streams them to clamd — because it works even when
        the daemon can't open the path itself (different user, container, or an
        on-access AV holding a lock). Fall back to asking clamd to open it."""
        try:
            with open(path, "rb") as f:
                res = self.cd.instream(f)
            return (res or {}).get("stream", (None, None))
        except Exception:
            pass
        try:
            res = self.cd.scan(path)  # {path: (status, signature)}
            for _p, (status, sig) in (res or {}).items():
                return status, sig
        except Exception:
            pass
        return (None, None)


class YaraScanner:
    """Matches files against the bundled hacktool rules plus any user/Malpedia
    rules in data/yara/. Prefers the yara-x engine (works on modern Python) and
    falls back to yara-python if that's what's installed."""

    def __init__(self):
        self.rules = None
        self.backend: str | None = None        # "yara-x" | "yara" | None
        self.rule_count = 0
        self.reload()

    def _rule_files(self) -> list[Path]:
        files: list[Path] = []
        for d in (BUILTIN_YARA_DIR, YARA_DIR):
            if d.is_dir():
                files += list(d.rglob("*.yar")) + list(d.rglob("*.yara"))
        return files

    def reload(self) -> None:
        """(Re)compile bundled + user rules. Bad rule files are skipped one by one
        so a broken rule in a big community pack can't disable everything."""
        self.rules = None
        self.backend = None
        self.rule_count = 0
        files = self._rule_files()
        if not files:
            return
        if _HAVE_YARAX:
            self._compile_yarax(files)
        elif _HAVE_YARA:
            self._compile_yara(files)

    def _compile_yarax(self, files: list[Path]) -> None:
        comp = yara_x.Compiler()
        # Define the external variables big community packs (signature-base) use,
        # so rules referencing them compile instead of being skipped wholesale.
        for _ext in ("filename", "filepath", "extension", "filetype", "owner", "md5"):
            try:
                comp.define_global(_ext, "")
            except Exception:
                pass
        count = 0
        for p in files:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
                comp.add_source(text)
                count += len(_RULE_RE.findall(text))
            except Exception:
                continue          # skip a broken / duplicate rule file
        if count == 0:
            return
        try:
            self.rules = comp.build()
            self.backend = "yara-x"
            self.rule_count = count
        except Exception:
            self.rules = None

    def _compile_yara(self, files: list[Path]) -> None:
        good: dict[str, str] = {}
        count = 0
        for i, p in enumerate(files):
            try:
                yara.compile(filepath=str(p))         # test-compile in isolation
                good[f"r{i}"] = str(p)
                count += len(_RULE_RE.findall(p.read_text(encoding="utf-8", errors="ignore")))
            except Exception:
                continue
        if not good:
            return
        try:
            self.rules = yara.compile(filepaths=good)
            self.backend = "yara"
            self.rule_count = count
        except yara.Error:
            self.rules = None

    @property
    def available(self) -> bool:
        return self.rules is not None

    def _filter_matches_for_path(self, names: list[str], path: str) -> list[str]:
        """Drop script-content heuristics when they only match strings embedded
        inside compiled desktop applications.

        Generic PowerShell strings such as DownloadString + IEX appear inside
        legitimate Electron/Node apps and SDKs. Treat those as useful only for
        script-like files; exact malware/hacktool signatures still apply to
        executables.
        """
        ext = os.path.splitext(path)[1].lower()
        if ext in _SCRIPT_EXTENSIONS:
            return names
        return [name for name in names if name not in _SCRIPT_ONLY_RULES]

    def _finding_for_match(self, name: str) -> Finding:
        if name in _SCRIPT_ONLY_RULES:
            return Finding(
                source="yara", name=name, severity=Severity.watch,
                detail=(
                    f"Matched the YARA heuristic '{name}' — script content contains "
                    "PowerShell download-and-execute patterns. Review before running."
                ),
            )
        return Finding(
            source="yara", name=name, severity=Severity.risk,
            detail=f"Matched the YARA rule '{name}' — a known tool or malware pattern.",
        )

    def scan(self, path: str) -> list[Finding]:
        if not self.rules:
            return []
        names: list[str] = []
        try:
            if self.backend == "yara-x":
                if os.path.getsize(path) > _YARA_MAX_BYTES:
                    return []
                with open(path, "rb") as f:
                    data = f.read()
                scanner = yara_x.Scanner(self.rules)
                base = os.path.basename(path)
                ext = os.path.splitext(path)[1].lower()
                for _id, _val in (("filename", base), ("filepath", path),
                                  ("extension", ext), ("filetype", ""),
                                  ("owner", ""), ("md5", "")):
                    try:
                        scanner.set_global(_id, _val)
                    except Exception:
                        pass
                result = scanner.scan(data)
                names = [r.identifier for r in result.matching_rules]
            else:
                names = [m.rule for m in self.rules.match(path, timeout=20)]
        except Exception:
            return []
        names = self._filter_matches_for_path(names, path)
        return [self._finding_for_match(name) for name in names]


class HashScanner:
    """Checks a file's SHA-256 against the abuse.ch-derived blocklist."""

    def __init__(self):
        self.blocklist: set[str] = set()
        self.reload()

    def reload(self) -> None:
        self.blocklist.clear()
        if HASH_FILE.exists():
            with open(HASH_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if len(line) == 64 and not line.startswith("#"):
                        self.blocklist.add(line)

    @property
    def count(self) -> int:
        return len(self.blocklist)

    def scan(self, path: str, digest: str | None = None) -> list[Finding]:
        digest = digest or sha256_of(path)
        if digest and digest in self.blocklist:
            return [Finding(source="hashfeed", name="known-malware-hash",
                            severity=Severity.risk,
                            detail="Hash appears in a threat-intel feed.")]
        return []


class Engine:
    """Runs all scanners over a path and returns the combined findings."""

    def __init__(self):
        self.clam = ClamScanner()
        self.yara = YaraScanner()
        self.hash = HashScanner()

    def scan(self, path: str) -> list[Finding]:
        if not os.path.exists(path):
            return []
        digest = sha256_of(path)
        findings: list[Finding] = []
        findings += self.hash.scan(path, digest)
        findings += self.clam.scan(path)
        findings += self.yara.scan(path)
        return findings
