"""Threat-intel feed updates + update-health.

Pulls a malware-hash feed from abuse.ch (MalwareBazaar) into data/hashes.txt and
records when signatures and feeds last refreshed, so the dashboard can warn when
protection goes stale — the failure mode ClamAV operators say matters most.

Run as a one-off:   python -m engine.feeds --update
Or on a schedule (cron / Task Scheduler / a background thread)."""

from __future__ import annotations
import json
import os
import time
import zipfile
import io
from pathlib import Path

import requests

from .paths import DATA
HASH_FILE = DATA / "hashes.txt"
C2_FILE = DATA / "c2_ips.txt"
STATE_FILE = DATA / "feed_state.json"

# abuse.ch Feodo Tracker — botnet command-and-control server IPs. Keyless bulk
# export (one IP per line); flags processes that phone home to a known C2.
FEODO_C2 = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# MalwareBazaar publishes bulk SHA-256 exports. "recent" is small and frequent;
# "full" is the complete set (large). Some abuse.ch endpoints now want a free
# Auth-Key header — set ABUSE_CH_KEY below if your account requires it.
MB_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
MB_FULL_ZIP = "https://bazaar.abuse.ch/export/txt/sha256/full/"

# These two need a free abuse.ch Auth-Key (auth.abuse.ch).
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_PAYLOADS = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
THREATFOX_IPS = DATA / "threatfox_ips.txt"

# Malpedia (Fraunhofer FKIE) YARA rules — fetched with the *user's own* key to
# their own machine, never bundled (respects TLP:AMBER/GREEN restrictions).
MALPEDIA_YARA = "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/after/2015-01-01"
YARA_DIR = DATA / "yara"

from . import keystore  # noqa: E402  (after constants, before functions)

STALE_SIGNATURES = 24 * 3600   # warn if ClamAV sigs older than a day
STALE_FEEDS = 24 * 3600        # warn if feeds older than a day


def _headers() -> dict:
    key = keystore.get("abuse_ch")
    return {"Auth-Key": key} if key else {}


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def _save_state(state: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def update(full: bool = False) -> int:
    """Download the hash feed and merge into data/hashes.txt. Returns the new count."""
    DATA.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if HASH_FILE.exists():
        existing = {l.strip().lower() for l in HASH_FILE.read_text(
            encoding="utf-8", errors="ignore").splitlines()
            if len(l.strip()) == 64}

    fetched: set[str] = set()
    try:
        if full:
            r = requests.get(MB_FULL_ZIP, headers=_headers(), timeout=120)
            r.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                for name in z.namelist():
                    text = z.read(name).decode("utf-8", "ignore")
                    fetched |= _parse_hashes(text)
        else:
            r = requests.get(MB_RECENT, headers=_headers(), timeout=60)
            r.raise_for_status()
            fetched = _parse_hashes(r.text)
    except requests.RequestException as e:
        print(f"[feeds] fetch failed: {e}")
        # do NOT update the timestamp on failure — that keeps "stale" honest
        return len(existing)

    merged = existing | fetched
    HASH_FILE.write_text("\n".join(sorted(merged)), encoding="utf-8")

    state = _load_state()
    state["feeds_updated_at"] = time.time()
    state["hash_count"] = len(merged)
    _save_state(state)
    print(f"[feeds] {len(fetched)} fetched, {len(merged)} total hashes")
    return len(merged)


def _parse_hashes(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip().strip('"').lower()
        if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
            out.add(line)
    return out


def _parse_ips(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parts = line.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            out.add(line)
    return out


def update_c2() -> int:
    """Refresh the Feodo Tracker C2 IP blocklist into data/c2_ips.txt.
    Returns the IP count. Like the hash feed, the timestamp is only advanced on a
    successful fetch so a failure shows as stale rather than a false 'fresh'."""
    DATA.mkdir(parents=True, exist_ok=True)
    try:
        r = requests.get(FEODO_C2, headers=_headers(), timeout=60)
        r.raise_for_status()
        ips = _parse_ips(r.text)
    except requests.RequestException as e:
        print(f"[feeds] C2 fetch failed: {e}")
        if C2_FILE.exists():
            return len(_parse_ips(C2_FILE.read_text(encoding="utf-8", errors="ignore")))
        return 0
    C2_FILE.write_text("\n".join(sorted(ips)), encoding="utf-8")
    state = _load_state()
    state["c2_updated_at"] = time.time()
    state["c2_count"] = len(ips)
    _save_state(state)
    print(f"[feeds] {len(ips)} C2 IPs")
    return len(ips)


def _merge_hashes(new: set[str]) -> int:
    """Union freshly-pulled SHA-256s into data/hashes.txt; return the new total."""
    DATA.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if HASH_FILE.exists():
        existing = {l.strip().lower() for l in HASH_FILE.read_text(
            encoding="utf-8", errors="ignore").splitlines() if len(l.strip()) == 64}
    merged = existing | {h.lower() for h in new if len(h) == 64}
    HASH_FILE.write_text("\n".join(sorted(merged)), encoding="utf-8")
    state = _load_state()
    state["hash_count"] = len(merged)
    _save_state(state)
    return len(merged)


def update_threatfox(days: int = 1) -> dict:
    """Pull recent ThreatFox IOCs: SHA-256s into the hash blocklist, C2 IPs into
    data/threatfox_ips.txt. Needs the Auth-Key. Honest: no timestamp bump on failure."""
    if not keystore.get("abuse_ch"):
        return {"error": "no abuse.ch Auth-Key"}
    try:
        r = requests.post(THREATFOX_API, headers=_headers(),
                          json={"query": "get_iocs", "days": days}, timeout=90)
        r.raise_for_status()
        data = r.json().get("data", []) or []
    except (requests.RequestException, ValueError) as e:
        print(f"[feeds] ThreatFox fetch failed: {e}")
        return {"error": str(e)}
    hashes, ips = set(), set()
    for it in data:
        t, v = it.get("ioc_type", ""), (it.get("ioc", "") or "").strip()
        if t == "sha256_hash" and len(v) == 64:
            hashes.add(v.lower())
        elif t in ("ip:port", "ip"):
            ip = v.rsplit(":", 1)[0].strip()
            if len(ip.split(".")) == 4 and all(
                    p.isdigit() and 0 <= int(p) <= 255 for p in ip.split(".")):
                ips.add(ip)
    THREATFOX_IPS.write_text("\n".join(sorted(ips)), encoding="utf-8")
    total = _merge_hashes(hashes)
    state = _load_state()
    state["threatfox_updated_at"] = time.time()
    state["threatfox_ip_count"] = len(ips)
    _save_state(state)
    print(f"[feeds] ThreatFox: +{len(hashes)} hashes, {len(ips)} C2 IPs")
    return {"hashes_added": len(hashes), "ips": len(ips), "hash_total": total}


def update_urlhaus() -> dict:
    """Pull recent URLhaus malware payloads (SHA-256) into the hash blocklist."""
    if not keystore.get("abuse_ch"):
        return {"error": "no abuse.ch Auth-Key"}
    try:
        r = requests.get(URLHAUS_PAYLOADS, headers=_headers(), timeout=90)
        r.raise_for_status()
        payloads = r.json().get("payloads", []) or []
    except (requests.RequestException, ValueError) as e:
        print(f"[feeds] URLhaus fetch failed: {e}")
        return {"error": str(e)}
    hashes = {p.get("sha256_hash", "").lower() for p in payloads
              if p.get("sha256_hash")}
    total = _merge_hashes(hashes)
    state = _load_state()
    state["urlhaus_updated_at"] = time.time()
    _save_state(state)
    print(f"[feeds] URLhaus: +{len(hashes)} payload hashes")
    return {"hashes_added": len(hashes), "hash_total": total}


def update_malpedia_yara() -> dict:
    """Fetch Malpedia YARA rules with the user's *own* key into data/yara/malpedia/.

    Respects TLP: the rules land only on this machine and are .gitignore'd — never
    bundled or redistributed. Implemented against Malpedia's documented API; if the
    response shape differs it fails gracefully rather than corrupting anything.
    """
    import base64

    key = keystore.get("malpedia")
    if not key:
        return {"error": "no Malpedia key"}
    try:
        r = requests.get(MALPEDIA_YARA, headers={"Authorization": f"apitoken {key}"},
                         timeout=120)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[feeds] Malpedia fetch failed: {e}")
        return {"error": str(e)}

    out_dir = YARA_DIR / "malpedia"
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    def _write(name: str, content: str) -> None:
        nonlocal count
        text = content
        try:                      # some entries are base64-encoded
            decoded = base64.b64decode(content, validate=True).decode("utf-8", "ignore")
            if "rule " in decoded:
                text = decoded
        except Exception:
            pass
        if "rule " not in text:
            return
        fname = Path(name).name
        if not fname.endswith((".yar", ".yara")):
            fname += ".yar"
        (out_dir / fname).write_text(text, encoding="utf-8", errors="ignore")
        count += 1

    if isinstance(data, dict):
        for k, v in data.items():               # tlp-keyed or filename-keyed
            if isinstance(v, dict):
                for name, content in v.items():
                    if isinstance(content, str):
                        _write(name, content)
            elif isinstance(v, str):
                _write(k, v)

    state = _load_state()
    state["malpedia_updated_at"] = time.time()
    state["malpedia_rule_count"] = count
    _save_state(state)
    print(f"[feeds] Malpedia: {count} YARA rules")
    return {"rules": count}


def signatures_age(clam_version: str = "unknown") -> float | None:
    """Best-effort age of the ClamAV signature DB from the daily.cvd/.cld mtime.

    Checks (in order) an explicit override, the engine's own bundled clamd DB,
    then the usual system locations — and returns the *freshest* it finds."""
    candidates: list[Path] = []
    env = os.environ.get("EYIL_CLAM_DB_DIR")
    if env:
        candidates += [Path(env) / "daily.cvd", Path(env) / "daily.cld"]
    local = DATA / "clam" / "db"     # see data/clam/clamd.conf
    candidates += [local / "daily.cvd", local / "daily.cld"]
    candidates += [Path("/var/lib/clamav/daily.cvd"), Path("/var/lib/clamav/daily.cld"),
                   Path(r"C:\Program Files\ClamAV\database\daily.cvd"),
                   Path(r"C:\ProgramData\ClamAV\database\daily.cvd")]
    newest: float | None = None
    for p in candidates:
        try:
            if p.exists():
                age = time.time() - p.stat().st_mtime
                newest = age if newest is None else min(newest, age)
        except OSError:
            pass
    return newest


def health(clam_version: str = "unknown", hash_count: int = 0):
    """Assemble an update-health snapshot for the API."""
    from .models import Health
    state = _load_state()
    sig_age = signatures_age(clam_version)
    feed_age = (time.time() - state["feeds_updated_at"]
                if "feeds_updated_at" in state else None)
    sig_stale = sig_age is None or sig_age > STALE_SIGNATURES
    feed_stale = feed_age is None or feed_age > STALE_FEEDS
    return Health(
        clam_version=clam_version,
        signatures_age_seconds=sig_age,
        feeds_age_seconds=feed_age,
        signatures_stale=sig_stale,
        feeds_stale=feed_stale,
        hash_feed_count=hash_count or state.get("hash_count", 0),
        c2_count=state.get("c2_count", 0) + state.get("threatfox_ip_count", 0),
        ok=not (sig_stale or feed_stale),
    )


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true", help="fetch the recent feed")
    ap.add_argument("--full", action="store_true", help="fetch the full (large) feed")
    args = ap.parse_args()
    if args.update or args.full:
        update(full=args.full)
    else:
        print(health())
