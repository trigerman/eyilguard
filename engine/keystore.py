"""Bring-your-own-key store (BYOK).

User-supplied API keys live in data/keys.json on the user's own machine and are
NEVER bundled or committed (see .gitignore). The API only ever exposes a *masked*
status (e.g. "8cce…3981") — never the secret itself.

This is what makes restricted feeds license-clean: Eyil ships only code; the
user brings their own credentials, and the data those keys fetch stays local.
An environment variable (e.g. ABUSE_CH_KEY) overrides the stored value.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
KEYS_FILE = DATA / "keys.json"
LEGACY_ABUSE = DATA / "abuse_ch_key.txt"

# Services Eyil can hold a key for. VirusTotal is intentionally NOT here — its
# terms forbid API use in an antivirus product even with your own key, so it's
# offered only as a manual "look up on virustotal.com" link, never a key field.
SERVICES = ("abuse_ch", "malpedia")


def _load() -> dict:
    data: dict = {}
    if KEYS_FILE.exists():
        try:
            data = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    # one-time migration of the standalone abuse.ch key file
    if "abuse_ch" not in data and LEGACY_ABUSE.exists():
        try:
            k = LEGACY_ABUSE.read_text(encoding="utf-8").strip()
            if k:
                data["abuse_ch"] = k
        except OSError:
            pass
    return data


def get(service: str) -> str:
    env = os.environ.get(service.upper() + "_KEY") or os.environ.get(service.upper())
    if env:
        return env.strip()
    return (_load().get(service) or "").strip()


def set_key(service: str, key: str) -> None:
    if service not in SERVICES:
        raise ValueError(f"unknown service {service!r}")
    DATA.mkdir(parents=True, exist_ok=True)
    data = _load()
    if key and key.strip():
        data[service] = key.strip()
    else:
        data.pop(service, None)
    KEYS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _mask(k: str) -> str:
    if not k:
        return ""
    if len(k) <= 8:
        return "•" * len(k)
    return f"{k[:4]}…{k[-4:]}"


def status() -> dict:
    """Per-service {set, masked} — safe to send to the dashboard."""
    return {s: {"set": bool(get(s)), "masked": _mask(get(s))} for s in SERVICES}
