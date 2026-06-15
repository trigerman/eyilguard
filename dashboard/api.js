/* Eyil dashboard <-> engine adapter.
 *
 * Maps the engine's live shapes (MonitoredObject / Health from engine/models.py)
 * into what the UI renders, and exposes useEngine() — a hook that loads
 * GET /objects + GET /health and follows the WS /stream for live verdicts.
 *
 * HONESTY RULE (internal notes #4): fields the engine does not (yet) track —
 * file size, cpu/mem, signer details, blocked/allowed network status — are
 * rendered as "—" or "monitored", never fabricated. We only show what's real.
 */

import { useCallback, useEffect, useRef, useState } from "react";

const ENGINE =
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_ENGINE_URL) ||
  ""; // "" => same origin (the engine serves the UI in the packaged product)

const httpBase = ENGINE || "";
const wsBase = (() => {
  const origin =
    ENGINE ||
    (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8787");
  return origin.replace(/^http/, "ws");
})();

/* ----------------------------- formatting ------------------------------ */

export function humanizeAge(seconds) {
  if (seconds == null) return "unknown";
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function fmtTime(ts) {
  if (ts == null) return "";
  try {
    return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
  } catch {
    return String(ts);
  }
}

function fmtFull(ts) {
  if (ts == null) return "—";
  try {
    return new Date(ts * 1000).toLocaleString([], { hour12: false });
  } catch {
    return "—";
  }
}

function fmtBytes(bytes) {
  if (bytes == null || Number.isNaN(Number(bytes))) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || value >= 10 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

function baseName(p = "") {
  return (p || "").replace(/\//g, "\\").split("\\").filter(Boolean).pop() || "";
}

/* --------------------------- field derivation -------------------------- */

const OP_LVL = {
  ENCRYPT: "crit",
  DELETE: "crit",
  WRITE: "warn",
  EXECUTE: "info",
  CONNECT: "info",
  READ: "info",
};

function kindFromPath(p = "") {
  const ext = (p.split(".").pop() || "").toLowerCase();
  if (["exe", "dll", "scr", "com", "bat", "cmd", "ps1", "msi"].includes(ext)) return "Executable";
  if (["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf"].includes(ext)) return "Document";
  if (["jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"].includes(ext)) return "Image";
  if (["zip", "rar", "7z", "tar", "gz"].includes(ext)) return "Archive";
  return "Unknown";
}

function folderStory(p = "") {
  const low = p.toLowerCase();
  if (low.includes("\\downloads\\") || low.includes("/downloads/")) return "Arrived in your Downloads folder";
  if (low.includes("\\documents\\") || low.includes("/documents/")) return "Lives in your Documents folder";
  if (low.includes("\\pictures\\") || low.includes("/pictures/")) return "Lives in your Pictures folder";
  if (low.includes("\\desktop\\") || low.includes("/desktop/")) return "Sits on your Desktop";
  if (low.includes("\\windows defender\\")) return "Part of Windows Defender";
  if (low.includes("temp") || low.includes("/tmp/")) return "Lives in a temporary folder";
  if (low.includes("system32") || low.includes("\\windows\\")) return "Lives in a Windows system folder";
  if (low.includes("\\program files")) return "Installed under Program Files";
  if (low.includes("\\programdata\\")) return "Lives in a shared app-data folder";
  // Otherwise name the nearest meaningful folder, skipping version-number dirs
  // (e.g. "...\\Platform\\4.18.26050.15-0\\x.exe" -> "Platform", not the version).
  const parts = p.replace(/\//g, "\\").split("\\").filter(Boolean);
  parts.pop(); // drop the filename
  while (parts.length && /^[\d._-]+$/.test(parts[parts.length - 1])) parts.pop();
  if (parts.length) return `Lives in the ${parts[parts.length - 1]} folder`;
  return "Location not known yet";
}

function parseNet(net = []) {
  return net.map((n) => {
    const target = (n.target || n.ip || "").toString();
    const i = target.lastIndexOf(":");
    const ip = i > 0 ? target.slice(0, i) : target;
    const port = i > 0 ? target.slice(i + 1) : "";
    // The engine doesn't yet record direction or block status, so we say
    // "monitored" rather than claiming we allowed or blocked it.
    return { dir: "OUT", ip: ip || "—", port: port || "—", host: "unverified", status: "monitored" };
  });
}

/** Map one engine MonitoredObject into the dashboard's display shape. */
export function mapObject(o) {
  const v = o.verdict || {};
  const ops = (o.ops || []).filter((x) => x && x.op);
  const net = parseNet(o.net);
  const logs = (o.logs || []).map((l) => ({
    ts: fmtTime(l.ts),
    lvl: OP_LVL[l.op] || "info",
    msg: `${l.op || "EVENT"} ${l.path || ""}`.trim(),
  }));
  const self = (o.name || baseName(o.path) || "").toLowerCase();
  const opens = [...new Set(ops.map((x) => baseName(x.path)).filter(Boolean))]
    .filter((n) => n.toLowerCase() !== self) // don't list the program as "opening" itself
    .slice(0, 6);

  return {
    id: o.id || String(o.pid ?? o.name),
    name: o.name || baseName(o.path) || "unknown",
    state: v.severity || "safe",
    status: o.status || "active", // active | allowed | quarantined
    pid: o.pid,
    // simple view — derived honestly from real fields
    home: folderStory(o.path),
    uses: net.length ? "Connects to the internet" : "Hasn't used the internet",
    opens: opens.length ? opens : ["Nothing — just runs on its own"],
    talks: net.length ? net.map((n) => `${n.ip}:${n.port}`) : ["No outside connections"],
    could:
      v.why ||
      (v.severity === "safe"
        ? "Nothing unusual. This one's behaving exactly as expected."
        : "Under review."),
    confidence: v.confidence,
    findings: v.findings || [],
    // technical view — real where known, "—" where the engine can't say yet
    tech: {
      path: o.path || "—",
      kind: kindFromPath(o.path),
      pid: o.pid ?? "—",
      parent: o.parent || "—",
      signer: o.signer || "unknown",
      size: fmtBytes(o.size_bytes),
      seen: o.logs && o.logs.length ? fmtFull(o.logs[0].ts) : "—",
      sha256: o.sha256 || "—",
      res: { cpu: "—", mem: "—", disk: "—" }, // not tracked yet
      ops,
      net,
      services: o.services || [],
      logs,
    },
  };
}

/** BYOK: which services have a key set (masked status, never the secret). */
export async function getKeys() {
  const r = await fetch(`${httpBase}/keys`);
  if (!r.ok) throw new Error(`/keys ${r.status}`);
  return r.json();
}

/** Store (or, with an empty key, remove) a user-supplied API key. */
export async function saveKey(service, key) {
  const r = await fetch(`${httpBase}/keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ service, key }),
  });
  if (!r.ok) throw new Error(`/keys ${r.status}`);
  return r.json();
}

/** List identities the user allowed and Eyil is hiding from the dashboard. */
export async function getAllowlist() {
  const r = await fetch(`${httpBase}/allowlist`);
  if (!r.ok) throw new Error(`/allowlist ${r.status}`);
  return r.json();
}

/** Remove one allowlisted identity so future detections can appear again. */
export async function removeAllowlist(key) {
  const r = await fetch(`${httpBase}/allowlist/remove`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key }),
  });
  if (!r.ok) throw new Error(`/allowlist/remove ${r.status}`);
  return r.json();
}

/* ---------- custom YARA rules (write your own) ---------- */
async function _yaraPost(endpoint, body) {
  const r = await fetch(`${httpBase}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${endpoint} ${r.status}`);
  return r.json();
}
/** Compile-check a YARA rule without saving. */
export const validateYara = (rule) => _yaraPost("/yara/validate", { rule });
/** Compile a rule and test it against one file path. */
export const testYara = (rule, path) => _yaraPost("/yara/test", { rule, path });
/** Validate + save a custom rule, then reload the engine. */
export const saveYara = (name, rule) => _yaraPost("/yara/save", { name, rule });
/** Remove a saved custom rule. */
export const removeCustomYara = (name) => _yaraPost("/yara/custom/remove", { name });
/** List the user's saved custom rules. */
export async function listCustomYara() {
  const r = await fetch(`${httpBase}/yara/custom`);
  if (!r.ok) throw new Error(`/yara/custom ${r.status}`);
  return r.json();
}

/** Scan the watched folders on demand (catches files already on disk). */
export async function rescanNow() {
  const r = await fetch(`${httpBase}/rescan`, { method: "POST" });
  if (!r.ok) throw new Error(`/rescan ${r.status}`);
  return r.json();
}

/** Force a signature + threat-feed refresh now. Returns the updated health. */
export async function checkForUpdates() {
  const r = await fetch(`${httpBase}/update`, { method: "POST" });
  if (!r.ok) throw new Error(`/update ${r.status}`);
  return r.json();
}

/** Remove Eyil Guard from this machine (autostart + shortcut + logs), then the
    listener stops. Source files and your data are left in place. */
export async function uninstallApp() {
  const r = await fetch(`${httpBase}/uninstall`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true }),
  });
  if (!r.ok) throw new Error(`/uninstall ${r.status}`);
  return r.json();
}

/** Apply a user decision (allow | quarantine) to a monitored object by pid. */
export async function sendAction(pid, action) {
  const r = await fetch(`${httpBase}/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pid, action }),
  });
  if (!r.ok) throw new Error(`/action ${r.status}`);
  return r.json();
}

/* ------------------------------- the hook ------------------------------ */

/**
 * useEngine(enabled) — returns { files, health, connected }.
 * When the engine is unreachable, connected=false and files=[]; the UI then
 * falls back to clearly-labelled demo data rather than pretending it's live.
 */
export function useEngine(enabled = true) {
  const [files, setFiles] = useState([]);
  const [health, setHealth] = useState(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const retryRef = useRef(null);
  const aliveRef = useRef(true);

  const loadObjects = useCallback(async () => {
    const r = await fetch(`${httpBase}/objects`);
    if (!r.ok) throw new Error(`/objects ${r.status}`);
    const data = await r.json();
    setFiles(data.map(mapObject));
  }, []);

  const loadHealth = useCallback(async () => {
    const r = await fetch(`${httpBase}/health`);
    if (!r.ok) throw new Error(`/health ${r.status}`);
    setHealth(await r.json());
  }, []);

  useEffect(() => {
    if (!enabled) return undefined;
    aliveRef.current = true;
    let healthTimer = null;

    const scheduleRetry = () => {
      if (retryRef.current) return;
      retryRef.current = setTimeout(() => {
        retryRef.current = null;
        if (aliveRef.current) {
          bootstrap();
          openWs();
        }
      }, 3000);
    };

    const bootstrap = async () => {
      try {
        await Promise.all([loadObjects(), loadHealth()]);
        if (aliveRef.current) setConnected(true);
      } catch {
        if (aliveRef.current) {
          setConnected(false);
          scheduleRetry();
        }
      }
    };

    const openWs = () => {
      try {
        const ws = new WebSocket(`${wsBase}/stream`);
        wsRef.current = ws;
        ws.onopen = () => aliveRef.current && setConnected(true);
        ws.onmessage = (ev) => {
          let m;
          try {
            m = JSON.parse(ev.data);
          } catch {
            return;
          }
          if ((m.type === "hello" || m.type === "health") && m.health) setHealth(m.health);
          if (m.type === "verdict" || m.type === "objects_changed") {
            loadObjects().catch(() => {});
            loadHealth().catch(() => {});
          }
        };
        ws.onclose = () => {
          if (aliveRef.current) {
            setConnected(false);
            scheduleRetry();
          }
        };
        ws.onerror = () => {
          try {
            ws.close();
          } catch {}
        };
      } catch {
        scheduleRetry();
      }
    };

    bootstrap();
    openWs();
    healthTimer = setInterval(() => loadHealth().catch(() => {}), 60000);

    return () => {
      aliveRef.current = false;
      if (healthTimer) clearInterval(healthTimer);
      if (retryRef.current) {
        clearTimeout(retryRef.current);
        retryRef.current = null;
      }
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {}
      }
    };
  }, [enabled, loadObjects, loadHealth]);

  return { files, health, connected };
}
