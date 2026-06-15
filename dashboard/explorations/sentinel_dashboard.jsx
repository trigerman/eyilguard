import React, { useState, useEffect, useRef } from "react";

/* ------------------------------------------------------------------ *
 * Sentinel — endpoint activity console
 * Shows, per process, which files and services it is touching, with a
 * live access map. Mock data here mirrors the shape your real telemetry
 * (minifilter + ETW/Sysmon) would produce, so this UI can be wired to a
 * real feed later without changing the layout.
 * ------------------------------------------------------------------ */

const C = {
  ink: "#0E1419",
  panel: "#161D24",
  panel2: "#1B232B",
  line: "#243038",
  text: "#DCE3E8",
  muted: "#6B7B86",
  faint: "#3F4D57",
  signal: "#4FD1C5", // live / active
  clean: "#7FB069",
  watch: "#E0A458",
  block: "#E06C75",
};

const RISK = {
  clean: { c: C.clean, label: "clean" },
  watch: { c: C.watch, label: "watch" },
  blocked: { c: C.block, label: "blocked" },
};

const PROCESSES = [
  {
    id: "p1", name: "chrome.exe", pid: 8124, risk: "clean", cpu: 4.2,
    path: "C:\\Program Files\\Google\\Chrome\\chrome.exe",
    files: [
      { name: "Cookies", op: "read", risk: "clean" },
      { name: "History", op: "write", risk: "clean" },
      { name: "Cache\\data_1", op: "write", risk: "clean" },
      { name: "Preferences", op: "read", risk: "clean" },
    ],
    services: [
      { name: "Cryptographic Services", risk: "clean" },
      { name: "DNS Client", risk: "clean" },
      { name: "Network Connections", risk: "clean" },
    ],
  },
  {
    id: "p2", name: "svchost.exe", pid: 1044, risk: "clean", cpu: 0.8,
    path: "C:\\Windows\\System32\\svchost.exe",
    files: [
      { name: "SOFTWARE hive", op: "read", risk: "clean" },
      { name: "evtx\\System.evtx", op: "write", risk: "clean" },
    ],
    services: [
      { name: "Windows Update", risk: "clean" },
      { name: "Background Tasks", risk: "clean" },
      { name: "DCOM Server", risk: "clean" },
    ],
  },
  {
    id: "p3", name: "invoice_2026_04.pdf.exe", pid: 6691, risk: "blocked", cpu: 71.5,
    path: "C:\\Users\\you\\Downloads\\invoice_2026_04.pdf.exe",
    note: "Double extension. Mass file writes + shadow-copy access = ransomware pattern.",
    files: [
      { name: "Documents\\taxes.xlsx", op: "encrypt", risk: "blocked" },
      { name: "Documents\\resume.docx", op: "encrypt", risk: "blocked" },
      { name: "Pictures\\*.jpg (312)", op: "encrypt", risk: "blocked" },
      { name: "Desktop\\READ_ME.txt", op: "write", risk: "blocked" },
    ],
    services: [
      { name: "Volume Shadow Copy", risk: "blocked" },
      { name: "Network Connections", risk: "watch" },
    ],
  },
  {
    id: "p4", name: "updater.tmp", pid: 4502, risk: "watch", cpu: 12.1,
    path: "C:\\Users\\you\\AppData\\Local\\Temp\\updater.tmp",
    note: "Unsigned binary in Temp reading another process's memory.",
    files: [
      { name: "Temp\\updater.tmp", op: "execute", risk: "watch" },
      { name: "System32\\config", op: "read", risk: "watch" },
    ],
    services: [
      { name: "Remote Procedure Call", risk: "watch" },
      { name: "Task Scheduler", risk: "watch" },
    ],
  },
  {
    id: "p5", name: "explorer.exe", pid: 3320, risk: "clean", cpu: 1.4,
    path: "C:\\Windows\\explorer.exe",
    files: [
      { name: "Desktop\\", op: "read", risk: "clean" },
      { name: "thumbcache.db", op: "write", risk: "clean" },
    ],
    services: [
      { name: "Shell Hardware Detection", risk: "clean" },
      { name: "Themes", risk: "clean" },
    ],
  },
];

const OPS = {
  read: "R", write: "W", execute: "X", encrypt: "ENC",
};

function StatusDot({ risk, size = 8, pulse }) {
  return (
    <span
      className={pulse ? "sentinel-pulse" : ""}
      style={{
        width: size, height: size, borderRadius: 99, background: RISK[risk].c,
        display: "inline-block", flexShrink: 0,
        boxShadow: `0 0 0 0 ${RISK[risk].c}`,
      }}
    />
  );
}

/* The signature element: a process at center with arcs out to the files
 * (left) and services (right) it is touching. */
function AccessMap({ proc }) {
  const W = 560, H = 360, cx = W / 2, cy = H / 2;
  const files = proc.files.slice(0, 5);
  const services = proc.services.slice(0, 5);

  const place = (items, side) => {
    const n = items.length;
    return items.map((it, i) => {
      const t = n === 1 ? 0.5 : i / (n - 1);
      const y = 50 + t * (H - 100);
      const x = side === "left" ? 70 : W - 70;
      return { ...it, x, y };
    });
  };
  const fNodes = place(files, "left");
  const sNodes = place(services, "right");

  const edge = (n, fromLeft) => {
    const midX = fromLeft ? (n.x + cx) / 2 : (cx + n.x) / 2;
    return `M ${n.x} ${n.y} C ${midX} ${n.y}, ${midX} ${cy}, ${cx} ${cy}`;
  };

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto" }}>
      <text x={70} y={32} fill={C.muted} fontSize="10"
        fontFamily="ui-monospace, Menlo, monospace" letterSpacing="1.5"
        textAnchor="middle">FILES</text>
      <text x={W - 70} y={32} fill={C.muted} fontSize="10"
        fontFamily="ui-monospace, Menlo, monospace" letterSpacing="1.5"
        textAnchor="middle">SERVICES</text>

      {[...fNodes.map((n) => ["l", n]), ...sNodes.map((n) => ["r", n])].map(
        ([side, n], i) => (
          <path key={"e" + i} d={edge(n, side === "l")} fill="none"
            stroke={RISK[n.risk].c}
            strokeOpacity={n.risk === "clean" ? 0.28 : 0.7}
            strokeWidth={n.risk === "clean" ? 1 : 1.6}
            className="sentinel-edge"
            style={{ strokeDasharray: n.risk === "blocked" ? "4 3" : "none" }} />
        )
      )}

      {/* center process node */}
      <circle cx={cx} cy={cy} r={34} fill={C.panel2}
        stroke={RISK[proc.risk].c} strokeWidth={2} />
      <circle cx={cx} cy={cy} r={34} fill="none"
        stroke={RISK[proc.risk].c} strokeWidth={2} opacity={0.4}
        className="sentinel-ring" />
      <text x={cx} y={cy - 2} fill={C.text} fontSize="11" textAnchor="middle"
        fontFamily="ui-monospace, Menlo, monospace">PID</text>
      <text x={cx} y={cy + 12} fill={RISK[proc.risk].c} fontSize="12"
        textAnchor="middle" fontFamily="ui-monospace, Menlo, monospace">
        {proc.pid}</text>

      {fNodes.map((n, i) => (
        <g key={"f" + i}>
          <circle cx={n.x} cy={n.y} r={5} fill={RISK[n.risk].c} />
          <text x={n.x - 12} y={n.y + 4} fill={C.text} fontSize="10.5"
            textAnchor="end" fontFamily="ui-monospace, Menlo, monospace">
            {n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name}</text>
        </g>
      ))}
      {sNodes.map((n, i) => (
        <g key={"s" + i}>
          <circle cx={n.x} cy={n.y} r={5} fill={RISK[n.risk].c} />
          <text x={n.x + 12} y={n.y + 4} fill={C.text} fontSize="10.5"
            textAnchor="start" fontFamily="ui-monospace, Menlo, monospace">
            {n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name}</text>
        </g>
      ))}
    </svg>
  );
}

function AccessRow({ item, kind }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10, padding: "7px 10px",
      borderBottom: `1px solid ${C.line}`,
    }}>
      <StatusDot risk={item.risk} size={7} />
      <span style={{
        fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12.5,
        color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}>{item.name}</span>
      {kind === "file" && (
        <span style={{
          fontFamily: "ui-monospace, Menlo, monospace", fontSize: 10,
          color: item.risk === "blocked" ? C.block : C.muted,
          border: `1px solid ${item.risk === "blocked" ? C.block : C.faint}`,
          borderRadius: 3, padding: "1px 5px", letterSpacing: 0.5,
        }}>{OPS[item.op]}</span>
      )}
    </div>
  );
}

export default function App() {
  const [selId, setSelId] = useState("p3");
  const [feed, setFeed] = useState([]);
  const [live, setLive] = useState(true);
  const seq = useRef(0);
  const sel = PROCESSES.find((p) => p.id === selId);

  useEffect(() => {
    if (!live) return;
    const verbs = ["opened", "read", "wrote", "queried", "executed", "blocked"];
    const id = setInterval(() => {
      const p = PROCESSES[Math.floor(Math.random() * PROCESSES.length)];
      const pool = [...p.files.map((f) => f.name), ...p.services.map((s) => s.name)];
      const target = pool[Math.floor(Math.random() * pool.length)];
      const risk = p.risk;
      const v = risk === "blocked" ? "blocked" : verbs[Math.floor(Math.random() * 5)];
      seq.current += 1;
      const t = new Date();
      setFeed((f) => [{
        k: seq.current,
        ts: t.toTimeString().slice(0, 8),
        proc: p.name, verb: v, target, risk,
      }, ...f].slice(0, 40));
    }, 1100);
    return () => clearInterval(id);
  }, [live]);

  const counts = PROCESSES.reduce((a, p) => (a[p.risk]++, a),
    { clean: 0, watch: 0, blocked: 0 });

  return (
    <div style={{
      background: C.ink, color: C.text, minHeight: "100vh",
      fontFamily: "system-ui, -apple-system, sans-serif", padding: 18,
    }}>
      <style>{`
        @keyframes sentinelPulse {
          0%   { box-shadow: 0 0 0 0 ${C.signal}66; }
          70%  { box-shadow: 0 0 0 6px ${C.signal}00; }
          100% { box-shadow: 0 0 0 0 ${C.signal}00; }
        }
        .sentinel-pulse { animation: sentinelPulse 1.8s infinite; }
        @keyframes sentinelRing { 0%{ r:34; opacity:.4 } 100%{ r:46; opacity:0 } }
        .sentinel-ring { animation: sentinelRing 2.4s ease-out infinite; }
        @keyframes feedIn { from{ opacity:0; transform: translateY(-4px) } to{ opacity:1; transform:none } }
        .feed-row { animation: feedIn .3s ease both; }
        .proc-row { cursor:pointer; transition: background .12s; }
        .proc-row:hover { background:${C.panel2} !important; }
        .seg-btn { cursor:pointer; }
        @media (prefers-reduced-motion: reduce){
          .sentinel-pulse,.sentinel-ring,.feed-row{ animation:none !important }
        }
      `}</style>

      {/* header / instrument bar */}
      <div style={{
        display: "flex", alignItems: "center", gap: 18, flexWrap: "wrap",
        paddingBottom: 14, borderBottom: `1px solid ${C.line}`, marginBottom: 16,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <StatusDot risk="clean" size={9} pulse />
          <span style={{ fontWeight: 600, letterSpacing: 0.5, fontSize: 15 }}>
            SENTINEL</span>
          <span style={{
            fontFamily: "ui-monospace, Menlo, monospace", fontSize: 11,
            color: C.muted,
          }}>endpoint console</span>
        </div>
        <div style={{ flex: 1 }} />
        {[
          ["processes", PROCESSES.length, C.text],
          ["clean", counts.clean, C.clean],
          ["watch", counts.watch, C.watch],
          ["blocked", counts.blocked, C.block],
        ].map(([label, val, col]) => (
          <div key={label} style={{ textAlign: "right" }}>
            <div style={{
              fontFamily: "ui-monospace, Menlo, monospace", fontSize: 19,
              color: col, lineHeight: 1,
            }}>{val}</div>
            <div style={{ fontSize: 10, color: C.muted, letterSpacing: 1 }}>
              {label.toUpperCase()}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr 300px", gap: 16 }}>
        {/* process list */}
        <div style={{
          background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8,
          overflow: "hidden", alignSelf: "start",
        }}>
          <div style={{
            padding: "10px 12px", fontSize: 10, letterSpacing: 1.5,
            color: C.muted, borderBottom: `1px solid ${C.line}`,
          }}>RUNNING PROCESSES</div>
          {PROCESSES.map((p) => (
            <div key={p.id} className="proc-row" onClick={() => setSelId(p.id)}
              style={{
                display: "flex", alignItems: "center", gap: 9, padding: "10px 12px",
                borderBottom: `1px solid ${C.line}`,
                background: p.id === selId ? C.panel2 : "transparent",
                borderLeft: `2px solid ${p.id === selId ? RISK[p.risk].c : "transparent"}`,
              }}>
              <StatusDot risk={p.risk} pulse={p.risk === "blocked"} />
              <div style={{ flex: 1, overflow: "hidden" }}>
                <div style={{
                  fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12.5,
                  color: C.text, overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}>{p.name}</div>
                <div style={{ fontSize: 10.5, color: C.muted }}>
                  pid {p.pid} · {p.cpu}% cpu</div>
              </div>
            </div>
          ))}
        </div>

        {/* center: access map + detail */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{
            background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8,
            padding: 16,
          }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 4 }}>
              <span style={{
                fontFamily: "ui-monospace, Menlo, monospace", fontSize: 15,
                color: RISK[sel.risk].c,
              }}>{sel.name}</span>
              <span style={{
                fontSize: 10, letterSpacing: 1, color: RISK[sel.risk].c,
                border: `1px solid ${RISK[sel.risk].c}`, borderRadius: 3,
                padding: "1px 6px",
              }}>{RISK[sel.risk].label.toUpperCase()}</span>
            </div>
            <div style={{
              fontFamily: "ui-monospace, Menlo, monospace", fontSize: 11,
              color: C.muted, marginBottom: 8, wordBreak: "break-all",
            }}>{sel.path}</div>
            {sel.note && (
              <div style={{
                fontSize: 12, color: C.text, background: `${RISK[sel.risk].c}1A`,
                borderLeft: `2px solid ${RISK[sel.risk].c}`, padding: "7px 10px",
                borderRadius: 4, marginBottom: 6,
              }}>{sel.note}</div>
            )}
            <AccessMap proc={sel} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8 }}>
              <div style={{ padding: "10px 12px", fontSize: 10, letterSpacing: 1.5, color: C.muted, borderBottom: `1px solid ${C.line}` }}>
                FILES TOUCHED · {sel.files.length}</div>
              {sel.files.map((f, i) => <AccessRow key={i} item={f} kind="file" />)}
            </div>
            <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8 }}>
              <div style={{ padding: "10px 12px", fontSize: 10, letterSpacing: 1.5, color: C.muted, borderBottom: `1px solid ${C.line}` }}>
                SERVICES ACCESSED · {sel.services.length}</div>
              {sel.services.map((s, i) => <AccessRow key={i} item={s} kind="svc" />)}
            </div>
          </div>
        </div>

        {/* live feed */}
        <div style={{
          background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8,
          alignSelf: "start", maxHeight: 640, display: "flex", flexDirection: "column",
        }}>
          <div style={{
            padding: "10px 12px", display: "flex", alignItems: "center", gap: 8,
            borderBottom: `1px solid ${C.line}`,
          }}>
            <StatusDot risk={live ? "clean" : "watch"} pulse={live} />
            <span style={{ fontSize: 10, letterSpacing: 1.5, color: C.muted, flex: 1 }}>
              LIVE ACTIVITY</span>
            <span className="seg-btn" onClick={() => setLive((v) => !v)}
              style={{
                fontSize: 10, letterSpacing: 1, color: C.signal,
                border: `1px solid ${C.faint}`, borderRadius: 3, padding: "2px 8px",
              }}>{live ? "PAUSE" : "RESUME"}</span>
          </div>
          <div style={{ overflowY: "auto" }}>
            {feed.length === 0 && (
              <div style={{ padding: 16, fontSize: 12, color: C.muted }}>
                Listening for file and service events…</div>
            )}
            {feed.map((e) => (
              <div key={e.k} className="feed-row" style={{
                padding: "7px 12px", borderBottom: `1px solid ${C.line}`,
                fontFamily: "ui-monospace, Menlo, monospace", fontSize: 11,
                display: "flex", gap: 7, alignItems: "baseline",
              }}>
                <span style={{ color: C.faint }}>{e.ts}</span>
                <span style={{ color: RISK[e.risk].c }}>{e.proc}</span>
                <span style={{ color: C.muted }}>{e.verb}</span>
                <span style={{ color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {e.target}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
