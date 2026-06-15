import React, { useState, useEffect } from "react";
import { AlertOctagon, AlertTriangle, CheckCircle2, ShieldX, Search,
  XCircle, Cpu, HardDrive, Globe, FileWarning, Cog, MapPin, Activity } from "lucide-react";

/* Triage console.
 * Layout follows the SOC workflow (triage -> investigate -> respond) and a
 * strict three-tier severity hierarchy. Color is reserved for severity only;
 * every severity also carries an icon + text label so it never depends on
 * color alone. Deep-grey dark theme for long monitoring shifts. */

const c = {
  bg: "#14161B", panel: "#1B1E25", raise: "#21252E", row: "#1F232B",
  line: "#2A2F3A", text: "#E4E7EC", mute: "#8A93A2", dim: "#5C6573",
  // severity — the ONLY semantic colors
  crit: "#F0544F", warn: "#E8A33D", ok: "#4FB477",
  // interactive (deliberately not a severity color)
  act: "#6E8FCB",
};

const SEV = {
  critical: { col: c.crit, label: "CRITICAL", Icon: AlertOctagon },
  elevated: { col: c.warn, label: "ELEVATED", Icon: AlertTriangle },
  routine:  { col: c.ok,   label: "ROUTINE",  Icon: CheckCircle2 },
};

const ALERTS = [
  {
    id: "a1", sev: "critical", status: "active", confidence: 98,
    title: "Ransomware behavior — mass file encryption",
    process: "invoice_2026_04.pdf.exe", pid: 6691, time: "11:42:07",
    why: "A file disguised as a PDF is encrypting personal documents and deleting Volume Shadow Copies (backups). This is the signature behavior of a ransomware payload mid-execution.",
    runsFrom: "C:\\Users\\you\\Downloads\\",
    res: { cpu: "72%", disk: "high write", net: "active" },
    files: { summary: "312 files encrypted", items: ["Documents\\*.docx, *.xlsx", "Pictures\\*.jpg", "Desktop\\READ_ME.txt (created)"] },
    services: ["Volume Shadow Copy (backup deletion)", "Network Connections"],
    net: "Outbound to 185.234.x.x (flagged)",
  },
  {
    id: "a2", sev: "elevated", status: "active", confidence: 74,
    title: "Unsigned binary reading system files",
    process: "updater.tmp", pid: 4502, time: "11:39:51",
    why: "An unsigned executable running from a temp folder is reading protected system configuration. Could be a legitimate updater, but the location and behavior are unusual.",
    runsFrom: "C:\\Users\\you\\AppData\\Local\\Temp\\",
    res: { cpu: "12%", disk: "low", net: "active" },
    files: { summary: "2 sensitive reads", items: ["System32\\config (registry hive)", "Temp\\updater.tmp"] },
    services: ["Remote Procedure Call", "Task Scheduler"],
    net: "Outbound to 52.18.x.x (unverified)",
  },
  {
    id: "a3", sev: "elevated", status: "active", confidence: 61,
    title: "Office macro spawned PowerShell",
    process: "powershell.exe", pid: 7720, time: "11:35:18",
    why: "Word launched a hidden PowerShell process. Document macros spawning shells is a common initial-access technique, though some enterprise templates do it legitimately.",
    runsFrom: "C:\\Windows\\System32\\WindowsPowerShell\\",
    res: { cpu: "3%", disk: "low", net: "none" },
    files: { summary: "1 script staged", items: ["Temp\\a8f2.ps1 (created)"] },
    services: ["Windows Management Instrumentation"],
    net: "None observed",
  },
  {
    id: "a4", sev: "routine", status: "cleared", confidence: 99,
    title: "Normal browser activity",
    process: "chrome.exe", pid: 8124, time: "11:30:02",
    why: "Standard browser file and network activity, consistent with expected behavior for this signed application.",
    runsFrom: "C:\\Program Files\\Google\\Chrome\\",
    res: { cpu: "4%", disk: "low", net: "active" },
    files: { summary: "Cache & profile", items: ["Cookies, History, Cache"] },
    services: ["DNS Client", "Cryptographic Services"],
    net: "Standard web traffic",
  },
  {
    id: "a5", sev: "routine", status: "cleared", confidence: 99,
    title: "Windows Update service",
    process: "svchost.exe", pid: 1044, time: "11:22:44",
    why: "Signed system host process performing scheduled update checks. No anomalies.",
    runsFrom: "C:\\Windows\\System32\\",
    res: { cpu: "1%", disk: "low", net: "active" },
    files: { summary: "System logs", items: ["System.evtx", "SOFTWARE hive (read)"] },
    services: ["Windows Update", "Background Tasks"],
    net: "Microsoft update servers",
  },
];

const MODULES = ["Signature", "Behavior", "Ransomware", "Network", "Web"];

function SevChip({ sev, small }) {
  const s = SEV[sev]; const I = s.Icon;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5, color: s.col,
      border: `1px solid ${s.col}66`, background: `${s.col}14`,
      borderRadius: 5, padding: small ? "1px 7px" : "3px 9px",
      fontSize: small ? 10.5 : 11.5, fontWeight: 700, letterSpacing: 0.6,
    }}><I size={small ? 12 : 14} />{s.label}</span>
  );
}

function EvidenceRow({ icon: Icon, label, children }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "11px 0", borderBottom: `1px solid ${c.line}` }}>
      <div style={{ width: 130, flexShrink: 0, display: "flex", alignItems: "center", gap: 8, color: c.mute, fontSize: 12 }}>
        <Icon size={14} />{label}
      </div>
      <div style={{ flex: 1, fontSize: 13, color: c.text }}>{children}</div>
    </div>
  );
}

function Mono({ children }) {
  return <span style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12.5 }}>{children}</span>;
}

export default function App() {
  const [selId, setSelId] = useState("a1");
  const [statuses, setStatuses] = useState({});
  const [clock, setClock] = useState("11:42:09");

  useEffect(() => {
    const id = setInterval(() => {
      const d = new Date();
      setClock(d.toTimeString().slice(0, 8));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const sel = ALERTS.find((a) => a.id === selId);
  const status = statuses[sel.id] || sel.status;

  const act = (s) => setStatuses((m) => ({ ...m, [sel.id]: s }));

  const tiers = ["critical", "elevated", "routine"];
  const counts = ALERTS.reduce((a, x) => {
    const st = statuses[x.id] || x.status;
    if (st === "active") a[x.sev] = (a[x.sev] || 0) + 1;
    return a;
  }, {});
  const activeCrit = counts.critical || 0;
  const score = activeCrit > 0 ? 34 : (counts.elevated ? 68 : 96);

  return (
    <div style={{
      background: c.bg, minHeight: "100vh", color: c.text,
      fontFamily: "system-ui, -apple-system, sans-serif", fontSize: 14,
    }}>
      <style>{`
        @keyframes blip { 0%,100%{opacity:1} 50%{opacity:.35} }
        .live { animation: blip 1.6s infinite; }
        .qrow { cursor:pointer; transition: background .1s; }
        .qrow:hover { background:${c.raise} !important; }
        .btn { cursor:pointer; font:inherit; border-radius:7px; padding:9px 16px; font-weight:600; font-size:13px; border:1px solid transparent; }
        @media (prefers-reduced-motion: reduce){ .live{animation:none} }
      `}</style>

      {/* ---- posture bar ---- */}
      <div style={{
        display: "flex", alignItems: "center", gap: 22, padding: "13px 20px",
        borderBottom: `1px solid ${c.line}`, flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <ShieldX size={18} color={activeCrit ? c.crit : c.ok} />
          <span style={{ fontWeight: 700, letterSpacing: 0.4 }}>Sentinel</span>
        </div>

        {/* risk score */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ position: "relative", width: 40, height: 40 }}>
            <svg width="40" height="40" style={{ transform: "rotate(-90deg)" }}>
              <circle cx="20" cy="20" r="16" fill="none" stroke={c.line} strokeWidth="4" />
              <circle cx="20" cy="20" r="16" fill="none"
                stroke={score < 50 ? c.crit : score < 80 ? c.warn : c.ok} strokeWidth="4"
                strokeDasharray={`${(score / 100) * 100.5} 100.5`} strokeLinecap="round" />
            </svg>
            <span style={{
              position: "absolute", inset: 0, display: "flex", alignItems: "center",
              justifyContent: "center", fontSize: 12, fontWeight: 700,
            }}>{score}</span>
          </div>
          <div>
            <div style={{ fontSize: 12.5, fontWeight: 600 }}>Security score</div>
            <div style={{ fontSize: 11, color: c.mute }}>
              {activeCrit ? "Action required" : "Stable"}</div>
          </div>
        </div>

        {/* severity counts */}
        <div style={{ display: "flex", gap: 16 }}>
          {tiers.map((t) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 7 }}>
              {React.createElement(SEV[t].Icon, { size: 15, color: SEV[t].col })}
              <span style={{ fontSize: 17, fontWeight: 700, fontFamily: "ui-monospace, monospace" }}>
                {counts[t] || 0}</span>
              <span style={{ fontSize: 11, color: c.mute }}>{SEV[t].label.toLowerCase()}</span>
            </div>
          ))}
        </div>

        <div style={{ flex: 1 }} />

        {/* protection modules — secondary, quiet */}
        <div style={{ display: "flex", gap: 12 }}>
          {MODULES.map((m) => (
            <span key={m} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5, color: c.mute }}>
              <CheckCircle2 size={12} color={c.ok} />{m}
            </span>
          ))}
        </div>

        {/* live + clock */}
        <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11.5, color: c.mute }}>
          <Activity size={13} color={c.ok} className="live" />
          live · {clock}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr" }}>

        {/* ---- triage queue (three tiers) ---- */}
        <div style={{ borderRight: `1px solid ${c.line}`, minHeight: "calc(100vh - 56px)" }}>
          {tiers.map((tier) => {
            const rows = ALERTS.filter((a) => a.sev === tier);
            return (
              <div key={tier}>
                <div style={{
                  padding: "9px 16px", fontSize: 10.5, letterSpacing: 1.2, fontWeight: 700,
                  color: SEV[tier].col, background: c.panel, borderBottom: `1px solid ${c.line}`,
                  borderTop: `1px solid ${c.line}`, display: "flex", alignItems: "center", gap: 7,
                }}>
                  {React.createElement(SEV[tier].Icon, { size: 13 })}
                  {SEV[tier].label}
                  <span style={{ color: c.dim, fontWeight: 500 }}>· {rows.length}</span>
                </div>
                {rows.map((a) => {
                  const st = statuses[a.id] || a.status;
                  const isSel = a.id === selId;
                  const cleared = st !== "active";
                  return (
                    <div key={a.id} className="qrow" onClick={() => setSelId(a.id)}
                      style={{
                        padding: "12px 16px", borderBottom: `1px solid ${c.line}`,
                        borderLeft: `3px solid ${isSel ? SEV[a.sev].col : "transparent"}`,
                        background: isSel ? c.raise : "transparent",
                        opacity: cleared ? 0.5 : 1,
                      }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 13.5, fontWeight: 600, flex: 1, color: c.text }}>
                          {a.title}</span>
                        <span style={{ fontSize: 10.5, color: c.dim, fontFamily: "ui-monospace, monospace" }}>
                          {a.time}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <Mono><span style={{ color: c.mute }}>{a.process}</span></Mono>
                        {cleared && (
                          <span style={{ fontSize: 10, color: c.ok, marginLeft: "auto",
                            display: "inline-flex", alignItems: "center", gap: 4 }}>
                            <CheckCircle2 size={11} />{st === "contained" ? "contained" : "cleared"}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* ---- investigation / detail ---- */}
        <div style={{ padding: 24 }}>
          {/* header */}
          <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 4 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7 }}>
                <SevChip sev={sel.sev} />
                <span style={{ fontSize: 11.5, color: c.mute }}>
                  confidence <b style={{ color: c.text }}>{sel.confidence}%</b></span>
                <span style={{ fontSize: 11.5, color: c.mute, fontFamily: "ui-monospace, monospace" }}>
                  detected {sel.time}</span>
              </div>
              <h1 style={{ fontSize: 21, fontWeight: 700, margin: 0, lineHeight: 1.25 }}>{sel.title}</h1>
              <div style={{ marginTop: 6 }}>
                <Mono><span style={{ color: c.mute }}>{sel.process} · pid {sel.pid}</span></Mono>
              </div>
            </div>
          </div>

          {/* why it matters — context first */}
          <div style={{
            marginTop: 16, background: `${SEV[sel.sev].col}10`,
            borderLeft: `3px solid ${SEV[sel.sev].col}`, borderRadius: 6,
            padding: "13px 16px", fontSize: 14, lineHeight: 1.55, color: c.text,
          }}>
            <div style={{ fontSize: 10.5, letterSpacing: 1, color: SEV[sel.sev].col, fontWeight: 700, marginBottom: 5 }}>
              WHY THIS MATTERS</div>
            {sel.why}
          </div>

          {/* evidence */}
          <div style={{ marginTop: 22 }}>
            <div style={{ fontSize: 11, letterSpacing: 1, color: c.mute, fontWeight: 700, marginBottom: 4 }}>
              EVIDENCE</div>
            <EvidenceRow icon={MapPin} label="Runs from">
              <Mono>{sel.runsFrom}</Mono>
            </EvidenceRow>
            <EvidenceRow icon={Cpu} label="Resource use">
              <span style={{ display: "inline-flex", gap: 18 }}>
                <span><Cpu size={12} style={{ verticalAlign: -1 }} /> CPU {sel.res.cpu}</span>
                <span><HardDrive size={12} style={{ verticalAlign: -1 }} /> Disk {sel.res.disk}</span>
                <span><Globe size={12} style={{ verticalAlign: -1 }} /> Net {sel.res.net}</span>
              </span>
            </EvidenceRow>
            <EvidenceRow icon={FileWarning} label="Files touched">
              <div style={{ fontWeight: 600, marginBottom: 3 }}>{sel.files.summary}</div>
              <div style={{ color: c.mute, fontSize: 12.5 }}>{sel.files.items.join(" · ")}</div>
            </EvidenceRow>
            <EvidenceRow icon={Cog} label="Services used">
              {sel.services.join(" · ")}
            </EvidenceRow>
            <EvidenceRow icon={Globe} label="Network">
              <Mono>{sel.net}</Mono>
            </EvidenceRow>
          </div>

          {/* response actions — directly on the alert */}
          {status === "active" ? (
            <div style={{ marginTop: 22, display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button className="btn" onClick={() => act("contained")}
                style={{ background: c.crit, color: "#fff" }}>
                <ShieldX size={14} style={{ verticalAlign: -2, marginRight: 6 }} />Quarantine</button>
              <button className="btn" onClick={() => {}}
                style={{ background: "transparent", color: c.text, borderColor: c.line }}>
                <Search size={14} style={{ verticalAlign: -2, marginRight: 6 }} />Investigate</button>
              <button className="btn" onClick={() => act("cleared")}
                style={{ background: "transparent", color: c.mute, borderColor: c.line }}>
                <CheckCircle2 size={14} style={{ verticalAlign: -2, marginRight: 6 }} />Mark safe</button>
              <button className="btn" onClick={() => act("cleared")}
                style={{ background: "transparent", color: c.mute, borderColor: c.line }}>
                <XCircle size={14} style={{ verticalAlign: -2, marginRight: 6 }} />Dismiss</button>
            </div>
          ) : (
            <div style={{
              marginTop: 22, display: "inline-flex", alignItems: "center", gap: 8,
              color: c.ok, fontSize: 13.5, fontWeight: 600,
              border: `1px solid ${c.ok}44`, background: `${c.ok}12`,
              borderRadius: 7, padding: "9px 16px",
            }}>
              <CheckCircle2 size={15} />
              {status === "contained" ? "Threat quarantined — process killed and file isolated" : "Marked as safe"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
