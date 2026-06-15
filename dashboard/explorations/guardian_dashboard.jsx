import React, { useState } from "react";
import { Cpu, MemoryStick, Globe, FileText, Settings2, ShieldAlert,
  ShieldCheck, FolderOpen, Check } from "lucide-react";

/* Guardian — a calm, plain-language view of what each file is doing.
 * Pick a file on the left, read its story on the right. */

const T = {
  bg: "#F6F7F9", card: "#FFFFFF", border: "#E8EAED",
  text: "#1F2733", muted: "#7A8593", accent: "#4F6BED",
  safe: "#2FA86A", watch: "#E0A33E", block: "#E05656",
};

const V = {
  safe:    { c: T.safe,  label: "Safe",     icon: ShieldCheck },
  watch:   { c: T.watch, label: "Watching", icon: ShieldAlert },
  blocked: { c: T.block, label: "Blocked",  icon: ShieldAlert },
};

const FILES = [
  {
    id: "f1", name: "chrome.exe", verdict: "safe",
    runsFrom: "C:\\Program Files\\Google\\Chrome\\",
    uses: { cpu: "4%", memory: "180 MB", network: "Yes" },
    opens: ["Cookies", "History", "Cache files"],
    services: ["DNS Client", "Cryptographic Services"],
    impact: null,
  },
  {
    id: "f2", name: "explorer.exe", verdict: "safe",
    runsFrom: "C:\\Windows\\",
    uses: { cpu: "1%", memory: "95 MB", network: "No" },
    opens: ["Desktop folder", "Thumbnail cache"],
    services: ["Themes", "Shell Hardware Detection"],
    impact: null,
  },
  {
    id: "f3", name: "updater.tmp", verdict: "watch",
    runsFrom: "C:\\Users\\you\\AppData\\Local\\Temp\\",
    uses: { cpu: "12%", memory: "60 MB", network: "Yes" },
    opens: ["A temporary file", "System config"],
    services: ["Task Scheduler", "Remote Procedure Call"],
    impact: "Unsigned program running from a temp folder and reading system files. Worth keeping an eye on.",
  },
  {
    id: "f4", name: "invoice_2026_04.pdf.exe", verdict: "blocked",
    runsFrom: "C:\\Users\\you\\Downloads\\",
    uses: { cpu: "72%", memory: "320 MB", network: "Yes" },
    opens: ["Your documents", "Your photos", "Creating READ_ME.txt"],
    services: ["Volume Shadow Copy", "Network Connections"],
    impact: "Pretends to be a PDF, but is rapidly encrypting your files and deleting backups — this is ransomware. It was stopped automatically.",
  },
];

const CHECKS = [
  "Signature scan", "Behavior analysis", "Ransomware shield",
  "Network monitor", "Web protection",
];

function Pill({ verdict, big }) {
  const v = V[verdict]; const Icon = v.icon;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      color: v.c, background: `${v.c}14`,
      borderRadius: 999, padding: big ? "6px 14px" : "3px 10px",
      fontSize: big ? 14 : 12, fontWeight: 600,
    }}>
      <Icon size={big ? 16 : 13} /> {v.label}
    </span>
  );
}

function Step({ label, children, color }) {
  return (
    <div style={{ display: "flex", gap: 14 }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
        <div style={{ width: 9, height: 9, borderRadius: 99, background: color || T.border, marginTop: 5 }} />
        <div style={{ flex: 1, width: 2, background: T.border, marginTop: 4 }} />
      </div>
      <div style={{ paddingBottom: 22, flex: 1 }}>
        <div style={{ fontSize: 11, letterSpacing: 1, color: T.muted, textTransform: "uppercase", marginBottom: 7 }}>
          {label}</div>
        {children}
      </div>
    </div>
  );
}

function Chip({ icon: Icon, label, value }) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 8,
      border: `1px solid ${T.border}`, borderRadius: 10,
      padding: "8px 12px", marginRight: 8, marginBottom: 8,
    }}>
      <Icon size={15} color={T.muted} />
      <span style={{ fontSize: 13, color: T.muted }}>{label}</span>
      <span style={{ fontSize: 13, color: T.text, fontWeight: 600 }}>{value}</span>
    </div>
  );
}

function Tag({ children }) {
  return (
    <span style={{
      display: "inline-block", border: `1px solid ${T.border}`,
      borderRadius: 8, padding: "5px 10px", marginRight: 8, marginBottom: 8,
      fontSize: 13, color: T.text,
    }}>{children}</span>
  );
}

export default function App() {
  const [selId, setSelId] = useState("f4");
  const f = FILES.find((x) => x.id === selId);
  const blocked = FILES.filter((x) => x.verdict === "blocked").length;

  return (
    <div style={{
      background: T.bg, minHeight: "100vh", color: T.text,
      fontFamily: "system-ui, -apple-system, sans-serif", padding: 24,
    }}>
      <div style={{ maxWidth: 940, margin: "0 auto" }}>

        {/* header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 9, background: T.accent,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <ShieldCheck size={19} color="#fff" />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 17, fontWeight: 700 }}>Guardian</div>
            <div style={{ fontSize: 12.5, color: T.muted }}>
              {blocked > 0 ? `${blocked} threat blocked · you're protected`
                           : "All clear · you're protected"}</div>
          </div>
          <Pill verdict={blocked > 0 ? "blocked" : "safe"} />
        </div>

        {/* protection coverage — the "latest AV" checklist, kept simple */}
        <div style={{
          background: T.card, border: `1px solid ${T.border}`, borderRadius: 14,
          padding: "12px 16px", marginBottom: 18, display: "flex",
          flexWrap: "wrap", gap: 18,
        }}>
          {CHECKS.map((c) => (
            <span key={c} style={{ display: "inline-flex", alignItems: "center", gap: 7, fontSize: 13, color: T.text }}>
              <span style={{
                width: 17, height: 17, borderRadius: 99, background: `${T.safe}1A`,
                display: "inline-flex", alignItems: "center", justifyContent: "center",
              }}><Check size={11} color={T.safe} /></span>
              {c}
            </span>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", gap: 18 }}>

          {/* file list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {FILES.map((x) => (
              <button key={x.id} onClick={() => setSelId(x.id)}
                style={{
                  textAlign: "left", cursor: "pointer", font: "inherit",
                  background: x.id === selId ? T.card : "transparent",
                  border: `1px solid ${x.id === selId ? T.border : "transparent"}`,
                  borderRadius: 12, padding: "12px 14px",
                  boxShadow: x.id === selId ? "0 1px 3px rgba(0,0,0,0.04)" : "none",
                  display: "flex", alignItems: "center", gap: 10,
                }}>
                <span style={{ width: 8, height: 8, borderRadius: 99, background: V[x.verdict].c, flexShrink: 0 }} />
                <span style={{
                  fontSize: 13.5, color: T.text, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: x.id === selId ? 600 : 400,
                }}>{x.name}</span>
              </button>
            ))}
          </div>

          {/* the story */}
          <div style={{
            background: T.card, border: `1px solid ${T.border}`, borderRadius: 16,
            padding: 24, boxShadow: "0 1px 3px rgba(0,0,0,0.04)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
              <FileText size={20} color={T.muted} />
              <span style={{ fontSize: 18, fontWeight: 700, flex: 1 }}>{f.name}</span>
              <Pill verdict={f.verdict} big />
            </div>

            <Step label="Runs from" color={T.accent}>
              <span style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 13, color: T.text }}>
                {f.runsFrom}</span>
            </Step>

            <Step label="Uses these resources" color={T.accent}>
              <div>
                <Chip icon={Cpu} label="CPU" value={f.uses.cpu} />
                <Chip icon={MemoryStick} label="Memory" value={f.uses.memory} />
                <Chip icon={Globe} label="Internet" value={f.uses.network} />
              </div>
            </Step>

            <Step label="Opens these files" color={T.accent}>
              <div>{f.opens.map((o, i) => <Tag key={i}><FolderOpen size={12} style={{ verticalAlign: -1, marginRight: 5 }} color={T.muted} />{o}</Tag>)}</div>
            </Step>

            <Step label="Uses these services" color={T.accent}>
              <div>{f.services.map((s, i) => <Tag key={i}><Settings2 size={12} style={{ verticalAlign: -1, marginRight: 5 }} color={T.muted} />{s}</Tag>)}</div>
            </Step>

            <div style={{ display: "flex", gap: 14 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{ width: 9, height: 9, borderRadius: 99, background: V[f.verdict].c, marginTop: 5 }} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, letterSpacing: 1, color: T.muted, textTransform: "uppercase", marginBottom: 7 }}>
                  {f.verdict === "safe" ? "Impact" : "Could harm"}</div>
                {f.impact ? (
                  <div style={{
                    background: `${V[f.verdict].c}12`, border: `1px solid ${V[f.verdict].c}33`,
                    borderRadius: 10, padding: "12px 14px", fontSize: 14, lineHeight: 1.5, color: T.text,
                  }}>{f.impact}</div>
                ) : (
                  <div style={{ fontSize: 14, color: T.muted }}>Nothing risky observed. This file is behaving normally.</div>
                )}

                {f.verdict !== "safe" && (
                  <div style={{ marginTop: 16, display: "flex", gap: 10 }}>
                    <button style={{
                      cursor: "pointer", font: "inherit", fontWeight: 600, fontSize: 13.5,
                      color: "#fff", background: T.block, border: "none",
                      borderRadius: 10, padding: "10px 18px",
                    }}>Quarantine</button>
                    <button style={{
                      cursor: "pointer", font: "inherit", fontWeight: 600, fontSize: 13.5,
                      color: T.text, background: T.card, border: `1px solid ${T.border}`,
                      borderRadius: 10, padding: "10px 18px",
                    }}>Allow anyway</button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
