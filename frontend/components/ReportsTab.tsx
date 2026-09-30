"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";

function toCsv(rows: any[]): string {
  if (!rows.length) return "";
  const cols = Object.keys(rows[0]);
  const esc = (v: any) => {
    const s = Array.isArray(v) ? v.join(" > ") : v === null || v === undefined ? "" : String(v);
    return '"' + s.replace(/"/g, '""') + '"';
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}

function download(name: string, rows: any[]) {
  const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsTab() {
  const [findings, setFindings] = useState<any[]>([]);
  const [tickets, setTickets] = useState<any[]>([]);
  const [identities, setIdentities] = useState<any[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api.get("/api/v1/findings"),
      api.get("/api/v1/tickets"),
      api.get("/api/v1/identities"),
    ])
      .then(([f, t, i]) => {
        setFindings(f.data);
        setTickets(t.data);
        setIdentities(i.data);
      })
      .catch((e) => setError(e?.message || "Could not load report data"));
  }, []);

  const today = new Date().toISOString().slice(0, 10);
  const open = tickets.filter((t) => t.status === "Open").length;
  const paths = findings.filter((f) => Array.isArray(f.attack_path) && f.attack_path.length > 0).length;
  const noMfa = identities.filter((i) => !i.mfa_enabled).length;
  const avg = findings.length
    ? Math.round((findings.reduce((s, f) => s + f.unified_risk_score, 0) / findings.length) * 100)
    : 0;

  const stat = (label: string, v: number | string) => (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
      <p className="text-sm opacity-70">{label}</p>
      <p className="text-3xl font-bold">{v}</p>
    </div>
  );

  const item = (title: string, desc: string, file: string, rows: any[]) => (
    <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-white/5 p-5">
      <div>
        <p className="font-semibold">{title}</p>
        <p className="text-sm opacity-70">{desc} ({rows.length} rows)</p>
      </div>
      <button
        disabled={!rows.length}
        onClick={() => download(file, rows)}
        className="rounded-lg bg-blue-600 px-4 py-2 text-white disabled:opacity-40"
      >
        Download CSV
      </button>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs tracking-widest opacity-60">WORKSPACE</p>
        <h1 className="text-3xl font-bold">Reports</h1>
        <p className="opacity-70">Export live findings, tickets and identities. Generated {today}.</p>
      </div>
      {error && <p className="text-red-400">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {stat("Findings", findings.length)}
        {stat("Open tickets", open)}
        {stat("Paths to Domain Admin", paths)}
        {stat("Identities without MFA", noMfa)}
        {stat("Average risk", avg)}
      </div>

      <div className="space-y-3">
        {item("Findings report", "CVE, host, owner, EPSS, unified risk, attack path", `xentra-findings-${today}.csv`, findings)}
        {item("Tickets report", "Remediation tickets with status and recommended actions", `xentra-tickets-${today}.csv`, tickets)}
        {item("Identities report", "Accounts, privilege level, MFA and last login", `xentra-identities-${today}.csv`, identities)}
      </div>
    </div>
  );
}
