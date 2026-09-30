"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";

const STATUSES = ["Open", "In Progress", "Resolved", "Closed"];

export default function TicketsTab() {
  const [rows, setRows] = useState<any[]>([]);
  const [error, setError] = useState("");

  const load = () =>
    api.get("/api/v1/tickets")
      .then((r) => setRows(r.data))
      .catch((e) => setError(e?.message || "Could not load tickets"));

  useEffect(() => { load(); }, []);

  async function setStatus(id: string, status: string) {
    try {
      setError("");
      await api.patch(`/api/v1/tickets/${id}/status`, { status });
      load();
    } catch (e: any) {
      setError(JSON.stringify(e?.response?.data?.detail || e.message));
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs tracking-widest opacity-60">WORKSPACE</p>
        <h1 className="text-3xl font-bold">Tickets</h1>
        <p className="opacity-70">Remediation tickets created from correlated findings.</p>
      </div>
      {error && <p className="text-red-400">{error}</p>}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="opacity-70">
              <th className="p-3">Ticket</th><th>Title</th><th>Severity</th>
              <th>Risk</th><th>Owner</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr key={t.ticket_id} className="border-t border-white/10">
                <td className="p-3 font-mono text-sm">{t.ticket_id}</td>
                <td>{t.title}</td>
                <td>{t.severity}</td>
                <td>{Math.round(t.unified_risk_score * 100)}</td>
                <td>{t.owner}</td>
                <td>
                  <select
                    className="rounded bg-[#0b1220] border border-white/20 p-1"
                    value={t.status}
                    onChange={(e) => setStatus(t.ticket_id, e.target.value)}
                  >
                    {Array.from(new Set([t.status, ...STATUSES])).map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}