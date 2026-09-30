"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";

export default function AttackPathsTab() {
  const [rows, setRows] = useState<any[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/api/v1/findings")
      .then((r) => setRows(r.data))
      .catch((e) => setError(e?.message || "Could not load attack paths"));
  }, []);

  const withPath = rows
    .filter((r) => Array.isArray(r.attack_path) && r.attack_path.length > 0)
    .sort((a, b) => b.unified_risk_score - a.unified_risk_score);
  const noPath = rows.filter((r) => !Array.isArray(r.attack_path) || r.attack_path.length === 0);
  const shortest = withPath.length
    ? Math.min(...withPath.map((r) => r.hops_to_domain_admin ?? r.attack_path.length - 1))
    : 0;
  const top = withPath[0] ? Math.round(withPath[0].unified_risk_score * 100) : 0;

  const card = (label: string, v: number | string) => (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
      <p className="text-sm opacity-70">{label}</p>
      <p className="text-3xl font-bold">{v}</p>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs tracking-widest opacity-60">WORKSPACE</p>
        <h1 className="text-3xl font-bold">Attack Paths</h1>
        <p className="opacity-70">How an attacker can move from a vulnerable host to Domain Admin.</p>
      </div>
      {error && <p className="text-red-400">{error}</p>}

      <div className="grid grid-cols-3 gap-4">
        {card("Paths to Domain Admin", withPath.length)}
        {card("Shortest path (hops)", shortest)}
        {card("Highest path risk", top)}
      </div>

      <div className="space-y-4">
        {withPath.map((r) => (
          <div key={r.cve_id + r.host} className="rounded-2xl border border-white/10 bg-white/5 p-5">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <div>
                <span className="font-mono text-blue-300">{r.cve_id}</span>
                <span className="opacity-70"> on {r.host} (owner: {r.owner})</span>
              </div>
              <div className="text-sm">
                Risk <b>{Math.round(r.unified_risk_score * 100)}</b> ·{" "}
                {r.hops_to_domain_admin ?? r.attack_path.length - 1} hops
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {r.attack_path.map((node: string, i: number) => {
                const last = i === r.attack_path.length - 1;
                return (
                  <div key={i} className="flex items-center gap-2">
                    <span
                      className={
                        "rounded-lg border px-3 py-1 font-mono text-sm " +
                        (last
                          ? "border-red-400/60 bg-red-500/20 text-red-300"
                          : i === 0
                          ? "border-blue-400/60 bg-blue-500/20"
                          : "border-white/20 bg-white/5")
                      }
                    >
                      {node}
                    </span>
                    {!last && <span className="opacity-60">→</span>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        {withPath.length === 0 && !error && (
          <p className="opacity-70">No attack paths found.</p>
        )}
      </div>

      {noPath.length > 0 && (
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
          <p className="font-semibold mb-2">No path to Domain Admin ({noPath.length})</p>
          <ul className="text-sm opacity-80 space-y-1">
            {noPath.map((r) => (
              <li key={r.cve_id + r.host}>
                <span className="font-mono">{r.cve_id}</span> on {r.host} (owner: {r.owner})
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
