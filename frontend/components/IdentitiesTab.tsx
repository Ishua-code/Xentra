"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";

export default function IdentitiesTab() {
  const [rows, setRows] = useState<any[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/api/v1/identities")
      .then((r) => setRows(r.data))
      .catch((e) => setError(e?.message || "Could not load identities"));
  }, []);

  const noMfa = rows.filter((r) => !r.mfa_enabled).length;
  const admins = rows.filter((r) => r.privilege_level === "domain_admin").length;
  const card = (label: string, v: number) => (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
      <p className="text-sm opacity-70">{label}</p>
      <p className="text-3xl font-bold">{v}</p>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs tracking-widest opacity-60">WORKSPACE</p>
        <h1 className="text-3xl font-bold">Identities</h1>
        <p className="opacity-70">Accounts, privilege level and MFA status, from live backend data.</p>
      </div>
      {error && <p className="text-red-400">{error}</p>}
      <div className="grid grid-cols-3 gap-4">
        {card("Total identities", rows.length)}
        {card("MFA disabled", noMfa)}
        {card("Domain admins", admins)}
      </div>
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="opacity-70">
              <th className="p-3">Username</th><th>Privilege</th><th>MFA</th>
              <th>Last login (days)</th><th>Asset IP</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.username} className="border-t border-white/10">
                <td className="p-3">{r.username}</td>
                <td>{r.privilege_level}</td>
                <td>
                  <span className={r.mfa_enabled ? "text-green-400" : "text-red-400"}>
                    {r.mfa_enabled ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td>{r.last_login_days_ago}</td>
                <td className="font-mono">{r.owned_asset_ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}