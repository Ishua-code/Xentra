"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";

type Asset = {
  host: string;
  owner: string;
  privilege: string;
  mfa: boolean | null;
  cves: string[];
  topRisk: number;
  onPath: boolean;
};

export default function AssetsTab() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.get("/api/v1/findings"), api.get("/api/v1/identities")])
      .then(([f, i]) => {
        const map: Record<string, Asset> = {};
        const get = (host: string): Asset =>
          (map[host] ||= {
            host, owner: "unknown", privilege: "-", mfa: null,
            cves: [], topRisk: 0, onPath: false,
          });

        i.data.forEach((id: any) => {
          const a = get(id.owned_asset_ip);
          a.owner = id.username;
          a.privilege = id.privilege_level;
          a.mfa = id.mfa_enabled;
        });
        f.data.forEach((fd: any) => {
          const a = get(fd.host);
          if (a.owner === "unknown" && fd.owner) a.owner = fd.owner;
          a.cves.push(fd.cve_id);
          a.topRisk = Math.max(a.topRisk, Math.round(fd.unified_risk_score * 100));
          if (Array.isArray(fd.attack_path) && fd.attack_path.length > 0) a.onPath = true;
        });
        setAssets(Object.values(map).sort((x, y) => y.topRisk - x.topRisk));
      })
      .catch((e) => setError(e?.message || "Could not load assets"));
  }, []);

  const withFindings = assets.filter((a) => a.cves.length > 0).length;
  const onPath = assets.filter((a) => a.onPath).length;
  const noMfa = assets.filter((a) => a.mfa === false).length;

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
        <h1 className="text-3xl font-bold">Asset inventory</h1>
        <p className="opacity-70">Hosts, ownership and exposure, from live backend data.</p>
      </div>
      {error && <p className="text-red-400">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {card("Total assets", assets.length)}
        {card("With vulnerabilities", withFindings)}
        {card("On a Domain Admin path", onPath)}
        {card("Owner without MFA", noMfa)}
      </div>

      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="opacity-70">
              <th className="p-3">Host</th><th>Owner</th><th>Privilege</th>
              <th>MFA</th><th>Vulnerabilities</th><th>Top risk</th><th>Exposure</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.host} className="border-t border-white/10">
                <td className="p-3 font-mono">{a.host}</td>
                <td>{a.owner}</td>
                <td>{a.privilege}</td>
                <td>
                  {a.mfa === null ? (
                    <span className="opacity-50">-</span>
                  ) : (
                    <span className={a.mfa ? "text-green-400" : "text-red-400"}>
                      {a.mfa ? "Enabled" : "Disabled"}
                    </span>
                  )}
                </td>
                <td className="font-mono text-sm">{a.cves.length ? a.cves.join(", ") : "None"}</td>
                <td>{a.cves.length ? a.topRisk : "-"}</td>
                <td>
                  {a.onPath ? (
                    <span className="text-red-400">Path to Domain Admin</span>
                  ) : a.cves.length ? (
                    <span className="text-yellow-300">Vulnerable</span>
                  ) : (
                    <span className="text-green-400">Clean</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
