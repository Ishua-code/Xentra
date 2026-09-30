"use client";
import { useState } from "react";
import api from "@/lib/api";

const vulnerabilities = [
  { cve_id: "CVE-2021-44228", host: "192.168.1.10", cvss_score: 10.0 },
  { cve_id: "CVE-2017-0144", host: "192.168.1.24", cvss_score: 8.1 },
  { cve_id: "CVE-2018-7600", host: "192.168.1.31", cvss_score: 9.8 },
  { cve_id: "CVE-2019-0708", host: "192.168.1.44", cvss_score: 9.8 },
  { cve_id: "CVE-2020-1472", host: "192.168.1.6", cvss_score: 10.0 },
];

const identities = [
  { username: "admin_john", privilege_level: "domain_admin", mfa_enabled: false, last_login_days_ago: 1, owned_asset_ip: "192.168.1.10" },
  { username: "mike_ops", privilege_level: "standard", mfa_enabled: true, last_login_days_ago: 5, owned_asset_ip: "192.168.1.44" },
  { username: "sara_finance", privilege_level: "standard", mfa_enabled: true, last_login_days_ago: 0, owned_asset_ip: "192.168.1.31" },
  { username: "svc_backup", privilege_level: "service_account", mfa_enabled: false, last_login_days_ago: 3, owned_asset_ip: "192.168.1.24" },
  { username: "svc_print", privilege_level: "service_account", mfa_enabled: true, last_login_days_ago: 2, owned_asset_ip: "192.168.1.18" },
];

export default function ScanButton() {
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!window.confirm("Run a new scan? This saves new findings and tickets.")) return;
    setBusy(true);
    try {
      const r = await api.post("/api/v1/correlate", { vulnerabilities, identities });
      window.alert(`Scan complete: ${r.data.findings.length} findings, ${r.data.tickets.length} tickets`);
      window.location.reload();
    } catch (e: any) {
      window.alert("Scan failed: " + JSON.stringify(e?.response?.data?.detail || e.message));
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      onClick={run}
      disabled={busy}
      className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
    >
      {busy ? "Scanning..." : "Run new scan"}
    </button>
  );
}
