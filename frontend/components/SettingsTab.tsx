"use client";
import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function readToken() {
  try {
    const t = localStorage.getItem("xentra_token");
    if (!t) return null;
    const p = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return p as { sub?: string; exp?: number };
  } catch {
    return null;
  }
}

export default function SettingsTab() {
  const [health, setHealth] = useState<any>(null);
  const [down, setDown] = useState(false);
  const [user, setUser] = useState<{ sub?: string; exp?: number } | null>(null);

  useEffect(() => {
    setUser(readToken());
    fetch(`${API}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setDown(true));
  }, []);

  function logout() {
    localStorage.removeItem("xentra_token");
    window.location.href = "/login";
  }

  const expires = user?.exp ? new Date(user.exp * 1000).toLocaleString() : "unknown";
  const row = (k: string, v: React.ReactNode) => (
    <div className="flex justify-between border-t border-white/10 py-3 first:border-0">
      <span className="opacity-70">{k}</span>
      <span className="font-mono text-sm">{v}</span>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs tracking-widest opacity-60">SYSTEM</p>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="opacity-70">Your session and backend connection.</p>
      </div>

      <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
        <p className="font-semibold mb-2">Profile</p>
        {row("Username", user?.sub || "admin")}
        {row("Role", "Security Analyst")}
        {row("Session expires", expires)}
      </div>

      <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
        <p className="font-semibold mb-2">Backend</p>
        {row("API URL", API)}
        {row(
          "Status",
          down ? (
            <span className="text-red-400">Unreachable</span>
          ) : health ? (
            <span className="text-green-400">{health.status}</span>
          ) : (
            "checking..."
          )
        )}
        {row("Service", health?.service || "-")}
        {row("Environment", health?.environment || "-")}
      </div>

      <button onClick={logout} className="rounded-lg bg-red-600 px-4 py-2 text-white">
        Log out
      </button>
    </div>
  );
}
