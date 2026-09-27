"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
    } catch (err: unknown) {
      if (err && typeof err === "object" && "response" in err) {
        const axiosErr = err as { response?: { status?: number; data?: unknown } };
        setError(
          `Login failed (status ${axiosErr.response?.status}): ${JSON.stringify(
            axiosErr.response?.data
          )}`
        );
      } else if (err && typeof err === "object" && "message" in err) {
        setError(`Network/CORS error: ${(err as Error).message}`);
      } else {
        setError("Unknown error during login.");
      }
    } finally {
      setLoading(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    width: "100%",
    padding: 10,
    marginBottom: 12,
    background: "#1a1f2e",
    color: "white",
    border: "1px solid #2a3040",
    borderRadius: 4,
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        alignItems: "center",
        justifyContent: "center",
        background: "#080c14",
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{ width: 320, padding: 32, background: "#0f1420", borderRadius: 8 }}
      >
        <h1 style={{ color: "white", marginBottom: 24 }}>XENTRA Login</h1>
        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={inputStyle}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={inputStyle}
        />
        {error && (
          <p style={{ color: "#ff6b6b", fontSize: 13, marginBottom: 12, wordBreak: "break-word" }}>
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={loading}
          style={{
            width: "100%",
            padding: 10,
            background: "#3b82f6",
            color: "white",
            border: "none",
            borderRadius: 4,
            fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? "Logging in..." : "Log in"}
        </button>
      </form>
    </div>
  );
}