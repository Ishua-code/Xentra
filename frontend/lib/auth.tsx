"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useRouter } from "next/navigation";
import api from "./api";

interface AuthContextType {
  token: string | null;
  username: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Decodes the "sub" (username) claim out of our JWT without adding a
// dependency: JWTs are three base64url segments separated by dots, and
// the payload is the middle one.
function getUsernameFromToken(token: string): string | null {
  try {
    const payload = token.split(".")[1];
    const decoded = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    );
    return decoded.sub ?? null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const stored = localStorage.getItem("xentra_token");
    if (stored) setToken(stored);
    setIsLoading(false);
  }, []);

  const username = token ? getUsernameFromToken(token) : null;

  async function login(username: string, password: string) {
    const body = new URLSearchParams();
    body.append("username", username);
    body.append("password", password);

    const res = await api.post("/api/v1/auth/login", body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const accessToken = res.data.access_token;
    localStorage.setItem("xentra_token", accessToken);
    setToken(accessToken);
    router.push("/");
  }

  function logout() {
    localStorage.removeItem("xentra_token");
    setToken(null);
    router.push("/login");
  }

  return (
    <AuthContext.Provider
      value={{ token, username, login, logout, isAuthenticated: !!token, isLoading }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
