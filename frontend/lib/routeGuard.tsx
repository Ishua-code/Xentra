"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "./auth";

const PUBLIC_PATHS = ["/login"];

export function RouteGuard({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  const isPublicPath = PUBLIC_PATHS.includes(pathname);

  useEffect(() => {
    if (isLoading) return; // wait until we've checked localStorage

    if (!isAuthenticated && !isPublicPath) {
      router.push("/login");
    }

    if (isAuthenticated && isPublicPath) {
      // already logged in, no need to see the login page again
      router.push("/");
    }
  }, [isLoading, isAuthenticated, isPublicPath, router]);

  // While checking auth state, or while redirecting, show nothing (avoids flicker)
  if (isLoading) return null;
  if (!isAuthenticated && !isPublicPath) return null;
  if (isAuthenticated && isPublicPath) return null;

  return <>{children}</>;
}