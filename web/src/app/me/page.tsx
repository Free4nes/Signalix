"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { me, tokens, fetchWithAuth, ApiCallError, type MeResponse } from "@/lib/api";

export default function MePage() {
  const router = useRouter();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tokens.getAccess()) {
      router.replace("/login");
      return;
    }
    fetchWithAuth((token) => me(token))
      .then(setUser)
      .catch((err) => {
        if (err instanceof ApiCallError && err.status === 401) {
          tokens.clear();
          router.replace("/login");
        } else {
          setError(err instanceof Error ? err.message : "Failed to load profile");
        }
      });
  }, [router]);

  function handleLogout() {
    tokens.clear();
    router.push("/login");
  }

  if (error) {
    return (
      <Card>
        <p className="rounded-lg border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-400">
          {error}
        </p>
        <button
          onClick={handleLogout}
          className="mt-4 w-full rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition"
        >
          Back to login
        </button>
      </Card>
    );
  }

  if (!user) {
    return (
      <Card>
        <div className="flex items-center justify-center py-8">
          <span className="h-6 w-6 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="mb-6 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-indigo-600 text-lg font-bold">
          {user.phone_number.slice(-2)}
        </div>
        <div>
          <p className="text-xs text-zinc-500 uppercase tracking-widest">Signed in as</p>
          <p className="font-semibold text-zinc-100">{user.phone_number}</p>
        </div>
      </div>

      <div className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-sm">
        <Row label="User ID" value={user.id} mono />
        <Row label="Phone" value={user.phone_number} />
      </div>

      <button
        onClick={handleLogout}
        className="mt-6 w-full rounded-lg border border-zinc-700 px-4 py-2.5 font-medium text-zinc-300 transition hover:border-red-700 hover:bg-red-950 hover:text-red-400"
      >
        Logout
      </button>
    </Card>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-8 shadow-xl">
      <h1 className="mb-6 text-center text-2xl font-bold tracking-tight">Your profile</h1>
      {children}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="shrink-0 text-zinc-500">{label}</span>
      <span
        className={`break-all text-right text-zinc-300 ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}
