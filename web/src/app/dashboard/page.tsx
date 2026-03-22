"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { me, tokens, fetchWithAuth, ApiCallError, type MeResponse } from "@/lib/api";
import { displayLabel } from "@/lib/format";
import ProjectsSection from "./ProjectsSection";

export default function DashboardPage() {
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

  return (
    <div className="flex h-screen w-full overflow-hidden bg-zinc-950 text-zinc-100">
      {/* Sidebar */}
      <aside className="flex w-56 shrink-0 flex-col border-r border-zinc-800 bg-zinc-900">
        {/* Brand */}
        <div className="flex h-16 items-center border-b border-zinc-800 px-5">
          <span className="text-lg font-bold tracking-tight text-white">Signalix</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4">
          <Link href="/dashboard">
            <NavItem active>
              <GridIcon />
              Dashboard
            </NavItem>
          </Link>
          <Link href="/chats">
            <NavItem>
              <ChatIcon />
              Chats
            </NavItem>
          </Link>
          <Link href="/contacts">
            <NavItem>
              <ContactsIcon />
              Contacts
            </NavItem>
          </Link>
          <Link href="/profile">
            <NavItem>
              <ProfileIcon />
              Profile
            </NavItem>
          </Link>
        </nav>

        {/* Logout */}
        <div className="border-t border-zinc-800 p-3">
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-red-950 hover:text-red-400"
          >
            <LogoutIcon />
            Logout
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex flex-1 flex-col overflow-auto">
        {/* Top bar */}
        <header className="flex h-16 items-center border-b border-zinc-800 px-6">
          <h1 className="text-lg font-semibold">Dashboard</h1>
        </header>

        {/* Content */}
        <main className="flex-1 p-6">
          {error && (
            <div className="mb-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          {!user && !error && (
            <div className="flex items-center gap-3 text-zinc-500">
              <span className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
              Loading…
            </div>
          )}

          {user && (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <ProfileCard user={user} />
                <StatCard label="Status" value="Active" accent="green" />
                <StatCard label="Auth method" value="OTP" accent="indigo" />
              </div>
              <ProjectsSection />
            </>
          )}
        </main>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function NavItem({
  children,
  active,
}: {
  children: React.ReactNode;
  active?: boolean;
}) {
  return (
    <div
      className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition ${
        active
          ? "bg-indigo-600/20 text-indigo-400"
          : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
      }`}
    >
      {children}
    </div>
  );
}

function ProfileCard({ user }: { user: MeResponse }) {
  const label = displayLabel(user);
  const initials = label.slice(-2);
  return (
    <div className="col-span-full rounded-2xl border border-zinc-800 bg-zinc-900 p-6 sm:col-span-2">
      <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-zinc-500">
        Your account
      </p>
      <div className="flex items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-indigo-600 text-xl font-bold">
          {initials}
        </div>
        <div className="min-w-0">
          <p className="truncate text-lg font-semibold">{label}</p>
          <p className="mt-0.5 truncate font-mono text-xs text-zinc-500">{user.id}</p>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: "green" | "indigo";
}) {
  const dot =
    accent === "green"
      ? "bg-emerald-500"
      : "bg-indigo-500";
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
      <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-zinc-500">
        {label}
      </p>
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <span className="font-semibold">{value}</span>
      </div>
    </div>
  );
}

function ContactsIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
    </svg>
  );
}

function ProfileIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
    </svg>
  );
}

function ChatIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
    </svg>
  );
}

function GridIcon() {
  return (
    <svg
      className="h-4 w-4 shrink-0"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
    >
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );
}

function LogoutIcon() {
  return (
    <svg
      className="h-4 w-4 shrink-0"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h6a2 2 0 012 2v1"
      />
    </svg>
  );
}
