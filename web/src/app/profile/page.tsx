"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  getMe,
  tokens,
  fetchWithAuth,
  updateMeDisplayName,
  ApiCallError,
  type MeResponse,
} from "@/lib/api";
import { displayLabel } from "@/lib/format";

const MAX_DISPLAY_NAME = 50;

export default function ProfilePage() {
  const router = useRouter();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tokens.getAccess()) {
      router.replace("/login");
      return;
    }
    fetchWithAuth((t) => getMe(t))
      .then((u) => {
        setUser(u);
        setDisplayName(u.display_name?.trim() ?? "");
      })
      .catch((err) => {
        if (err instanceof ApiCallError && err.status === 401) {
          tokens.clear();
          router.replace("/login");
        } else {
          setError(err instanceof Error ? err.message : "Failed to load profile");
        }
      });
  }, [router]);

  const handleSave = async () => {
    if (!user) return;
    const trimmed = displayName.trim();
    if (trimmed.length > MAX_DISPLAY_NAME) {
      setError(`Max ${MAX_DISPLAY_NAME} characters`);
      return;
    }
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const value = trimmed || null;
      const updated = await fetchWithAuth((t) => updateMeDisplayName(t, value));
      setUser(updated);
      setDisplayName(updated.display_name?.trim() ?? "");
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const label = user ? displayLabel(user) : "";

  return (
    <div className="flex h-screen w-full overflow-hidden bg-zinc-950 text-zinc-100">
      <aside className="flex w-56 shrink-0 flex-col border-r border-zinc-800 bg-zinc-900">
        <div className="flex h-16 items-center border-b border-zinc-800 px-5">
          <Link href="/dashboard" className="text-lg font-bold tracking-tight text-white hover:text-zinc-200">
            Signalix
          </Link>
        </div>
        <nav className="flex-1 px-3 py-4">
          <Link href="/dashboard" className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <GridIcon />
            Dashboard
          </Link>
          <Link href="/chats" className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <ChatIcon />
            Chats
          </Link>
          <Link href="/contacts" className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <ContactsIcon />
            Contacts
          </Link>
          <div className="mt-1 flex items-center gap-2 rounded-lg bg-indigo-600/20 px-3 py-2 text-sm font-medium text-indigo-400">
            <ProfileIcon />
            Profile
          </div>
        </nav>
        <div className="border-t border-zinc-800 p-3">
          <button
            onClick={() => { tokens.clear(); router.push("/login"); }}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-red-950 hover:text-red-400"
          >
            <LogoutIcon />
            Logout
          </button>
        </div>
      </aside>

      <div className="flex flex-1 flex-col overflow-auto">
        <header className="flex h-16 items-center border-b border-zinc-800 px-6">
          <h1 className="text-lg font-semibold">Profile</h1>
        </header>
        <main className="flex-1 p-6">
          {!user && !error && (
            <div className="flex items-center gap-3 text-zinc-500">
              <span className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
              Loading…
            </div>
          )}
          {user && (
            <div className="max-w-md space-y-6">
              <div>
                <p className="text-2xl font-semibold tracking-tight text-white">
                  {label}
                </p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-zinc-400">Display Name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => {
                    setDisplayName(e.target.value.slice(0, MAX_DISPLAY_NAME));
                    setError(null);
                  }}
                  placeholder={user.phone_number}
                  maxLength={MAX_DISPLAY_NAME}
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-zinc-100 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
                <p className="mt-1 text-xs text-zinc-500">
                  Max {MAX_DISPLAY_NAME} characters. Empty = show phone number.
                </p>
                {error && (
                  <p className="mt-1 text-sm text-red-400">{error}</p>
                )}
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium hover:bg-indigo-500 disabled:opacity-50"
                >
                  {saving ? "Speichern…" : "Save"}
                </button>
                {saved && (
                  <span className="text-sm text-emerald-500">Saved</span>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function GridIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
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
function LogoutIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h6a2 2 0 012 2v1" />
    </svg>
  );
}
