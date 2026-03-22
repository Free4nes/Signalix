"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  me,
  tokens,
  fetchWithAuth,
  ApiCallError,
  syncContacts,
  createConversation,
  listConversations,
  type MeResponse,
  type SyncContactUser,
} from "@/lib/api";
import { displayLabel } from "@/lib/format";

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

export default function ContactsPage() {
  const router = useRouter();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [phoneInput, setPhoneInput] = useState("");
  const [users, setUsers] = useState<SyncContactUser[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [chattingUserId, setChattingUserId] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [chatError, setChatError] = useState<string | null>(null);

  useEffect(() => {
    if (!tokens.getAccess()) {
      router.replace("/login");
      return;
    }
    fetchWithAuth((t) => me(t))
      .then(setUser)
      .catch((err) => {
        if (err instanceof ApiCallError && err.status === 401) {
          tokens.clear();
          router.replace("/login");
        }
      });
  }, [router]);

  const handleSync = async () => {
    const raw = phoneInput.trim();
    if (!raw) return;
    const phones = raw.split(/[,\n]/).map((p) => p.trim()).filter(Boolean);
    if (phones.length === 0) return;

    setSyncing(true);
    setSyncError(null);
    try {
      const result = await fetchWithAuth((t) => syncContacts(t, phones));
      setUsers(result);
    } catch (err) {
      setUsers([]);
      setSyncError(err instanceof Error ? err.message : "Sync failed");
    } finally {
      setSyncing(false);
    }
  };

  const handleChat = async (contactUserId: string) => {
    if (!user) return;
    setChattingUserId(contactUserId);
    setChatError(null);
    try {
      const convs = await fetchWithAuth((t) => listConversations(t));
      const existing = convs.find(
        (c) =>
          !c.is_group &&
          c.members?.length === 2 &&
          c.members.includes(user.id) &&
          c.members.includes(contactUserId),
      );
      if (existing) {
        router.push(`/chats?conversation=${existing.id}`);
        return;
      }
      const conv = await fetchWithAuth((t) =>
        createConversation(t, [user.id, contactUserId]),
      );
      router.push(`/chats?conversation=${conv.id}`);
    } catch (err) {
      setChatError(err instanceof Error ? err.message : "Failed to start chat");
    } finally {
      setChattingUserId(null);
    }
  };

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
          <div className="mt-1 flex items-center gap-2 rounded-lg bg-indigo-600/20 px-3 py-2 text-sm font-medium text-indigo-400">
            <ContactsIcon />
            Contacts
          </div>
          <Link href="/profile" className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <ProfileIcon />
            Profile
          </Link>
        </nav>
        <div className="border-t border-zinc-800 p-3">
          <button
            onClick={() => {
              tokens.clear();
              router.push("/login");
            }}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-red-950 hover:text-red-400"
          >
            <LogoutIcon />
            Logout
          </button>
        </div>
      </aside>

      <div className="flex flex-1 flex-col overflow-auto p-6">
        <h1 className="mb-6 text-xl font-semibold">Contacts</h1>

        <div className="mb-6">
          <textarea
            value={phoneInput}
            onChange={(e) => setPhoneInput(e.target.value)}
            placeholder="Paste phone numbers (comma or new line)"
            rows={6}
            className="w-full max-w-lg resize-none rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-3 text-sm text-zinc-100 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <button
            onClick={handleSync}
            disabled={!phoneInput.trim() || syncing}
            className="mt-3 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium hover:bg-indigo-500 disabled:opacity-50"
          >
            {syncing ? "Syncing..." : "Sync"}
          </button>
          {syncError && (
            <p className="mt-2 text-sm text-red-400">{syncError}</p>
          )}
        </div>

        {chatError && (
          <div className="mb-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-400">
            {chatError}
          </div>
        )}

        <div>
          <h2 className="mb-3 text-sm font-semibold text-zinc-400">On Signalix</h2>
          {users.length === 0 ? (
            <p className="text-sm text-zinc-500">No users found. Paste numbers and click Sync.</p>
          ) : (
            <ul className="space-y-2">
              {users.map((u) => (
                <li
                  key={u.user_id}
                  className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3"
                >
                  <span className="text-sm font-medium">{displayLabel(u)}</span>
                  <button
                    onClick={() => handleChat(u.user_id)}
                    disabled={chattingUserId !== null}
                    className="rounded-lg bg-indigo-600 px-3 py-1.5 text-sm font-medium hover:bg-indigo-500 disabled:opacity-50"
                  >
                    {chattingUserId === u.user_id ? "..." : "Chat"}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
