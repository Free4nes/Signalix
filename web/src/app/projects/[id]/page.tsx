"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  tokens,
  fetchWithAuth,
  ApiCallError,
  getProject,
  listProjectActivity,
  type ProjectWithConversationsResponse,
  type ProjectActivityItem,
} from "@/lib/api";

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    const now = new Date();
    const sameDay =
      d.getDate() === now.getDate() &&
      d.getMonth() === now.getMonth() &&
      d.getFullYear() === now.getFullYear();
    if (sameDay) {
      return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = typeof params.id === "string" ? params.id : null;
  const [project, setProject] = useState<ProjectWithConversationsResponse | null>(null);
  const [activity, setActivity] = useState<ProjectActivityItem[]>([]);
  const [activityHasMore, setActivityHasMore] = useState(false);
  const [activityNextCursor, setActivityNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tokens.getAccess()) {
      router.replace("/login");
      return;
    }
    if (!id) {
      setLoading(false);
      setError("Invalid project");
      return;
    }
    setLoading(true);
    setError(null);
    Promise.all([
      fetchWithAuth((t) => getProject(t, id)),
      fetchWithAuth((t) => listProjectActivity(t, id)),
    ])
      .then(([proj, page]) => {
        setProject(proj);
        setActivity(page.items ?? []);
        setActivityHasMore(page.has_more ?? false);
        setActivityNextCursor(page.next_cursor ?? null);
      })
      .catch((err) => {
        if (err instanceof ApiCallError && err.status === 401) {
          tokens.clear();
          router.replace("/login");
        } else if (err instanceof ApiCallError && err.status === 404) {
          router.replace("/dashboard");
          return;
        } else if (err instanceof ApiCallError && err.status === 403) {
          setError("You don't have access to this project");
        } else {
          setError(err instanceof Error ? err.message : "Failed to load project");
        }
      })
      .finally(() => setLoading(false));
  }, [id, router]);

  if (!id || loading) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-zinc-950 text-zinc-100">
        <span className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
      </div>
    );
  }

  if (error || !project) {
    return (
      <div className="flex h-screen w-full flex-col items-center justify-center gap-4 bg-zinc-950 text-zinc-100">
        <p className="text-red-400">{error ?? "Project not found"}</p>
        <Link
          href="/dashboard"
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium hover:bg-indigo-500"
        >
          Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-full overflow-hidden bg-zinc-950 text-zinc-100">
      <aside className="flex w-56 shrink-0 flex-col border-r border-zinc-800 bg-zinc-900">
        <div className="flex h-16 items-center border-b border-zinc-800 px-5">
          <Link href="/dashboard" className="text-lg font-bold tracking-tight text-white hover:text-zinc-200">
            Signalix
          </Link>
        </div>
        <nav className="flex-1 px-3 py-4">
          <Link
            href="/dashboard"
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100"
          >
            <GridIcon />
            Dashboard
          </Link>
          <Link
            href="/chats"
            className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100"
          >
            <ChatIcon />
            Chats
          </Link>
          <Link href="/contacts" className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <ContactsIcon />
            Contacts
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

      <main className="flex flex-1 flex-col overflow-auto">
        <header className="flex h-16 shrink-0 items-center border-b border-zinc-800 px-6">
          <Link href="/dashboard" className="text-sm text-zinc-400 hover:text-zinc-200">
            ← Dashboard
          </Link>
        </header>

        <div className="flex-1 p-6">
          <h1 className="mb-2 text-2xl font-semibold">{project.name}</h1>
          <p className="mb-6 text-sm text-zinc-500">
            Created {project.created_at ? new Date(project.created_at).toLocaleDateString() : ""}
          </p>

          <div className="mb-4">
            <Link
              href={`/chats?project=${project.id}`}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium hover:bg-indigo-500"
            >
              New Chat in Project
            </Link>
          </div>

          <h2 className="mb-3 text-base font-semibold text-zinc-200">Activity</h2>
          {activity.length === 0 ? (
            <p className="mb-6 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-4 text-sm text-zinc-500">
              No activity yet.
            </p>
          ) : (
            <div className="mb-6">
              <ul className="mb-4 space-y-2">
                {activity.map((a) => (
                  <li
                    key={a.id}
                    className="flex flex-col gap-0.5 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2"
                  >
                    <span className="text-sm font-medium text-zinc-100">
                      {a.summary}
                    </span>
                    <span className="text-xs text-zinc-500">
                      {new Date(a.timestamp).toLocaleString()} · Actor: {a.actor_label}
                    </span>
                  </li>
                ))}
              </ul>
              {activityHasMore && (
                <button
                  onClick={async () => {
                    if (!activityNextCursor || loadingMore || !id) return;
                    setLoadingMore(true);
                    try {
                      const page = await fetchWithAuth((t) =>
                        listProjectActivity(t, id, {
                          before: activityNextCursor,
                          limit: 20,
                        }),
                      );
                      setActivity((prev) => [...prev, ...page.items]);
                      setActivityHasMore(page.has_more);
                      setActivityNextCursor(page.next_cursor);
                    } finally {
                      setLoadingMore(false);
                    }
                  }}
                  disabled={loadingMore}
                  className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-200 disabled:opacity-50"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </button>
              )}
            </div>
          )}

          <h2 className="mb-3 text-base font-semibold text-zinc-200">Chats</h2>
          {project.conversations.length === 0 ? (
            <p className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-6 text-sm text-zinc-500">
              No chats in this project yet. Create one with &quot;New Chat in Project&quot; above.
            </p>
          ) : (
            <ul className="space-y-1">
              {project.conversations.map((c) => (
                <li key={c.id}>
                  <Link
                    href={`/chats?conversation=${c.id}`}
                    className="flex flex-col rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 transition hover:bg-zinc-800"
                  >
                    <span className="font-medium text-zinc-100">{c.display_title || "Chat"}</span>
                    <span className="truncate text-sm text-zinc-500">
                      {c.last_message_preview || "No messages"}
                    </span>
                    {c.updated_at && (
                      <span className="mt-0.5 text-xs text-zinc-600">
                        {formatTime(c.updated_at)}
                      </span>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </main>
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

function LogoutIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h6a2 2 0 012 2v1" />
    </svg>
  );
}
