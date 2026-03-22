"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  me,
  tokens,
  fetchWithAuth,
  ApiCallError,
  listConversations,
  listProjects,
  createConversation,
  lookupUserByPhone,
  listMessages,
  createMessage,
  type MeResponse,
  type ProjectResponse,
  type ConversationWithPreview,
  type MessageResponse,
} from "@/lib/api";
import { displayLabel } from "@/lib/format";
import { isValidE164 } from "@/lib/phone";

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

export default function ChatsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [conversations, setConversations] = useState<ConversationWithPreview[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageResponse[]>([]);
  const [inputText, setInputText] = useState("");
  const [newChatPhone, setNewChatPhone] = useState("");
  const [newChatIsGroup, setNewChatIsGroup] = useState(false);
  const [newChatGroupName, setNewChatGroupName] = useState("");
  const [newChatProjectId, setNewChatProjectId] = useState<string | null>(null);
  const [projects, setProjects] = useState<ProjectResponse[]>([]);
  const [creatingConv, setCreatingConv] = useState(false);
  const [convsLoading, setConvsLoading] = useState(true);
  const [msgsLoading, setMsgsLoading] = useState(false);
  const [sendLoading, setSendLoading] = useState(false);
  const [newChatError, setNewChatError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadConversations = useCallback(async () => {
    await fetchWithAuth(async (accessToken) => {
      const convs = await listConversations(accessToken);
      setConversations(convs);
    });
  }, []);

  const loadMessages = useCallback(
    async (convId: string) => {
      setMsgsLoading(true);
      try {
        await fetchWithAuth(async (accessToken) => {
          const msgs = await listMessages(accessToken, convId);
          setMessages(msgs);
        });
      } finally {
        setMsgsLoading(false);
      }
    },
    [],
  );

  // Auth
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

  // Load conversations
  useEffect(() => {
    if (!tokens.getAccess()) return;
    setConvsLoading(true);
    loadConversations().finally(() => setConvsLoading(false));
  }, [loadConversations]);

  // Load projects (for new-chat dropdown)
  useEffect(() => {
    if (!tokens.getAccess()) return;
    fetchWithAuth((t) => listProjects(t)).then(setProjects).catch(() => {});
  }, []);

  // Preselect project from URL (e.g. /chats?project=ID from project detail "New Chat in Project")
  const presetProjectId = searchParams.get("project");
  useEffect(() => {
    if (presetProjectId) setNewChatProjectId(presetProjectId);
  }, [presetProjectId]);

  // Open conversation from URL (e.g. after "Chat" on contacts)
  const openConversationId = searchParams.get("conversation");
  useEffect(() => {
    if (!openConversationId) return;
    let cancelled = false;
    fetchWithAuth((t) => listConversations(t))
      .then((convs) => {
        if (cancelled) return;
        setConversations(convs);
        setActiveConversationId(openConversationId);
        router.replace("/chats");
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [openConversationId, router]);

  // Load messages when active conversation changes
  useEffect(() => {
    if (activeConversationId) {
      loadMessages(activeConversationId);
    } else {
      setMessages([]);
    }
  }, [activeConversationId, loadMessages]);

  // Poll every 3s
  useEffect(() => {
    if (!tokens.getAccess()) return;
    pollRef.current = setInterval(() => {
      loadConversations();
      if (activeConversationId) {
        fetchWithAuth((t) => listMessages(t, activeConversationId)).then(setMessages);
      }
    }, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [loadConversations, activeConversationId]);

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    const text = inputText.trim();
    if (!text || !activeConversationId || !user) return;

    const body_ciphertext_base64 = btoa(unescape(encodeURIComponent(text)));
    const body_preview = text.slice(0, 80);

    setSendLoading(true);
    try {
      const msg = await fetchWithAuth((t) =>
        createMessage(t, activeConversationId, body_ciphertext_base64, body_preview),
      );
      setMessages((prev) => [msg, ...prev]);
      setInputText("");
      setConversations((prev) =>
        prev.map((c) =>
          c.id === activeConversationId
            ? { ...c, last_message_preview: body_preview, last_message_at: msg.sent_at }
            : c,
        ),
      );
    } catch {
      // Error handling could be improved
    } finally {
      setSendLoading(false);
    }
  };

  const handleRefresh = () => {
    loadConversations();
    if (activeConversationId) loadMessages(activeConversationId);
  };

  const handleNewChat = async () => {
    const input = newChatPhone.trim();
    if (!input || !user) return;
    const phones = input.split(",").map((p) => p.trim()).filter(Boolean);
    setNewChatError(null);
    if (phones.length === 0) return;
    if (newChatIsGroup && phones.length < 2) {
      setNewChatError("Group requires at least 2 members");
      return;
    }
    if (!newChatIsGroup && phones.length !== 1) {
      setNewChatError("1:1 chat requires exactly one phone number");
      return;
    }
    setCreatingConv(true);
    try {
      const memberIds: string[] = [user.id];
      for (const phone of phones) {
        const { user_id } = await fetchWithAuth((t) => lookupUserByPhone(t, phone));
        if (user_id === user.id) {
          setNewChatError("Cannot chat with yourself");
          return;
        }
        if (!memberIds.includes(user_id)) memberIds.push(user_id);
      }
      if (!newChatIsGroup && memberIds.length === 2) {
        const convs = await fetchWithAuth((t) => listConversations(t));
        const existing = convs.find(
          (c) =>
            !c.is_group &&
            c.members?.length === 2 &&
            c.members.includes(user.id) &&
            c.members.includes(memberIds[1]),
        );
        if (existing) {
          setActiveConversationId(existing.id);
          await loadConversations();
          setNewChatPhone("");
          setNewChatGroupName("");
          return;
        }
      }
      const title = newChatIsGroup ? newChatGroupName.trim() || undefined : undefined;
      const projectId = newChatProjectId && newChatProjectId.trim() ? newChatProjectId : undefined;
      const res = await fetchWithAuth((t) =>
        createConversation(t, memberIds, title || undefined, projectId),
      );
      await loadConversations();
      setActiveConversationId(res.id);
      setNewChatPhone("");
      setNewChatGroupName("");
      setNewChatProjectId(null);
    } catch (err) {
      setNewChatError(err instanceof Error ? err.message : "Failed to create chat");
    } finally {
      setCreatingConv(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const activeConv = conversations.find((c) => c.id === activeConversationId);

  // E.164 validation for New Chat
  const trimmedPhone = newChatPhone.trim();
  const phoneParts = trimmedPhone ? trimmedPhone.split(",").map((p) => p.trim()).filter(Boolean) : [];
  const is1x1Valid = !newChatIsGroup && phoneParts.length === 1 && isValidE164(phoneParts[0]!);
  const isGroupValid = newChatIsGroup && phoneParts.length >= 2 && phoneParts.every(isValidE164);
  const isPhoneValid = is1x1Valid || isGroupValid;
  const phoneValidationError =
    trimmedPhone.length > 0 && !isPhoneValid
      ? "Enter a valid phone number (E.164, e.g. +491234567890)."
      : null;

  return (
    <div className="flex h-screen w-full overflow-hidden bg-zinc-950 text-zinc-100">
      {/* Sidebar */}
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
          <div className="mt-1 flex items-center gap-2 rounded-lg bg-indigo-600/20 px-3 py-2 text-sm font-medium text-indigo-400">
            <ChatIcon />
            Chats
          </div>
          <Link href="/contacts" className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100">
            <ContactsIcon />
            Contacts
          </Link>
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

      {/* Chat layout */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="flex h-full min-w-0">
          {/* Conversation list */}
          <div className="flex w-80 shrink-0 flex-col border-r border-zinc-800 bg-zinc-900">
            <div className="flex flex-col gap-2 border-b border-zinc-800 px-4 py-3">
              <h2 className="text-lg font-semibold">Chats</h2>
              <label className="text-sm text-zinc-400">Project (optional)</label>
              <select
                value={newChatProjectId ?? ""}
                onChange={(e) => setNewChatProjectId(e.target.value || null)}
                className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 focus:border-indigo-500 focus:outline-none"
              >
                <option value="">— None —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={newChatIsGroup}
                  onChange={(e) => setNewChatIsGroup(e.target.checked)}
                  className="rounded border-zinc-600"
                />
                Group
              </label>
              {newChatIsGroup && (
                <input
                  type="text"
                  value={newChatGroupName}
                  onChange={(e) => setNewChatGroupName(e.target.value)}
                  placeholder="Group name"
                  className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
                />
              )}
              <input
                type="text"
                value={newChatPhone}
                onChange={(e) => { setNewChatPhone(e.target.value); setNewChatError(null); }}
                placeholder={newChatIsGroup ? "+49..., +49..., +49..." : "Phone number for new chat"}
                className={`rounded-lg border px-3 py-2 text-sm placeholder-zinc-500 focus:outline-none ${
                  phoneValidationError
                    ? "border-red-500 bg-zinc-800 focus:border-red-500"
                    : "border-zinc-700 bg-zinc-800 focus:border-indigo-500"
                }`}
              />
              {phoneValidationError && (
                <p className="text-xs text-red-400">{phoneValidationError}</p>
              )}
              {newChatError && !phoneValidationError && (
                <p className="text-xs text-red-400">{newChatError}</p>
              )}
              <button
                onClick={handleNewChat}
                disabled={!isPhoneValid || creatingConv}
                className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium hover:bg-indigo-500 disabled:opacity-50"
              >
                {creatingConv ? "..." : "New"}
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">
              {convsLoading ? (
                <div className="flex items-center justify-center py-8 text-zinc-500">
                  <span className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
                </div>
              ) : conversations.length === 0 ? (
                <p className="px-4 py-6 text-sm text-zinc-500">No conversations yet</p>
              ) : (
                <ul>
                  {conversations.map((c) => (
                    <li key={c.id}>
                      <button
                        onClick={() => setActiveConversationId(c.id)}
                        className={`w-full px-4 py-3 text-left transition ${
                          activeConversationId === c.id
                            ? "bg-indigo-600/20"
                            : "hover:bg-zinc-800"
                        }`}
                      >
                        <p className="truncate text-sm font-medium">
                          {c.display_title || "Chat"}
                        </p>
                        <p className="truncate text-xs text-zinc-500">
                          {c.last_message_preview || "No messages"}
                        </p>
                        {c.last_message_at && (
                          <p className="mt-0.5 text-xs text-zinc-600">
                            {formatTime(c.last_message_at)}
                          </p>
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {/* Message panel */}
          <div className="flex flex-1 flex-col min-w-0">
            {!activeConversationId ? (
              <div className="flex flex-1 flex-col items-center justify-center text-zinc-500">
                <ChatIcon className="h-16 w-16 mb-4 opacity-50" />
                <p className="text-sm">Select a conversation</p>
              </div>
            ) : (
              <>
                {/* Header */}
                <header className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-zinc-800 px-4">
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    <h3 className="truncate font-medium">
                      {activeConv?.display_title ?? "Conversation"}
                    </h3>
                    {activeConv?.project_name && (
                      <span className="shrink-0 rounded-full bg-indigo-600/30 px-2 py-0.5 text-xs font-medium text-indigo-300">
                        {activeConv.project_name}
                      </span>
                    )}
                  </div>
                  <button
                    onClick={handleRefresh}
                    className="rounded px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                  >
                    Refresh
                  </button>
                </header>

                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 flex flex-col">
                  {msgsLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <span className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-col gap-2">
                        {[...messages].reverse().map((m) => {
                          const isOwn = m.sender_user_id === user?.id;
                          return (
                            <div
                              key={m.id}
                              className={`flex ${isOwn ? "justify-end" : "justify-start"}`}
                            >
                              <div
                                className={`max-w-[75%] rounded-2xl px-4 py-2 ${
                                  isOwn
                                    ? "rounded-br-md bg-indigo-600 text-white"
                                    : "rounded-bl-md bg-zinc-800 text-zinc-100"
                                }`}
                              >
                                <p className="text-sm whitespace-pre-wrap break-words">
                                  {decodePreview(m)}
                                </p>
                                <p
                                  className={`mt-1 text-xs ${
                                    isOwn ? "text-indigo-200" : "text-zinc-500"
                                  }`}
                                >
                                  {formatTime(m.sent_at)}
                                </p>
                              </div>
                            </div>
                          );
                        })}
                        <div ref={messagesEndRef} />
                      </div>
                    </>
                  )}
                </div>

                {/* Input */}
                <div className="shrink-0 border-t border-zinc-800 p-4">
                  <div className="flex gap-2">
                    <textarea
                      value={inputText}
                      onChange={(e) => setInputText(e.target.value)}
                      onKeyDown={handleKeyDown}
                      placeholder="Type a message..."
                      rows={1}
                      className="flex-1 resize-none rounded-xl border border-zinc-700 bg-zinc-800 px-4 py-3 text-sm text-zinc-100 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                      disabled={sendLoading}
                    />
                    <button
                      onClick={handleSend}
                      disabled={!inputText.trim() || sendLoading}
                      className="shrink-0 rounded-xl bg-indigo-600 px-4 py-3 text-sm font-medium text-white transition hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {sendLoading ? (
                        <span className="h-4 w-4 block animate-spin rounded-full border-2 border-white border-t-transparent" />
                      ) : (
                        "Send"
                      )}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function decodePreview(m: MessageResponse): string {
  try {
    return decodeURIComponent(escape(atob(m.body_ciphertext)));
  } catch {
    return m.body_preview || "(encrypted)";
  }
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

function ChatIcon({ className }: { className?: string }) {
  return (
    <svg className={`h-4 w-4 shrink-0 ${className ?? ""}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
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
