import { Platform } from "react-native";
import Constants from "expo-constants";

// ── Base URL ──────────────────────────────────────────────────────────────────
// Set EXPO_PUBLIC_API_HOST in .env (e.g. http://192.168.0.131:8080) for real-device. Else emulator uses 10.0.2.2.

function resolveApiBase(): string {
  const configured = (Constants.expoConfig?.extra?.apiBaseUrl as string | undefined)?.trim();
  if (configured) return configured.replace(/\/$/, "");
  if (Platform.OS === "android") return "http://10.0.2.2:8080";
  return "http://localhost:8080";
}

export const API_BASE = resolveApiBase();

// Temporary debug: remove when real-device API is confirmed
console.log("RESOLVED_API_BASE_URL=" + API_BASE);

// ── Generic fetch helper ──────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit & { token?: string } = {}
): Promise<T> {
  const { token, ...rest } = options;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(rest.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const url = `${API_BASE}${path}`;
  if (__DEV__ && path.includes("blocked")) {
    console.log("BLOCKED_USERS_FETCH_REQUEST url=", url, "hasAuth=", !!token);
  }
  if (__DEV__ && path.match(/\/conversations\/[^/]+\/?$/) && !path.includes("messages")) {
    console.log("GROUP_DETAILS_FETCH url=", url, "hasAuth=", !!token);
  }
  const res = await fetch(url, { ...rest, headers });
  if (__DEV__ && path.includes("blocked")) {
    console.log("BLOCKED_USERS_FETCH_RESPONSE status=", res.status, "ok=", res.ok);
  }
  if (__DEV__ && path.includes("verify_otp")) {
    console.log("OTP_VERIFY_RESPONSE", { url, status: res.status, ok: res.ok });
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
      if (__DEV__ && path.includes("verify_otp")) console.log("OTP_VERIFY_RESPONSE_BODY_ERROR", body);
    } catch {}
    throw new ApiError(res.status, msg);
  }
  // 204 No Content
  if (res.status === 204) return undefined as T;
  const data = (await res.json()) as T;
  if (__DEV__ && path.includes("verify_otp")) {
    console.log("OTP_VERIFY_RESPONSE_BODY", { hasAccessToken: !!(data as { access_token?: string })?.access_token });
  }
  return data;
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  phone_number: string;
  display_name?: string;
  avatar_url?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Conversation {
  id: string;
  is_group: boolean;
  title?: string;
  display_title: string;
  members: string[];
  other_avatar_url?: string | null;
  project_id?: string;
  project_name?: string;
  last_message_preview: string;
  last_message_at?: string;
}

export interface ConversationMember {
  user_id: string;
  phone_number: string;
  display_name?: string;
  avatar_url?: string;
}

export interface ConversationDetail {
  id: string;
  is_group: boolean;
  title?: string;
  display_title: string;
  members: ConversationMember[];
  project_id?: string;
  project_name?: string;
}

export interface Message {
  id: string;
  sender_user_id: string;
  sender_display_name?: string;
  sent_at: string;
  body_ciphertext: string; // base64
  body_preview: string;
  msg_type: "text" | "audio" | "image";
  audio_url?: string;
  audio_duration_ms?: number;
  audio_mime?: string;
  deleted_for_everyone?: boolean;
  deleted_at?: string;
  status?: "sent" | "delivered" | "read";
  read_at?: string | null;
  edited_at?: string | null;
  reply_to_id?: string | null;
  reply_to?: { id: string; body: string };
  reactions?: Record<string, number>;
  my_reaction?: string;
}

export interface SyncUser {
  user_id: string;
  phone_number: string;
  display_name?: string;
}

// ── Auth endpoints ────────────────────────────────────────────────────────────

export async function requestOtp(phoneNumber: string): Promise<{ message: string; dev_otp?: string }> {
  return request("/auth/request_otp", {
    method: "POST",
    body: JSON.stringify({ phone_number: phoneNumber }),
  });
}

export async function verifyOtp(
  phoneNumber: string,
  otp: string
): Promise<AuthTokens & { user: AuthUser }> {
  return request("/auth/verify_otp", {
    method: "POST",
    body: JSON.stringify({ phone_number: phoneNumber, otp }),
  });
}

export async function refreshTokens(
  refreshToken: string
): Promise<AuthTokens> {
  return request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export async function logout(refreshToken: string, token: string): Promise<void> {
  return request("/auth/logout", {
    method: "POST",
    token,
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export async function getMe(token: string): Promise<AuthUser> {
  return request("/me", { token });
}

export async function patchMe(
  token: string,
  displayName: string | null
): Promise<AuthUser> {
  return request("/me", {
    method: "PATCH",
    token,
    body: JSON.stringify({ display_name: displayName?.trim() || null }),
  });
}

export async function putMeAvatar(
  token: string,
  avatarUrl: string
): Promise<AuthUser> {
  return request("/me/avatar", {
    method: "PUT",
    token,
    body: JSON.stringify({ avatar_url: avatarUrl }),
  });
}

export interface UserOnlineStatus {
  online: boolean;
  last_seen?: string;
}

export async function getUserOnlineStatus(token: string, userId: string): Promise<UserOnlineStatus> {
  return request(`/users/${userId}/online-status`, { token });
}

export interface BlockedUser {
  user_id: string;
  phone: string;
  display_name: string;
}

export async function listBlockedUsers(token: string): Promise<BlockedUser[]> {
  if (__DEV__) console.log("BLOCKED_USERS_API_CALL hasToken=", !!token, "tokenLength=", token?.length ?? 0);
  return request("/users/blocked", { method: "GET", token });
}

export async function blockUser(token: string, blockedUserId: string): Promise<void> {
  await request("/users/block", {
    method: "POST",
    token,
    body: JSON.stringify({ blocked_user_id: blockedUserId }),
  });
}

export async function unblockUser(token: string, blockedUserId: string): Promise<void> {
  await request(`/users/block/${blockedUserId}`, {
    method: "DELETE",
    token,
  });
}

export async function savePushToken(
  token: string,
  expoPushToken: string,
  platform: "android" | "ios"
): Promise<void> {
  await request("/me/push-token", {
    method: "POST",
    token,
    body: JSON.stringify({ expo_push_token: expoPushToken, platform }),
  });
}

// ── Conversations ─────────────────────────────────────────────────────────────

export async function listConversations(token: string): Promise<Conversation[]> {
  return request("/conversations", { token });
}

export async function getConversation(
  token: string,
  conversationId: string
): Promise<ConversationDetail> {
  return request(`/conversations/${conversationId}`, { token });
}

export async function updateConversationTitle(
  token: string,
  conversationId: string,
  title: string
): Promise<Conversation> {
  return request(`/conversations/${conversationId}`, {
    method: "PATCH",
    token,
    body: JSON.stringify({ title: title.trim() || null }),
  });
}

export async function addConversationMember(
  token: string,
  conversationId: string,
  userId: string
): Promise<Conversation> {
  return request(`/conversations/${conversationId}/members`, {
    method: "POST",
    token,
    body: JSON.stringify({ user_id: userId }),
  });
}

export async function removeConversationMember(
  token: string,
  conversationId: string,
  userId: string
): Promise<Conversation> {
  return request(`/conversations/${conversationId}/members/${userId}`, {
    method: "DELETE",
    token,
  });
}

export async function listMessages(
  token: string,
  conversationId: string,
  limit = 50
): Promise<Message[]> {
  return request(`/conversations/${conversationId}/messages?limit=${limit}`, { token });
}

export async function clearConversationMessages(
  token: string,
  conversationId: string
): Promise<void> {
  const url = `${API_BASE}/conversations/${conversationId}/messages`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {}
    throw new ApiError(res.status, msg);
  }
}

export async function searchMessages(
  token: string,
  conversationId: string,
  q: string
): Promise<Message[]> {
  const encoded = encodeURIComponent(q);
  return request(`/conversations/${conversationId}/messages/search?q=${encoded}`, { token });
}

export async function editMessage(
  token: string,
  messageId: string,
  body: string
): Promise<Message> {
  return request(`/messages/${messageId}`, {
    method: "PUT",
    token,
    body: JSON.stringify({ body }),
  });
}

export async function deleteMessage(
  token: string,
  _conversationId: string,
  messageId: string,
  mode: "everyone" | "me"
): Promise<Message> {
  const url = `${API_BASE}/messages/${messageId}?mode=${mode}`;
  if (__DEV__) {
    console.log("[delete] DELETE", url);
  }
  const res = await fetch(url, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {}
    if (__DEV__) {
      console.warn("[delete] failed", res.status, msg);
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<Message>;
}

export async function uploadImage(
  token: string,
  uri: string,
  mimeType = "image/jpeg"
): Promise<{ url: string }> {
  const url = `${API_BASE}/upload`;
  const formData = new FormData();
  const ext = mimeType === "image/png" ? ".png" : mimeType === "image/webp" ? ".webp" : mimeType === "image/gif" ? ".gif" : ".jpg";
  formData.append("file", {
    uri,
    name: (uri.split("/").pop() ?? "image").replace(/\.[^.]+$/, "") + ext,
    type: mimeType,
  } as unknown as Blob);

  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<{ url: string }>;
}

export async function sendImageMessage(
  token: string,
  conversationId: string,
  imageUrl: string,
  replyToId?: string | null
): Promise<Message> {
  const body: Record<string, unknown> = {
    msg_type: "image",
    body_preview: imageUrl,
    body_ciphertext_base64: "",
    reply_to_id: replyToId ?? null,
  };
  return request(`/conversations/${conversationId}/messages`, {
    method: "POST",
    token,
    body: JSON.stringify(body),
  });
}

export interface AudioUploadResult {
  audio_url: string;
  audio_duration_ms: number;
  audio_mime: string;
  message_id: string;
}

export async function sendAudioMessage(
  token: string,
  conversationId: string,
  uri: string,
  durationMs: number,
  mimeType = "audio/mp4"
): Promise<AudioUploadResult> {
  const url = `${API_BASE}/conversations/${conversationId}/audio`;
  const formData = new FormData();
  const ext = mimeType.includes("mpeg")
    ? ".mp3"
    : mimeType.includes("ogg")
      ? ".ogg"
      : mimeType.includes("webm")
        ? ".webm"
        : ".m4a";
  const baseName = (uri.split("/").pop() ?? "voice").replace(/\.[^.]+$/, "");
  formData.append("file", {
    uri,
    name: `${baseName}${ext}`,
    type: mimeType,
  } as unknown as Blob);
  if (durationMs > 0) {
    formData.append("duration_ms", String(Math.round(durationMs)));
  }

  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<AudioUploadResult>;
}

export async function sendMessage(
  token: string,
  conversationId: string,
  text: string,
  replyToId?: string | null
): Promise<Message> {
  // No E2E encryption yet: store plaintext as both ciphertext bytes and preview.
  // Use Uint8Array → base64 without spreading into args (avoids stack overflow on long strings).
  const bytes = new TextEncoder().encode(text);
  let b64 = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    b64 += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  b64 = btoa(b64);
  const body: Record<string, unknown> = {
    body_ciphertext_base64: b64,
    body_preview: text,
    reply_to_id: replyToId ?? null,
  };
  return request(`/conversations/${conversationId}/messages`, {
    method: "POST",
    token,
    body: JSON.stringify(body),
  });
}

export async function createConversation(
  token: string,
  memberUserIds: string[],
  title?: string
): Promise<Conversation> {
  const body: { member_user_ids: string[]; title?: string } = {
    member_user_ids: memberUserIds,
  };
  if (title != null && title.trim() !== "") {
    body.title = title.trim();
  }
  return request("/conversations", {
    method: "POST",
    token,
    body: JSON.stringify(body),
  });
}

// ── Contacts ──────────────────────────────────────────────────────────────────

export async function lookupContact(
  token: string,
  phoneNumber: string
): Promise<{ user_id: string }> {
  return request("/contacts/lookup", {
    method: "POST",
    token,
    body: JSON.stringify({ phone_number: phoneNumber }),
  });
}

export async function syncContacts(
  token: string,
  phones: string[]
): Promise<SyncUser[]> {
  const res = await request<{ users: SyncUser[] }>("/contacts/sync", {
    method: "POST",
    token,
    body: JSON.stringify({ phones }),
  });
  return res.users;
}

