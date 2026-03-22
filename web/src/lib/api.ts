const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080";

// ── Token storage ────────────────────────────────────────────────────────────

export const tokens = {
  getAccess: (): string | null =>
    typeof window !== "undefined" ? localStorage.getItem("access_token") : null,
  getRefresh: (): string | null =>
    typeof window !== "undefined" ? localStorage.getItem("refresh_token") : null,
  set: (access: string, refresh: string) => {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
  },
  clear: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },
};

// ── Raw API calls ─────────────────────────────────────────────────────────────

export interface RequestOtpResponse {
  message: string;
  dev_otp?: string;
}

export interface VerifyOtpResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: { id: string; phone_number: string; display_name?: string | null };
}

export interface RefreshResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface MeResponse {
  id: string;
  phone_number: string;
  display_name?: string | null;
}

export interface ApiError {
  error: string;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as T;
}

export class ApiCallError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiCallError";
  }
}

export async function requestOtp(phone_number: string): Promise<RequestOtpResponse> {
  return post<RequestOtpResponse>("/auth/request_otp", { phone_number });
}

export async function verifyOtp(
  phone_number: string,
  otp: string,
): Promise<VerifyOtpResponse> {
  return post<VerifyOtpResponse>("/auth/verify_otp", { phone_number, otp });
}

export async function refresh(refresh_token: string): Promise<RefreshResponse> {
  return post<RefreshResponse>("/auth/refresh", { refresh_token });
}

// ── Projects ──────────────────────────────────────────────────────────────────

export interface ProjectResponse {
  id: string;
  name: string;
  created_at: string;
}

export interface KeyResponse {
  id: string;
  name: string;
  last4: string;
  created_at: string;
  revoked_at?: string | null;
}

export interface CreateKeyResponse extends KeyResponse {
  api_key: string;
}

export async function createProject(access_token: string, name: string): Promise<ProjectResponse> {
  const res = await fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
    body: JSON.stringify({ name }),
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as ProjectResponse;
}

export async function listProjects(access_token: string): Promise<ProjectResponse[]> {
  const res = await fetch(`${BASE}/projects`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return (data ?? []) as ProjectResponse[];
}

export interface ProjectConversationResponse {
  id: string;
  display_title: string;
  last_message_preview: string;
  updated_at: string;
}

export interface ProjectWithConversationsResponse {
  id: string;
  name: string;
  created_at: string;
  conversations: ProjectConversationResponse[];
}

export interface ProjectActivityItem {
  id: string;
  type: string;
  timestamp: string;
  actor_id: string;
  actor_label: string;
  summary: string;
}

export interface ProjectActivityPage {
  items: ProjectActivityItem[];
  next_cursor: string | null;
  has_more: boolean;
}

export async function listProjectActivity(
  access_token: string,
  projectId: string,
  options?: { before?: string; limit?: number },
): Promise<ProjectActivityPage> {
  const params = new URLSearchParams();
  if (options?.before) params.set("before", options.before);
  if (options?.limit != null) params.set("limit", String(options.limit));
  const qs = params.toString();
  const url = `${BASE}/projects/${projectId}/activity${qs ? `?${qs}` : ""}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  const raw = data as { items: ProjectActivityItem[]; next_cursor?: string | null; has_more: boolean };
  return {
    items: raw.items ?? [],
    next_cursor: raw.next_cursor ?? null,
    has_more: raw.has_more ?? false,
  };
}

export async function getProject(
  access_token: string,
  projectId: string,
): Promise<ProjectWithConversationsResponse> {
  const res = await fetch(`${BASE}/projects/${projectId}`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as ProjectWithConversationsResponse;
}

export async function archiveProject(
  access_token: string,
  projectId: string,
): Promise<void> {
  const res = await fetch(`${BASE}/projects/${projectId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${access_token}` },
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  }
}

/** @deprecated use listProjects */
export const getProjects = listProjects;

export async function createKey(
  access_token: string,
  projectId: string,
  name: string,
): Promise<CreateKeyResponse> {
  const res = await fetch(`${BASE}/projects/${projectId}/keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
    body: JSON.stringify({ name }),
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as CreateKeyResponse;
}

export async function listKeys(access_token: string, projectId: string): Promise<KeyResponse[]> {
  const res = await fetch(`${BASE}/projects/${projectId}/keys`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return (data ?? []) as KeyResponse[];
}

export async function revokeKey(
  access_token: string,
  projectId: string,
  keyId: string,
): Promise<void> {
  const res = await fetch(`${BASE}/projects/${projectId}/keys/${keyId}/revoke`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}` },
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  }
}

// ── Events ────────────────────────────────────────────────────────────────────

export interface EventResponse {
  id: string;
  event: string;
  received_at: string;
  payload: unknown;
}

export async function listEvents(
  access_token: string,
  projectId: string,
): Promise<EventResponse[]> {
  const res = await fetch(`${BASE}/projects/${projectId}/events`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return (data ?? []) as EventResponse[];
}

// ── Contacts ─────────────────────────────────────────────────────────────────

export interface LookupUserResponse {
  user_id: string;
}

export interface SyncContactUser {
  user_id: string;
  phone_number: string;
  display_name?: string | null;
}

export async function syncContacts(
  access_token: string,
  phones: string[],
): Promise<SyncContactUser[]> {
  const res = await fetch(`${BASE}/contacts/sync`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
    },
    body: JSON.stringify({ phones }),
  });
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  const parsed = data as { users: SyncContactUser[] };
  return parsed.users ?? [];
}

export async function lookupUserByPhone(
  access_token: string,
  phone_number: string,
): Promise<LookupUserResponse> {
  const res = await fetch(`${BASE}/contacts/lookup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
    },
    body: JSON.stringify({ phone_number }),
  });
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as LookupUserResponse;
}

// ── Chat ─────────────────────────────────────────────────────────────────────

export interface ConversationWithPreview {
  id: string;
  is_group: boolean;
  title?: string | null;
  display_title: string;
  members: string[];
  project_id?: string | null;
  project_name?: string;
  last_message_preview: string;
  last_message_at: string | null;
}

export interface MessageResponse {
  id: string;
  sender_user_id: string;
  sent_at: string;
  body_ciphertext: string;
  body_preview: string;
}

export interface CreateConversationResponse {
  id: string;
  is_group: boolean;
  title?: string | null;
  display_title: string;
  members: string[];
  project_id?: string | null;
  project_name?: string;
}

export async function createConversation(
  access_token: string,
  member_user_ids: string[],
  title?: string | null,
  project_id?: string | null,
): Promise<CreateConversationResponse> {
  const body: { member_user_ids: string[]; title?: string; project_id?: string } = { member_user_ids };
  if (title != null && title.trim() !== "") body.title = title;
  if (project_id != null && project_id.trim() !== "") body.project_id = project_id;
  const res = await fetch(`${BASE}/conversations`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
    },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as CreateConversationResponse;
}

export async function listConversations(
  access_token: string,
): Promise<ConversationWithPreview[]> {
  const res = await fetch(`${BASE}/conversations`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return (data ?? []) as ConversationWithPreview[];
}

export async function listMessages(
  access_token: string,
  conversationId: string,
  limit = 50,
): Promise<MessageResponse[]> {
  const res = await fetch(
    `${BASE}/conversations/${conversationId}/messages?limit=${limit}`,
    { headers: { Authorization: `Bearer ${access_token}` } },
  );
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return (data ?? []) as MessageResponse[];
}

export async function createMessage(
  access_token: string,
  conversationId: string,
  body_ciphertext_base64: string,
  body_preview: string,
): Promise<MessageResponse> {
  const res = await fetch(
    `${BASE}/conversations/${conversationId}/messages`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        body_ciphertext_base64,
        body_preview,
      }),
    },
  );
  const data = await res.json();
  if (!res.ok)
    throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as MessageResponse;
}

export async function getMe(access_token: string): Promise<MeResponse> {
  const res = await fetch(`${BASE}/me`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as MeResponse;
}

/** @deprecated use getMe */
export const me = getMe;

export async function updateMeDisplayName(
  access_token: string,
  display_name: string | null,
): Promise<MeResponse> {
  const res = await fetch(`${BASE}/me`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
    },
    body: JSON.stringify({ display_name }),
  });
  const data = await res.json();
  if (!res.ok) throw new ApiCallError(res.status, (data as ApiError).error ?? "unknown error");
  return data as MeResponse;
}

// ── fetchWithAuth ─────────────────────────────────────────────────────────────
// Calls `fn` with the current access token. On 401 it attempts a single token
// refresh, stores the new tokens, and retries. If the refresh itself returns 401
// (reuse detected, revoked, expired) it clears tokens and throws 401 so callers
// can redirect to /login.

export async function fetchWithAuth<T>(fn: (accessToken: string) => Promise<T>): Promise<T> {
  const accessToken = tokens.getAccess();
  if (!accessToken) throw new ApiCallError(401, "not authenticated");

  try {
    return await fn(accessToken);
  } catch (err) {
    if (!(err instanceof ApiCallError && err.status === 401)) throw err;

    const refreshToken = tokens.getRefresh();
    if (!refreshToken) {
      tokens.clear();
      throw new ApiCallError(401, "session expired");
    }

    try {
      const refreshed = await refresh(refreshToken);
      tokens.set(refreshed.access_token, refreshed.refresh_token);
      return await fn(refreshed.access_token);
    } catch (refreshErr) {
      tokens.clear();
      throw new ApiCallError(401, "session expired");
    }
  }
}
