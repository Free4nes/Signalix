import { API_BASE } from "./api";

export type WsEvent =
  | { type: "message.created"; conversation_id: string; message: WsMessage }
  | { type: "message.updated"; conversation_id: string; message: WsMessage }
  | { type: "message.deleted"; conversation_id: string; message_id: string; message?: WsMessage }
  | { type: "message.reaction"; conversation_id: string; message_id: string; user_id: string; reaction: string }
  | { type: "typing"; conversation_id: string; user_id: string; is_typing: boolean }
  | { type: "online_status"; user_id: string; online: boolean; last_seen: string };

export interface WsMessage {
  id: string;
  sender_user_id: string;
  sender_display_name?: string;
  body_preview: string;
  msg_type: string;
  reply_to_id?: string | null;
  deleted_for_everyone?: boolean;
  status?: string;
  sent_at: string;
  [key: string]: unknown;
}

const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_DELAY_MS = 30000;

function wsUrl(): string {
  return API_BASE.replace(/^http/, "ws") + "/ws";
}

type MessageHandler = (event: WsEvent) => void;

export interface WsClient {
  connect: (token: string) => void;
  disconnect: () => void;
  subscribe: (handler: MessageHandler) => () => void;
  send: (payload: unknown) => void;
}

export function createWsClient(): WsClient {
  let ws: WebSocket | null = null;
  let token: string | null = null;
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  let reconnectDelay = RECONNECT_DELAY_MS;
  const handlers = new Set<MessageHandler>();

  function connect(t: string) {
    token = t;
    const base = wsUrl();
    const url = `${base}?token=${encodeURIComponent(token)}`;
    if (__DEV__) {
      console.log("[WS] connecting to", base);
    }
    ws = new WebSocket(url);
    ws.onopen = () => {
      if (__DEV__) console.log("WS_CONNECTED");
      reconnectDelay = RECONNECT_DELAY_MS;
    };
    ws.onclose = () => {
      if (__DEV__) console.log("[WS] disconnected");
      ws = null;
      if (token) {
        reconnectTimeout = setTimeout(() => {
          if (__DEV__) console.log("[WS] reconnecting...");
          connect(token!);
          reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY_MS);
        }, reconnectDelay);
      }
    };
    ws.onerror = () => {
      if (__DEV__) console.warn("[WS] error");
    };
    ws.onmessage = (ev) => {
      try {
        const raw = typeof ev.data === "string" ? ev.data : (ev.data != null ? String(ev.data) : "{}");
        const event = JSON.parse(raw || "{}") as WsEvent;
        if (__DEV__) {
          console.log("WS_RAW_EVENT", event.type ?? "unknown", JSON.stringify(event));
          if (event.type === "message.created") {
            console.log("WS_DISPATCH_MESSAGE_CREATED");
          } else if (event.type === "typing") {
            console.log("WS_DISPATCH_TYPING");
          }
          console.log("WS_SUBSCRIBERS_COUNT", handlers.size);
        }
        handlers.forEach((h) => h(event));
      } catch (e) {
        if (__DEV__) console.warn("[WS] parse error", ev.data, e);
      }
    };
  }

  function disconnect() {
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }
    token = null;
    if (ws) {
      ws.close();
      ws = null;
    }
    // Do not clear handlers - they stay so reconnect keeps subscribers
    if (__DEV__) console.log("[WS] disconnect");
  }

  function subscribe(handler: MessageHandler) {
    handlers.add(handler);
    return () => {
      handlers.delete(handler);
      // Do NOT disconnect when handlers hit 0 – WsProvider controls connect/disconnect via accessToken.
      // Disconnecting here would drop the connection during navigation (e.g. ChatsScreen unmounts
      // before ChatScreen mounts) and prevent re-subscribing screens from receiving events.
    };
  }

  function send(payload: unknown) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
      const s = typeof payload === "string" ? payload : JSON.stringify(payload);
      ws.send(s);
    } catch (e) {
      if (__DEV__) console.warn("[WS] send error", e);
    }
  }

  return { connect, disconnect, subscribe, send };
}
