import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
} from "react";
import { useAuth } from "./auth";
import { createWsClient, type WsEvent } from "../lib/ws";

type MessageHandler = (event: WsEvent) => void;

interface WsContextValue {
  subscribe: (handler: MessageHandler) => () => void;
  send: (payload: unknown) => void;
}

const WsContext = createContext<WsContextValue | null>(null);

export function WsProvider({ children }: { children: React.ReactNode }) {
  const { accessToken } = useAuth();
  const clientRef = useRef<ReturnType<typeof createWsClient> | null>(null);

  if (!clientRef.current) {
    clientRef.current = createWsClient();
  }
  const client = clientRef.current;

  useEffect(() => {
    if (accessToken) {
      client.connect(accessToken);
    } else {
      client.disconnect();
    }
    return () => {
      client.disconnect();
    };
  }, [accessToken, client]);

  const subscribe = useCallback(
    (handler: MessageHandler) => {
      return client.subscribe(handler);
    },
    [client]
  );

  const send = useCallback(
    (payload: unknown) => {
      client.send(payload);
    },
    [client]
  );

  return (
    <WsContext.Provider value={{ subscribe, send }}>
      {children}
    </WsContext.Provider>
  );
}

export function useWs(): WsContextValue {
  const ctx = useContext(WsContext);
  if (!ctx) throw new Error("useWs must be used inside WsProvider");
  return ctx;
}
