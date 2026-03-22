import React, { createContext, useCallback, useContext, useRef } from "react";

type ClearCallback = () => void;

const ClearChatContext = createContext<{
  register: (convId: string, callback: ClearCallback) => void;
  unregister: (convId: string) => void;
  clearConversation: (convId: string) => void;
} | null>(null);

export function ClearChatProvider({ children }: { children: React.ReactNode }) {
  const callbacksRef = useRef<Map<string, ClearCallback>>(new Map());

  const register = useCallback((convId: string, callback: ClearCallback) => {
    callbacksRef.current.set(convId, callback);
  }, []);

  const unregister = useCallback((convId: string) => {
    callbacksRef.current.delete(convId);
  }, []);

  const clearConversation = useCallback((convId: string) => {
    callbacksRef.current.get(convId)?.();
  }, []);

  return (
    <ClearChatContext.Provider value={{ register, unregister, clearConversation }}>
      {children}
    </ClearChatContext.Provider>
  );
}

export function useClearChat() {
  const ctx = useContext(ClearChatContext);
  if (!ctx) throw new Error("useClearChat must be used inside ClearChatProvider");
  return ctx;
}
