import React, { createContext, useCallback, useContext, useState } from "react";

interface ChatListContextValue {
  activeChatId: string | null;
  setActiveChatId: (id: string | null) => void;
  unreadCounts: Record<string, number>;
  incrementUnread: (convId: string) => void;
  resetUnread: (convId: string) => void;
  getUnread: (convId: string) => number;
}

const ChatListContext = createContext<ChatListContextValue | null>(null);

export function ChatListProvider({ children }: { children: React.ReactNode }) {
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});

  const incrementUnread = useCallback((convId: string) => {
    setUnreadCounts((prev) => {
      const next = prev[convId] ?? 0;
      if (__DEV__) console.log("UNREAD_INCREMENT", `convId=${convId}`, `count=${next + 1}`);
      return { ...prev, [convId]: next + 1 };
    });
  }, []);

  const resetUnread = useCallback((convId: string) => {
    setUnreadCounts((prev) => {
      if ((prev[convId] ?? 0) === 0) return prev;
      if (__DEV__) console.log("UNREAD_RESET", `convId=${convId}`);
      const next = { ...prev };
      delete next[convId];
      return next;
    });
  }, []);

  const getUnread = useCallback(
    (convId: string) => unreadCounts[convId] ?? 0,
    [unreadCounts]
  );

  return (
    <ChatListContext.Provider
      value={{
        activeChatId,
        setActiveChatId,
        unreadCounts,
        incrementUnread,
        resetUnread,
        getUnread,
      }}
    >
      {children}
    </ChatListContext.Provider>
  );
}

export function useChatList(): ChatListContextValue {
  const ctx = useContext(ChatListContext);
  if (!ctx) throw new Error("useChatList must be used inside ChatListProvider");
  return ctx;
}
