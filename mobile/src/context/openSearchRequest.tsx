import React, { createContext, useCallback, useContext, useState } from "react";

const OpenSearchRequestContext = createContext<{
  requestOpenSearch: (convId: string) => void;
  consumeOpenSearchRequest: (convId: string) => boolean;
} | null>(null);

export function OpenSearchRequestProvider({ children }: { children: React.ReactNode }) {
  const [convId, setConvId] = useState<string | null>(null);

  const requestOpenSearch = useCallback((id: string) => {
    setConvId(id);
  }, []);

  const consumeOpenSearchRequest = useCallback((id: string) => {
    if (convId === id) {
      setConvId(null);
      return true;
    }
    return false;
  }, [convId]);

  return (
    <OpenSearchRequestContext.Provider value={{ requestOpenSearch, consumeOpenSearchRequest }}>
      {children}
    </OpenSearchRequestContext.Provider>
  );
}

export function useOpenSearchRequest() {
  const ctx = useContext(OpenSearchRequestContext);
  if (!ctx) throw new Error("useOpenSearchRequest must be used inside OpenSearchRequestProvider");
  return ctx;
}
