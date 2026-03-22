import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { API_BASE, verifyOtp, requestOtp, logout, refreshTokens, ApiError } from "../lib/api";
import { getItem, removeItem, setItem } from "../lib/storage";

const ACCESS_TOKEN_KEY = "signalix_access_token";
const REFRESH_TOKEN_KEY = "signalix_refresh_token";
const USER_KEY = "signalix_user";

export interface AuthUser {
  id: string;
  phone_number: string;
  display_name?: string;
  avatar_url?: string;
}

interface AuthState {
  /** null = not loaded yet, "" = logged out, string = token */
  accessToken: string | null;
  refreshToken: string | null;
  user: AuthUser | null;
  isLoading: boolean;
}

interface AuthContextValue extends AuthState {
  sendOtp: (phone: string) => Promise<{ devOtp?: string }>;
  confirmOtp: (phone: string, otp: string) => Promise<void>;
  signOut: () => Promise<void>;
  updateUser: (user: AuthUser) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({
    accessToken: null,
    refreshToken: null,
    user: null,
    isLoading: true,
  });

  // Load persisted tokens on mount
  useEffect(() => {
    (async () => {
      try {
        const [at, rt, userJson] = await Promise.all([
          getItem(ACCESS_TOKEN_KEY),
          getItem(REFRESH_TOKEN_KEY),
          getItem(USER_KEY),
        ]);
        const user: AuthUser | null = userJson ? JSON.parse(userJson) : null;

        if (at && rt) {
          // Try to refresh immediately to get a fresh access token
          try {
            const tokens = await refreshTokens(rt);
            await setItem(ACCESS_TOKEN_KEY, tokens.access_token);
            await setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
            setState({
              accessToken: tokens.access_token,
              refreshToken: tokens.refresh_token,
              user,
              isLoading: false,
            });
            return;
          } catch {
            // Refresh failed — clear and force re-login
            await clearTokens();
          }
        }
        setState({ accessToken: "", refreshToken: "", user: null, isLoading: false });
      } catch {
        setState({ accessToken: "", refreshToken: "", user: null, isLoading: false });
      }
    })();
  }, []);

  const sendOtp = useCallback(async (phone: string) => {
    const res = await requestOtp(phone);
    return { devOtp: res.dev_otp };
  }, []);

  const confirmOtp = useCallback(async (phone: string, otp: string) => {
    if (__DEV__) {
      console.log("OTP_VERIFY_REQUEST", { url: `${API_BASE}/auth/verify_otp` });
    }
    const res = await verifyOtp(phone, otp);
    if (__DEV__) console.log("OTP_VERIFY_RESPONSE_OK", { hasToken: !!res?.access_token });
    try {
      await setItem(ACCESS_TOKEN_KEY, res.access_token);
      await setItem(REFRESH_TOKEN_KEY, res.refresh_token);
      await setItem(USER_KEY, JSON.stringify(res.user));
      if (__DEV__) console.log("OTP_VERIFY_TOKEN_SAVE_SUCCESS");
    } catch (e) {
      if (__DEV__) console.warn("OTP_VERIFY_TOKEN_SAVE_FAIL", e);
      throw e;
    }
    setState({
      accessToken: res.access_token,
      refreshToken: res.refresh_token,
      user: res.user,
      isLoading: false,
    });
  }, []);

  const updateUser = useCallback(async (user: AuthUser) => {
    await setItem(USER_KEY, JSON.stringify(user));
    setState((prev) => (prev.user ? { ...prev, user } : prev));
  }, []);

  const signOut = useCallback(async () => {
    try {
      if (state.refreshToken && state.accessToken) {
        await logout(state.refreshToken, state.accessToken);
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        // Token already expired — ignore
      }
    } finally {
      await clearTokens();
      setState({ accessToken: "", refreshToken: "", user: null, isLoading: false });
    }
  }, [state.refreshToken, state.accessToken]);

  return (
    <AuthContext.Provider value={{ ...state, sendOtp, confirmOtp, signOut, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

async function clearTokens() {
  await Promise.all([
    removeItem(ACCESS_TOKEN_KEY),
    removeItem(REFRESH_TOKEN_KEY),
    removeItem(USER_KEY),
  ]);
}
