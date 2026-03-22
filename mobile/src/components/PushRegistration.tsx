import { useEffect } from "react";
import { useAuth } from "../context/auth";
import { registerForPushNotifications } from "@/services/pushNotifications";

/**
 * Registers for push notifications and sends token to backend when user is authenticated.
 * Runs once per login; skips on web and emulators.
 */
export function PushRegistration() {
  const { accessToken } = useAuth();

  useEffect(() => {
    if (!accessToken) {
      if (__DEV__) console.log("PUSH_REGISTRATION_SKIPPED_NO_TOKEN");
      return;
    }
    let cancelled = false;
    (async () => {
      if (__DEV__) console.log("PUSH_REGISTRATION_EFFECT_START");
      await registerForPushNotifications(accessToken);
      if (cancelled) return;
      if (__DEV__) console.log("PUSH_REGISTRATION_EFFECT_DONE");
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  return null;
}
