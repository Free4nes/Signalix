/**
 * Sets up push notification handlers: foreground display and navigation on tap.
 * Must be mounted inside the router context.
 */
import { useEffect, useRef } from "react";
import { useRouter } from "expo-router";
import * as Notifications from "expo-notifications";
import {
  setupAndroidChannel,
  addNotificationResponseListener,
  handleInitialNotificationResponse,
} from "../services/pushNotifications";

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

export function PushNotificationHandler() {
  const router = useRouter();
  const mountedRef = useRef(true);

  useEffect(() => {
    setupAndroidChannel();

    const handleResponse = (data: { conversationId?: string }) => {
      const convId = data?.conversationId;
      if (convId && typeof convId === "string" && mountedRef.current) {
        if (__DEV__) console.log("PUSH_TAP_NAVIGATE conversationId=" + convId);
        router.push(`/chat/${convId}`);
      }
    };

    handleInitialNotificationResponse(handleResponse);

    const remove = addNotificationResponseListener(handleResponse);
    return () => {
      mountedRef.current = false;
      remove();
    };
  }, [router]);

  return null;
}
