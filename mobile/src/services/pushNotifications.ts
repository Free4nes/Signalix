/**
 * Push Notifications service for Signalix.
 * Handles registration, foreground display, and navigation on notification tap.
 */
import * as Notifications from "expo-notifications";
import { Platform } from "react-native";
import Constants from "expo-constants";
import * as Device from "expo-device";
import { savePushToken } from "../lib/api";

export type PushPlatform = "android" | "ios";

const projectId = Constants.expoConfig?.extra?.eas?.projectId as string | undefined;

function isExpoGo(): boolean {
  return Constants.appOwnership === "expo";
}

/**
 * Sets up Android default notification channel. Call on app start.
 */
export async function setupAndroidChannel(): Promise<void> {
  if (Platform.OS !== "android") return;
  try {
    await Notifications.setNotificationChannelAsync("default", {
      name: "default",
      importance: Notifications.AndroidImportance.MAX,
    });
  } catch {
    // Ignore - channel may already exist
  }
}

/**
 * Configures how notifications are presented when app is in foreground.
 * Show banner, badge, and play sound.
 */
export function setupNotificationHandler(): void {
  Notifications.setNotificationHandler({
    handleNotification: async () => ({
      shouldShowAlert: true,
      shouldPlaySound: true,
      shouldSetBadge: true,
      shouldShowBanner: true,
      shouldShowList: true,
      priority: Notifications.AndroidNotificationPriority.HIGH,
      categoryIdentifier: "message",
    }),
  });
}

/**
 * Registers for push notifications and sends the Expo push token to the backend.
 * Skips in Expo Go and emulator; runs only in dev build or standalone on physical device.
 */
export async function registerForPushNotifications(accessToken: string): Promise<void> {
  if (__DEV__) console.log("PUSH_REGISTER_START");

  if (isExpoGo()) {
    if (__DEV__) console.log("PUSH_SKIPPED_EXPO_GO");
    return;
  }

  if (!Device.isDevice) {
    if (__DEV__) console.log("PUSH_SKIPPED_EMULATOR");
    return;
  }

  try {
    const platform: PushPlatform = Platform.OS === "ios" ? "ios" : "android";

    if (__DEV__) console.log("PUSH_PERMISSION_CHECK_START");
    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    if (__DEV__) console.log("PUSH_PERMISSION_EXISTING_STATUS", existingStatus);
    let finalStatus = existingStatus;
    if (finalStatus !== "granted") {
      if (__DEV__) console.log("PUSH_PERMISSION_REQUEST_START");
      const { status } = await Notifications.requestPermissionsAsync();
      finalStatus = status;
    }
    if (__DEV__) console.log("PUSH_PERMISSION_RESULT", finalStatus);
    if (finalStatus !== "granted") {
      if (__DEV__) console.log("PUSH_PERMISSION_DENIED");
      return;
    }

    const tokenData = await Notifications.getExpoPushTokenAsync({
      projectId: projectId ?? undefined,
    });
    const expoToken = tokenData?.data;
    if (!expoToken) {
      if (__DEV__) console.log("PUSH_REGISTER_ERROR no token");
      return;
    }
    if (__DEV__) console.log("PUSH_TOKEN_OBTAINED", expoToken);

    if (__DEV__) console.log("PUSH_SAVE_TOKEN_REQUEST_START");
    try {
      await savePushToken(accessToken, expoToken, platform);
      if (__DEV__) console.log("PUSH_TOKEN_SAVE_SUCCESS");
    } catch (saveError) {
      if (__DEV__) console.log("PUSH_TOKEN_SAVE_ERROR", saveError);
      throw saveError;
    }
  } catch (e) {
    if (__DEV__) console.log("PUSH_REGISTER_ERROR", e);
  }
}

export interface NotificationData {
  conversationId?: string;
  [key: string]: unknown;
}

export type NotificationResponseHandler = (data: NotificationData) => void;

/**
 * Adds a listener for when the user taps a notification.
 * Call from a component that has access to the router.
 */
export function addNotificationResponseListener(
  onResponse: NotificationResponseHandler
): () => void {
  const sub = Notifications.addNotificationResponseReceivedListener((event) => {
    const data = (event.notification.request.content.data ?? {}) as NotificationData;
    onResponse(data);
  });
  return () => sub.remove();
}

/**
 * Handles the case when app was opened from a killed state by tapping a notification.
 * Call once on app mount.
 */
export async function handleInitialNotificationResponse(
  onResponse: NotificationResponseHandler
): Promise<void> {
  const response = await Notifications.getLastNotificationResponseAsync();
  if (response) {
    const data = (response.notification.request.content.data ?? {}) as NotificationData;
    onResponse(data);
  }
}
