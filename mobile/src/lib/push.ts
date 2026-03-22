import { Platform } from "react-native";
import Constants from "expo-constants";
import * as Device from "expo-device";
import { savePushToken } from "./api";

export type PushPlatform = "android" | "ios";

const projectId = Constants.expoConfig?.extra?.eas?.projectId as string | undefined;

/**
 * Returns true when running in Expo Go. Push notifications were removed from
 * Expo Go on Android in SDK 53+; use a development build (npx expo run:android) instead.
 */
function isExpoGo(): boolean {
  return Constants.appOwnership === "expo";
}

/**
 * Registers for push notifications and sends the Expo push token to the backend.
 * Call after the user is authenticated. Skips in Expo Go; runs only in dev build or standalone.
 */
export async function registerForPushNotifications(accessToken: string): Promise<void> {
  if (__DEV__) console.log("PUSH_INIT");

  // Skip in Expo Go - Android push was removed in SDK 53+; would crash
  if (isExpoGo()) {
    if (__DEV__) console.log("PUSH_SKIPPED_EXPO_GO");
    return;
  }

  if (!Device.isDevice) {
    if (__DEV__) console.log("PUSH: skipping - not a physical device");
    return;
  }

  try {
    const Notifications = await import("expo-notifications");
    const platform: PushPlatform = Platform.OS === "ios" ? "ios" : "android";

    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;

    if (existingStatus !== "granted") {
      if (__DEV__) console.log("PUSH_PERMISSION_REQUEST");
      const { status } = await Notifications.requestPermissionsAsync();
      finalStatus = status;
      if (status !== "granted") {
        if (__DEV__) console.log("PUSH_PERMISSION_DENIED");
        return;
      }
    }

    const tokenData = await Notifications.getExpoPushTokenAsync({
      projectId: projectId ?? undefined,
    });
    const expoToken = tokenData?.data;
    if (!expoToken) {
      if (__DEV__) console.warn("PUSH: no Expo push token returned");
      return;
    }

    if (__DEV__) console.log("PUSH_TOKEN_SUCCESS", expoToken);

    await savePushToken(accessToken, expoToken, platform);
    if (__DEV__) console.log("PUSH_TOKEN_SEND_SUCCESS");
  } catch (e) {
    // Fallback: expo-notifications may throw in Expo Go before we reach isExpoGo (race/timing)
    if (__DEV__) {
      const msg = String(e ?? "").toLowerCase();
      if (msg.includes("expo go") || msg.includes("development build")) {
        console.log("PUSH_SKIPPED_EXPO_GO");
      } else {
        console.warn("PUSH_ERROR", e);
      }
    }
  }
}
