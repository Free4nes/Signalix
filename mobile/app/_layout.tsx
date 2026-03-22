import { useEffect } from "react";
import { Stack, useRouter, useSegments } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { AuthProvider, useAuth } from "../src/context/auth";
import { PushRegistration } from "../src/components/PushRegistration";
import { PushNotificationHandler } from "../src/components/PushNotificationHandler";
import { ChatListProvider } from "../src/context/chatList";
import { ClearChatProvider } from "../src/context/clearChat";
import { OpenSearchRequestProvider } from "../src/context/openSearchRequest";
import { WsProvider } from "../src/context/ws";

function RootNavigator() {
  const { accessToken, isLoading } = useAuth();
  const segments = useSegments();
  const router = useRouter();

  useEffect(() => {
    if (isLoading) return;

    const seg = segments[0] as string | undefined;
    const inAuthGroup = seg === "login" || seg === "otp";
    const loggedIn = !!accessToken;

    if (!loggedIn && !inAuthGroup) {
      router.replace("/login");
    } else if (loggedIn && inAuthGroup) {
      router.replace("/(tabs)/chats");
    }
  }, [accessToken, isLoading, segments]);

  if (isLoading) return null;

  return (
    <Stack screenOptions={{ headerShown: false }}>
      <Stack.Screen name="login" />
      <Stack.Screen name="otp" />
      <Stack.Screen name="(tabs)" />
      <Stack.Screen
        name="chat"
        options={{
          headerShown: false,
        }}
      />
      <Stack.Screen
        name="blocked-users"
        options={{
          headerShown: false,
        }}
      />
    </Stack>
  );
}

export default function RootLayout() {
  return (
    <AuthProvider>
      <WsProvider>
        <ChatListProvider>
          <ClearChatProvider>
            <OpenSearchRequestProvider>
            <PushRegistration />
            <PushNotificationHandler />
            <StatusBar style="light" />
            <RootNavigator />
            </OpenSearchRequestProvider>
          </ClearChatProvider>
        </ChatListProvider>
      </WsProvider>
    </AuthProvider>
  );
}
