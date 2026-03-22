import { useLocalSearchParams, useRouter, useNavigation } from "expo-router";
import { Image as ImageIcon, Search, Trash2, UserX, UserCheck } from "lucide-react-native";
import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { useAuth } from "../../../src/context/auth";
import { useClearChat } from "../../../src/context/clearChat";
import { useOpenSearchRequest } from "../../../src/context/openSearchRequest";
import {
  blockUser,
  clearConversationMessages,
  getConversation,
  getUserOnlineStatus,
  listBlockedUsers,
  unblockUser,
} from "../../../src/lib/api";

function formatLastSeen(iso: string): string {
  const d = new Date(iso);
  const h = d.getHours().toString().padStart(2, "0");
  const m = d.getMinutes().toString().padStart(2, "0");
  return `last seen ${h}:${m}`;
}

export default function ConversationInfoScreen() {
  const { id: convId } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const navigation = useNavigation();
  const { accessToken, user } = useAuth();
  const { clearConversation } = useClearChat();
  const { requestOpenSearch } = useOpenSearchRequest();

  const [contact, setContact] = useState<{ id: string; name: string; phone: string } | null>(null);
  const [onlineStatus, setOnlineStatus] = useState<{ online: boolean; lastSeen?: string } | null>(null);
  const [isBlocked, setIsBlocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const [clearingChat, setClearingChat] = useState(false);

  const load = useCallback(async () => {
    if (!accessToken || !convId || !user) return;
    setLoading(true);
    try {
      const [conv, blocked] = await Promise.all([
        getConversation(accessToken, convId),
        listBlockedUsers(accessToken),
      ]);
      if (conv.is_group || conv.members.length < 2) {
        router.back();
        return;
      }
      const other = conv.members.find((m) => m.user_id !== user.id);
      if (!other) {
        router.back();
        return;
      }
      const name = (other.display_name && other.display_name.trim()) || other.phone_number || "Contact";
      setContact({ id: other.user_id, name, phone: other.phone_number });
      setIsBlocked(blocked.some((b) => b.user_id === other.user_id));

      const status = await getUserOnlineStatus(accessToken, other.user_id);
      setOnlineStatus({ online: status.online, lastSeen: status.last_seen });
    } catch {
      router.back();
    } finally {
      setLoading(false);
    }
  }, [accessToken, convId, user, router]);

  useEffect(() => {
    load();
  }, [load]);

  useLayoutEffect(() => {
    navigation.setOptions({ title: "Conversation Info" });
  }, [navigation]);

  const handleSearch = useCallback(() => {
    if (convId) {
      requestOpenSearch(convId);
      router.back();
    }
  }, [router, convId, requestOpenSearch]);

  const handleViewMedia = useCallback(() => {
    router.push({ pathname: "/chat/media/[id]", params: { id: convId } });
  }, [router, convId]);

  const handleBlockToggle = useCallback(async () => {
    if (!accessToken || !contact) return;
    const action = isBlocked ? unblockUser : blockUser;
    try {
      await action(accessToken, contact.id);
      setIsBlocked(!isBlocked);
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to update");
    }
  }, [accessToken, contact, isBlocked]);

  const performClearChat = useCallback(async () => {
    if (!accessToken || !convId || clearingChat) return;
    setClearingChat(true);
    try {
      await clearConversationMessages(accessToken, convId);
      clearConversation(convId);
      router.back();
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to clear chat");
    } finally {
      setClearingChat(false);
    }
  }, [accessToken, convId, clearingChat, clearConversation, router]);

  const handleClearChat = useCallback(() => {
    Alert.alert(
      "Clear chat",
      "Clear all messages in this chat for your account? This cannot be undone.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Clear",
          style: "destructive",
          onPress: () => {
            void performClearChat();
          },
        },
      ]
    );
  }, [performClearChat]);

  if (loading || !contact) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#1F6FEB" />
      </View>
    );
  }

  const options = [
    { icon: Search, label: "Search in chat", onPress: handleSearch },
    { icon: ImageIcon, label: "View media", onPress: handleViewMedia },
    {
      icon: isBlocked ? UserCheck : UserX,
      label: isBlocked ? "Unblock user" : "Block user",
      onPress: handleBlockToggle,
    },
    { icon: Trash2, label: "Clear chat", onPress: handleClearChat, destructive: true },
  ];

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.name}>{contact.name}</Text>
        <Text style={styles.phone}>{contact.phone}</Text>
        {onlineStatus && (
          <Text style={styles.status}>
            {onlineStatus.online
              ? "online"
              : onlineStatus.lastSeen
                ? formatLastSeen(onlineStatus.lastSeen)
                : ""}
          </Text>
        )}
      </View>
      <View style={styles.options}>
        {options.map((opt) => (
          <TouchableOpacity
            key={opt.label}
            style={styles.optionRow}
            onPress={opt.onPress}
            activeOpacity={0.7}
          >
            <opt.icon
              color={opt.destructive ? "#DC2626" : "#374151"}
              size={22}
              style={styles.optionIcon}
            />
            <Text style={[styles.optionLabel, opt.destructive && styles.optionLabelDestructive]}>
              {opt.label}
            </Text>
          </TouchableOpacity>
        ))}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  center: { flex: 1, alignItems: "center", justifyContent: "center" },
  content: { padding: 16, paddingBottom: 32 },
  header: {
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
    alignItems: "center",
    borderWidth: 1,
    borderColor: "#E5E7EB",
  },
  name: { fontSize: 20, fontWeight: "700", color: "#111827" },
  phone: { fontSize: 15, color: "#6B7280", marginTop: 4 },
  status: { fontSize: 13, color: "#1F6FEB", marginTop: 2 },
  options: {
    backgroundColor: "#fff",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "#E5E7EB",
    overflow: "hidden",
  },
  optionRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#E5E7EB",
  },
  optionIcon: { marginRight: 12 },
  optionLabel: { fontSize: 16, color: "#111827", fontWeight: "500" },
  optionLabelDestructive: { color: "#DC2626" },
});
