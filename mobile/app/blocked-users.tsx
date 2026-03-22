import { useCallback, useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  ActivityIndicator,
  Alert,
  Platform,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import { ChevronLeft } from "lucide-react-native";
import { useAuth } from "../src/context/auth";
import {
  listBlockedUsers,
  unblockUser,
  type BlockedUser,
} from "../src/lib/api";

function displayLabel(u: BlockedUser): string {
  if (u.display_name && u.display_name.trim()) return u.display_name;
  return u.phone;
}

export default function BlockedUsersScreen() {
  const router = useRouter();
  const { accessToken } = useAuth();
  const [list, setList] = useState<BlockedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [unblocking, setUnblocking] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (__DEV__) console.log("BLOCKED_USERS_SCREEN_LOAD");
    if (!accessToken) {
      if (__DEV__) console.log("BLOCKED_USERS_SCREEN_LOAD no accessToken, skip");
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await listBlockedUsers(accessToken);
      if (__DEV__) console.log("BLOCKED_USERS_RESPONSE", JSON.stringify(data));
      setList(data);
    } catch (e) {
      if (__DEV__) console.log("BLOCKED_USERS_RESPONSE error", e);
      setList([]);
    } finally {
      setLoading(false);
    }
  }, [accessToken]);

  useFocusEffect(
    useCallback(() => {
      load();
    }, [load])
  );

  async function handleUnblock(u: BlockedUser) {
    if (!accessToken) return;
    setUnblocking(u.user_id);
    try {
      await unblockUser(accessToken, u.user_id);
      setList((prev) => prev.filter((x) => x.user_id !== u.user_id));
      Alert.alert("Unblocked", `${displayLabel(u)} has been unblocked.`);
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to unblock");
    } finally {
      setUnblocking(null);
    }
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity
          onPress={() => router.back()}
          style={styles.backBtn}
          hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
        >
          <ChevronLeft size={24} color="#111827" />
        </TouchableOpacity>
        <Text style={styles.title}>Blocked Users</Text>
      </View>

      {loading ? (
        <View style={styles.centered}>
          <ActivityIndicator size="large" color="#1F6FEB" />
        </View>
      ) : list.length === 0 ? (
        <View style={styles.centered}>
          <Text style={styles.emptyText}>No blocked users</Text>
        </View>
      ) : (
        <FlatList
          data={list}
          keyExtractor={(item) => item.user_id}
          contentContainerStyle={styles.list}
          renderItem={({ item }) => (
            <View style={styles.row}>
              <Text style={styles.rowLabel} numberOfLines={1}>
                {displayLabel(item)}
              </Text>
              <TouchableOpacity
                style={styles.unblockBtn}
                onPress={() => handleUnblock(item)}
                disabled={unblocking === item.user_id}
              >
                {unblocking === item.user_id ? (
                  <ActivityIndicator size="small" color="#1F6FEB" />
                ) : (
                  <Text style={styles.unblockText}>Unblock</Text>
                )}
              </TouchableOpacity>
            </View>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  header: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 8,
    paddingVertical: 12,
    paddingTop: Platform.OS === "ios" ? 56 : 12,
    backgroundColor: "#FFFFFF",
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#E5E5EA",
  },
  backBtn: { padding: 8, marginRight: 4 },
  title: { fontSize: 18, fontWeight: "600", color: "#111827" },
  centered: { flex: 1, justifyContent: "center", alignItems: "center" },
  emptyText: { fontSize: 16, color: "#6B7280" },
  list: { padding: 16 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    backgroundColor: "#FFFFFF",
    paddingHorizontal: 16,
    paddingVertical: 14,
    marginBottom: 8,
    borderRadius: 12,
  },
  rowLabel: { fontSize: 16, color: "#111827", flex: 1 },
  unblockBtn: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    marginLeft: 12,
  },
  unblockText: { fontSize: 15, color: "#1F6FEB", fontWeight: "600" },
});
