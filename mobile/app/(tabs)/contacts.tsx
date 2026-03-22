import { useCallback, useEffect, useState } from "react";
import {
  View,
  Text,
  FlatList,
  StyleSheet,
  ActivityIndicator,
  TouchableOpacity,
  RefreshControl,
} from "react-native";
import { useAuth } from "../../src/context/auth";
import { syncContacts, type SyncUser } from "../../src/lib/api";

// In a real app these would come from the device address book.
// For now we sync a small set of known dev-mode phone numbers so the list
// shows real registered users from the backend.
const DEV_PHONES = [
  "+49911111111",
  "+49911111112",
  "+49911111113",
  "+49911111114",
  "+49911111115",
];

export default function ContactsScreen() {
  const { accessToken } = useAuth();
  const [contacts, setContacts] = useState<SyncUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (silent = false) => {
      if (!accessToken) return;
      if (!silent) setLoading(true);
      setError(null);
      try {
        const data = await syncContacts(accessToken, DEV_PHONES);
        setContacts(data);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load contacts");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [accessToken]
  );

  useEffect(() => { load(); }, [load]);

  function onRefresh() {
    setRefreshing(true);
    load(true);
  }

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#1F6FEB" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.center}>
        <Text style={styles.errorText}>{error}</Text>
        <TouchableOpacity style={styles.retryBtn} onPress={() => load()}>
          <Text style={styles.retryText}>Retry</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <FlatList
        data={contacts}
        keyExtractor={(item) => item.user_id}
        contentContainerStyle={styles.listContent}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#1F6FEB" />}
        ItemSeparatorComponent={() => <View style={styles.separator} />}
        ListEmptyComponent={
          <View style={styles.center}>
            <Text style={styles.emptyText}>No contacts found</Text>
            <Text style={styles.emptyHint}>Contacts who use Signalix will appear here</Text>
          </View>
        }
        renderItem={({ item }) => (
          <View style={styles.row}>
            <View style={styles.avatar}>
              <Text style={styles.avatarText}>
                {(item.display_name || item.phone_number)[0].toUpperCase()}
              </Text>
            </View>
            <View style={styles.contactContent}>
              <Text style={styles.name} numberOfLines={1}>{item.display_name || item.phone_number}</Text>
              <Text style={styles.phone}>{item.phone_number}</Text>
            </View>
          </View>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  listContent: { paddingVertical: 8, paddingBottom: 20 },
  center: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32 },
  errorText: { fontSize: 15, color: "#FF3B30", textAlign: "center", marginBottom: 12 },
  retryBtn: { paddingHorizontal: 24, paddingVertical: 12, backgroundColor: "#1F6FEB", borderRadius: 12 },
  retryText: { color: "#fff", fontWeight: "600" },
  emptyText: { fontSize: 17, fontWeight: "600", color: "#111827", marginBottom: 4 },
  emptyHint: { fontSize: 14, color: "#6B7280", textAlign: "center" },
  separator: { height: 8 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FFFFFF",
    borderRadius: 12,
    marginHorizontal: 12,
    marginVertical: 4,
    paddingHorizontal: 14,
    paddingVertical: 14,
  },
  avatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
    marginRight: 14,
  },
  avatarText: { color: "#fff", fontSize: 19, fontWeight: "600" },
  contactContent: { flex: 1, minWidth: 0 },
  name: { fontSize: 16, fontWeight: "700", color: "#111827" },
  phone: { fontSize: 13, color: "#6B7280", marginTop: 2 },
});
