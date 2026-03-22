import { useCallback, useEffect, useState } from "react";
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  RefreshControl,
  Modal,
  TextInput,
  KeyboardAvoidingView,
  Platform,
  Alert,
} from "react-native";
import { useRouter } from "expo-router";
import { useFocusEffect } from "expo-router";
import { Plus, X, Users } from "lucide-react-native";
import { Avatar } from "../../src/components/Avatar";
import { useAuth } from "../../src/context/auth";
import { useChatList } from "../../src/context/chatList";
import { useWs } from "../../src/context/ws";
import {
  listConversations,
  lookupContact,
  createConversation,
  syncContacts,
  type Conversation,
  type SyncUser,
} from "../../src/lib/api";

const DEV_TEST_RECIPIENT = "+4912340000000";
const DEV_PHONES = ["+49911111111", "+49911111112", "+49911111113", "+49911111114", "+49911111115"];

/** Strip spaces, dashes, dots, parens; convert 00→+ prefix. */
function normalizePhone(input: string): string {
  let s = input.trim().replace(/[\s\-().]/g, "");
  if (s.startsWith("00")) s = "+" + s.slice(2);
  return s;
}

/** Returns null if valid, or an error string if not. */
function validateRecipientPhone(input: string, ownPhone: string): string | null {
  const normalized = normalizePhone(input);
  if (!normalized) return "Phone number is required.";
  if (!/^\+[1-9]\d{6,14}$/.test(normalized)) {
    return "Enter a valid phone number starting with + (e.g. +4915112345678).";
  }
  if (normalized === ownPhone) {
    return "Recipient must be different from your own number.";
  }
  return null;
}

/**
 * Format a timestamp for the chat list right-hand side:
 *   - Today      → "14:05"
 *   - Otherwise  → "27.02"
 */
function formatTime(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const now = new Date();
  const isToday =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (isToday) {
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    return `${hh}:${mm}`;
  }
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${dd}.${mo}`;
}

export default function ChatsScreen() {
  const router = useRouter();
  const { accessToken, user } = useAuth();
  const { subscribe } = useWs();
  const {
    activeChatId,
    incrementUnread,
    getUnread,
  } = useChatList();

  const [convs, setConvs] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New-chat modal state
  const [modalVisible, setModalVisible] = useState(false);
  const [newPhone, setNewPhone] = useState("");
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  // New-group modal state
  const [groupModalVisible, setGroupModalVisible] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupMembers, setGroupMembers] = useState<SyncUser[]>([]);
  const [groupAddPhone, setGroupAddPhone] = useState("");
  const [groupAddError, setGroupAddError] = useState<string | null>(null);
  const [contacts, setContacts] = useState<SyncUser[]>([]);
  const [groupCreating, setGroupCreating] = useState(false);
  const closeNewChatModal = useCallback(() => {
    setModalVisible((prev) => (prev ? false : prev));
  }, []);
  const closeNewGroupModal = useCallback(() => {
    setGroupModalVisible((prev) => (prev ? false : prev));
  }, []);

  const load = useCallback(
    async (silent = false) => {
      if (!accessToken) return;
      if (!silent) setLoading(true);
      setError(null);
      try {
        const data = await listConversations(accessToken);
        setConvs(data);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load chats");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [accessToken]
  );

  // Refetch every time this tab comes into focus (e.g. navigating back from chat screen).
  useFocusEffect(
    useCallback(() => {
      load(true);
    }, [load])
  );

  // WebSocket: update chat list on message.created (unread, preview, move to top)
  useEffect(() => {
    const unsub = subscribe((event) => {
      if (event.type !== "message.created" || !event.message) return;
      const convId = event.conversation_id;
      const msg = event.message;
      const preview = msg.body_preview ?? "Message";
      const sentAt = msg.sent_at ?? new Date().toISOString();
      const isActiveChat = String(convId ?? "").toLowerCase() === String(activeChatId ?? "").toLowerCase();
      if (!isActiveChat) {
        incrementUnread(convId);
      }
      setConvs((prev) => {
        const existing = prev.find((c) => c.id === convId);
        const wasAtTop = existing && prev[0]?.id === convId;
        const updated: Conversation = existing
          ? { ...existing, last_message_preview: preview, last_message_at: sentAt }
          : {
              id: convId,
              is_group: false,
              display_title: "Chat",
              members: [],
              last_message_preview: preview,
              last_message_at: sentAt,
            };
        const rest = prev.filter((c) => c.id !== convId);
        const next = [updated, ...rest];
        if (__DEV__) {
          console.log("CHAT_LIST_UPDATE", convId, preview);
          if (!wasAtTop) console.log("CHAT_MOVED_TO_TOP", convId);
        }
        return next;
      });
    });
    return () => unsub();
  }, [subscribe, activeChatId, incrementUnread]);

  function onRefresh() {
    setRefreshing(true);
    load(true);
  }

  async function loadContactsForGroup() {
    if (!accessToken) return;
    try {
      const data = await syncContacts(accessToken, DEV_PHONES);
      setContacts(data.filter((c) => c.user_id !== user?.id));
    } catch {
      setContacts([]);
    }
  }

  function addGroupMemberByPhone() {
    if (!accessToken) return;
    const normalized = normalizePhone(groupAddPhone);
    const err = validateRecipientPhone(groupAddPhone, user?.phone_number ?? "");
    if (err) {
      setGroupAddError(err);
      return;
    }
    setGroupAddError(null);
    setGroupAddPhone("");
    lookupContact(accessToken, normalized)
      .then(async ({ user_id }) => {
        const existing = groupMembers.some((m) => m.user_id === user_id);
        if (existing) return;
        const synced = await syncContacts(accessToken, [normalized]);
        const u = synced.find((s) => s.user_id === user_id) ?? { user_id, phone_number: normalized };
        setGroupMembers((prev) => [...prev, u]);
      })
      .catch((e) => setGroupAddError(e instanceof Error ? e.message : "User not found"));
  }

  function removeGroupMember(userId: string) {
    setGroupMembers((prev) => prev.filter((m) => m.user_id !== userId));
  }

  async function handleCreateGroup() {
    if (!accessToken || !user) return;
    const trimmed = groupName.trim() || "Group";
    if (groupMembers.length < 2) {
      Alert.alert("Group", "Add at least 2 members to create a group.");
      return;
    }
    setGroupCreating(true);
    try {
      const conv = await createConversation(
        accessToken,
        groupMembers.map((m) => m.user_id),
        trimmed
      );
      closeNewGroupModal();
      setGroupName("");
      setGroupMembers([]);
      await load(true);
      router.push({
        pathname: "/chat/[id]",
        params: { id: conv.id, title: conv.display_title, isGroup: "true" },
      });
    } catch (e: unknown) {
      Alert.alert("Could not create group", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setGroupCreating(false);
    }
  }

  async function handleNewChat() {
    if (!accessToken || !user) return;
    const normalizedPhone = normalizePhone(newPhone);
    const validationError = validateRecipientPhone(newPhone, user.phone_number);
    if (validationError) {
      setPhoneError(validationError);
      return;
    }
    setPhoneError(null);
    setCreating(true);
    try {
      const { user_id: recipientId } = await lookupContact(accessToken, normalizedPhone);
      if (__DEV__) {
        console.log("[NewChat] POST /conversations payload:", { member_user_ids: [recipientId] });
      }
      const conv = await createConversation(accessToken, [recipientId]);
      closeNewChatModal();
      setNewPhone("");
      // No need to manually reload — useFocusEffect fires when chat screen is pushed,
      // but we do a silent reload here so the list is fresh before navigation.
      await load(true);
      router.push({
        pathname: "/chat/[id]",
        params: { id: conv.id, title: conv.display_title, otherUserId: recipientId },
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      if (__DEV__) console.error("[NewChat] error:", msg);
      Alert.alert("Could not start chat", msg);
    } finally {
      setCreating(false);
    }
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
        data={convs}
        keyExtractor={(item) => item.id}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor="#1F6FEB"
            colors={["#1F6FEB"]}
          />
        }
        ItemSeparatorComponent={() => <View style={styles.separator} />}
        contentContainerStyle={styles.listContent}
        ListEmptyComponent={
          <View style={styles.center}>
            <Text style={styles.emptyText}>No chats yet</Text>
            <Text style={styles.emptyHint}>Tap + to start a conversation</Text>
          </View>
        }
        renderItem={({ item }) => {
          const unread = getUnread(item.id);
          return (
            <TouchableOpacity
              style={styles.row}
              activeOpacity={0.7}
              onPress={() => {
                const other = user?.id && !item.is_group && item.members?.length === 2
                  ? item.members.find((m) => m !== user.id)
                  : undefined;
                router.push({
                  pathname: "/chat/[id]",
                  params: {
                    id: item.id,
                    title: item.display_title,
                    otherUserId: other ?? undefined,
                    otherAvatarUrl: item.other_avatar_url ?? undefined,
                    isGroup: item.is_group ? "true" : undefined,
                  },
                });
              }}
            >
              <View style={[styles.avatar, item.is_group && styles.avatarGroup]}>
                {item.is_group ? (
                  <Users color="#fff" size={22} />
                ) : (
                  <Avatar
                    avatarUrl={item.other_avatar_url}
                    displayName={item.display_title}
                    size={50}
                    style={styles.avatarImage}
                  />
                )}
              </View>
              <View style={styles.rowContent}>
                <View style={styles.rowTop}>
                  <Text style={styles.name} numberOfLines={1}>
                    {item.display_title}
                  </Text>
                  <View style={styles.rowRight}>
                    <Text style={styles.time}>{formatTime(item.last_message_at)}</Text>
                    {unread > 0 ? (
                      <View style={styles.unreadBadge}>
                        <Text style={styles.unreadBadgeText}>
                          {unread > 99 ? "99+" : unread}
                        </Text>
                      </View>
                    ) : null}
                  </View>
                </View>
                <Text style={styles.preview} numberOfLines={1}>
                  {item.last_message_preview || "No messages yet"}
                </Text>
              </View>
            </TouchableOpacity>
          );
        }}
      />

      <TouchableOpacity
        style={styles.fab}
        activeOpacity={0.8}
        onPress={() => {
          Alert.alert("New conversation", "Choose an option", [
            { text: "New Chat", onPress: () => { setNewPhone(""); setPhoneError(null); setModalVisible(true); } },
            { text: "New Group", onPress: () => { setGroupName(""); setGroupMembers([]); setGroupAddPhone(""); setGroupAddError(null); setGroupModalVisible(true); loadContactsForGroup(); } },
            { text: "Cancel", style: "cancel" },
          ]);
        }}
      >
        <Plus color="#fff" size={24} />
      </TouchableOpacity>

      <Modal
        visible={modalVisible}
        transparent
        animationType="slide"
        onRequestClose={closeNewChatModal}
      >
        <KeyboardAvoidingView
          style={styles.modalOverlay}
          behavior={Platform.OS === "ios" ? "padding" : "height"}
          keyboardVerticalOffset={0}
        >
          <View style={styles.modalSheet}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>New Chat</Text>
              <TouchableOpacity
                onPress={closeNewChatModal}
                hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
              >
                <X color="#6B7280" size={22} />
              </TouchableOpacity>
            </View>

            <Text style={styles.modalLabel}>Recipient phone number</Text>
            <TextInput
              style={[styles.modalInput, phoneError ? styles.modalInputError : null]}
              placeholder="+49 151 1234 5678"
              placeholderTextColor="#9CA3AF"
              keyboardType="phone-pad"
              autoFocus
              value={newPhone}
              onChangeText={(v) => {
                setNewPhone(v);
                setPhoneError(null);
              }}
              onSubmitEditing={handleNewChat}
              returnKeyType="done"
            />
            {phoneError ? (
              <Text style={styles.inlineError}>{phoneError}</Text>
            ) : null}

            {__DEV__ ? (
              <TouchableOpacity
                style={styles.devBtn}
                onPress={() => {
                  setNewPhone(DEV_TEST_RECIPIENT);
                  setPhoneError(null);
                }}
                activeOpacity={0.7}
              >
                <Text style={styles.devBtnText}>
                  🧪 Use test recipient ({DEV_TEST_RECIPIENT})
                </Text>
              </TouchableOpacity>
            ) : null}

            <TouchableOpacity
              style={[styles.modalBtn, creating && styles.modalBtnDisabled]}
              onPress={handleNewChat}
              disabled={creating}
              activeOpacity={0.8}
            >
              {creating ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.modalBtnText}>Start Chat</Text>
              )}
            </TouchableOpacity>
          </View>
        </KeyboardAvoidingView>
      </Modal>

      <Modal
        visible={groupModalVisible}
        transparent
        animationType="slide"
        onRequestClose={closeNewGroupModal}
      >
        <KeyboardAvoidingView
          style={styles.modalOverlay}
          behavior={Platform.OS === "ios" ? "padding" : "height"}
          keyboardVerticalOffset={0}
        >
          <View style={styles.modalSheet}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>New Group</Text>
              <TouchableOpacity
                onPress={closeNewGroupModal}
                hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
              >
                <X color="#6B7280" size={22} />
              </TouchableOpacity>
            </View>

            <Text style={styles.modalLabel}>Group name</Text>
            <TextInput
              style={styles.modalInput}
              placeholder="e.g. Team Project"
              placeholderTextColor="#9CA3AF"
              value={groupName}
              onChangeText={setGroupName}
            />

            <Text style={styles.modalLabel}>Add members (min. 2)</Text>
            <View style={styles.groupAddRow}>
              <TextInput
                style={[styles.modalInput, styles.groupAddInput, groupAddError ? styles.modalInputError : null]}
                placeholder="+49 151 1234 5678"
                placeholderTextColor="#9CA3AF"
                keyboardType="phone-pad"
                value={groupAddPhone}
                onChangeText={(v) => { setGroupAddPhone(v); setGroupAddError(null); }}
                onSubmitEditing={addGroupMemberByPhone}
                returnKeyType="done"
              />
              <TouchableOpacity style={styles.groupAddBtn} onPress={addGroupMemberByPhone}>
                <Text style={styles.groupAddBtnText}>Add</Text>
              </TouchableOpacity>
            </View>
            {groupAddError ? <Text style={styles.inlineError}>{groupAddError}</Text> : null}

            {contacts.length > 0 ? (
              <>
                <Text style={styles.modalLabel}>Or pick from contacts</Text>
                <View style={styles.contactChips}>
                  {contacts.map((c) => {
                    const selected = groupMembers.some((m) => m.user_id === c.user_id);
                    return (
                      <TouchableOpacity
                        key={c.user_id}
                        style={[styles.contactChip, selected && styles.contactChipSelected]}
                        onPress={() => {
                          if (selected) removeGroupMember(c.user_id);
                          else setGroupMembers((prev) => [...prev, c]);
                        }}
                      >
                        <Text style={styles.contactChipText} numberOfLines={1}>
                          {c.display_name || c.phone_number}
                        </Text>
                      </TouchableOpacity>
                    );
                  })}
                </View>
              </>
            ) : null}

            {groupMembers.length > 0 ? (
              <View style={styles.selectedMembers}>
                {groupMembers.map((m) => (
                  <View key={m.user_id} style={styles.selectedMemberChip}>
                    <Text style={styles.selectedMemberText} numberOfLines={1}>
                      {m.display_name || m.phone_number}
                    </Text>
                    <TouchableOpacity hitSlop={8} onPress={() => removeGroupMember(m.user_id)}>
                      <X color="#6B7280" size={16} />
                    </TouchableOpacity>
                  </View>
                ))}
              </View>
            ) : null}

            <TouchableOpacity
              style={[styles.modalBtn, (groupCreating || groupMembers.length < 2) && styles.modalBtnDisabled]}
              onPress={handleCreateGroup}
              disabled={groupCreating || groupMembers.length < 2}
              activeOpacity={0.8}
            >
              {groupCreating ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.modalBtnText}>Create Group</Text>
              )}
            </TouchableOpacity>
          </View>
        </KeyboardAvoidingView>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  listContent: { paddingHorizontal: 12, paddingVertical: 8, paddingBottom: 100 },
  center: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32 },
  errorText: { fontSize: 15, color: "#FF3B30", textAlign: "center", marginBottom: 12 },
  retryBtn: {
    paddingHorizontal: 24,
    paddingVertical: 12,
    backgroundColor: "#1F6FEB",
    borderRadius: 12,
  },
  retryText: { color: "#fff", fontWeight: "600" },
  emptyText: { fontSize: 17, fontWeight: "600", color: "#111827", marginBottom: 4 },
  emptyHint: { fontSize: 14, color: "#6B7280" },
  separator: { height: 8 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FFFFFF",
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 14,
    marginHorizontal: 4,
  },
  avatarImage: { backgroundColor: "transparent" },
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
  avatarGroup: {},
  rowContent: { flex: 1, minWidth: 0 },
  rowTop: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 4,
  },
  name: { fontSize: 16, fontWeight: "700", color: "#111827", flex: 1, marginRight: 8 },
  rowRight: { flexDirection: "row", alignItems: "center", gap: 8, flexShrink: 0 },
  time: { fontSize: 12, color: "#6B7280", fontWeight: "500" },
  unreadBadge: {
    minWidth: 22,
    height: 22,
    borderRadius: 11,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 6,
  },
  unreadBadgeText: { color: "#fff", fontSize: 12, fontWeight: "700" },
  preview: { fontSize: 14, color: "#6B7280", lineHeight: 20 },
  fab: {
    position: "absolute",
    bottom: 24,
    right: 20,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.15,
    shadowRadius: 8,
  },
  modalOverlay: {
    flex: 1,
    justifyContent: "flex-end",
    backgroundColor: "rgba(0,0,0,0.4)",
  },
  modalSheet: {
    backgroundColor: "#fff",
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    padding: 24,
    paddingBottom: 40,
  },
  modalHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 20,
  },
  modalTitle: { fontSize: 18, fontWeight: "700", color: "#111827" },
  modalLabel: { fontSize: 13, color: "#6B7280", marginBottom: 8 },
  modalInput: {
    height: 52,
    borderWidth: 1.5,
    borderColor: "#E5E5EA",
    borderRadius: 12,
    paddingHorizontal: 16,
    fontSize: 17,
    color: "#000",
    marginBottom: 4,
  },
  modalInputError: { borderColor: "#FF3B30" },
  inlineError: {
    fontSize: 13,
    color: "#FF3B30",
    marginBottom: 10,
    marginLeft: 4,
  },
  devBtn: {
    backgroundColor: "#FFF3CD",
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 12,
    marginBottom: 12,
    alignItems: "center",
  },
  devBtnText: { fontSize: 13, color: "#856404", fontWeight: "500" },
  modalBtn: {
    height: 52,
    backgroundColor: "#1F6FEB",
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
  },
  modalBtnDisabled: { opacity: 0.6 },
  modalBtnText: { color: "#fff", fontSize: 17, fontWeight: "600" },

  groupAddRow: { flexDirection: "row", gap: 8, alignItems: "center", marginBottom: 4 },
  groupAddInput: { flex: 1, marginBottom: 0 },
  groupAddBtn: { backgroundColor: "#1F6FEB", paddingHorizontal: 16, paddingVertical: 12, borderRadius: 12 },
  groupAddBtnText: { color: "#fff", fontWeight: "600" },
  contactChips: { flexDirection: "row", flexWrap: "wrap", gap: 8, marginBottom: 12 },
  contactChip: {
    backgroundColor: "#E5E7EB",
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 20,
  },
  contactChipSelected: { backgroundColor: "#1F6FEB" },
  contactChipText: { fontSize: 14, color: "#111827", maxWidth: 120 },
  selectedMembers: { flexDirection: "row", flexWrap: "wrap", gap: 8, marginBottom: 16 },
  selectedMemberChip: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#DCF4FF",
    paddingLeft: 12,
    paddingRight: 6,
    paddingVertical: 6,
    borderRadius: 20,
    gap: 6,
  },
  selectedMemberText: { fontSize: 14, color: "#111827", maxWidth: 100 },
});
