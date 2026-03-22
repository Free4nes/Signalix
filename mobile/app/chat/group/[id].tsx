import { useLocalSearchParams, useRouter } from "expo-router";
import { Plus, UserMinus, X } from "lucide-react-native";
import { useCallback, useEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { Avatar } from "../../../src/components/Avatar";
import { useAuth } from "../../../src/context/auth";
import {
  addConversationMember,
  getConversation,
  lookupContact,
  removeConversationMember,
  syncContacts,
  updateConversationTitle,
  type ConversationDetail,
  type ConversationMember,
  type SyncUser,
} from "../../../src/lib/api";

function normalizePhone(input: string): string {
  let s = input.trim().replace(/[\s\-().]/g, "");
  if (s.startsWith("00")) s = "+" + s.slice(2);
  return s;
}

function validatePhone(input: string, ownPhone: string): string | null {
  const normalized = normalizePhone(input);
  if (!normalized) return "Phone number is required.";
  if (!/^\+[1-9]\d{6,14}$/.test(normalized)) return "Enter a valid phone number (e.g. +4915112345678).";
  if (normalized === ownPhone) return "Cannot add yourself.";
  return null;
}

const DEV_PHONES = ["+49911111111", "+49911111112", "+49911111113", "+49911111114", "+49911111115"];

function memberLabel(m: ConversationMember): string {
  return (m.display_name && m.display_name.trim()) || m.phone_number || m.user_id;
}

export default function GroupDetailsScreen() {
  const { id: convId } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const { accessToken, user } = useAuth();

  const [detail, setDetail] = useState<ConversationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editTitle, setEditTitle] = useState("");
  const [isEditingTitle, setIsEditingTitle] = useState(false);
  const [addPhone, setAddPhone] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [contacts, setContacts] = useState<SyncUser[]>([]);

  const load = useCallback(async () => {
    if (!accessToken || !convId) {
      if (__DEV__) console.log("GROUP_DETAILS_SKIP", { hasToken: !!accessToken, convId });
      return;
    }
    setLoading(true);
    if (__DEV__) console.log("GROUP_DETAILS_FETCH", convId);
    try {
      const d = await getConversation(accessToken, convId);
      if (__DEV__) console.log("GROUP_DETAILS_FETCH_OK", convId, "members=" + d.members?.length);
      setDetail(d);
      setEditTitle((d.title ?? d.display_title ?? "Group").trim());
    } catch (e) {
      if (__DEV__) console.warn("GROUP_DETAILS_FETCH_ERROR", convId, e);
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to load group details");
      router.back();
    } finally {
      setLoading(false);
    }
  }, [accessToken, convId, router]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!accessToken) return;
    syncContacts(accessToken, DEV_PHONES)
      .then((users) => setContacts(users.filter((c) => c.user_id !== user?.id)))
      .catch(() => setContacts([]));
  }, [accessToken, user?.id]);

  const handleSaveTitle = useCallback(async () => {
    if (!accessToken || !convId || !detail) return;
    const trimmed = editTitle.trim() || "Group";
    if (trimmed === (detail.title ?? detail.display_title ?? "Group")) {
      setIsEditingTitle(false);
      return;
    }
    setSaving(true);
    try {
      const updated = await updateConversationTitle(accessToken, convId, trimmed);
      setDetail((prev) =>
        prev ? { ...prev, title: updated.title, display_title: updated.display_title } : prev
      );
      setIsEditingTitle(false);
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to rename");
    } finally {
      setSaving(false);
    }
  }, [accessToken, convId, detail, editTitle]);

  const handleAddByPhone = useCallback(() => {
    if (!accessToken) return;
    const err = validatePhone(addPhone, user?.phone_number ?? "");
    if (err) {
      setAddError(err);
      return;
    }
    setAddError(null);
    const normalized = normalizePhone(addPhone);
    setAddPhone("");
    lookupContact(accessToken, normalized)
      .then(async ({ user_id }) => {
        if (detail?.members.some((m) => m.user_id === user_id)) {
          setAddError("Already in group");
          return;
        }
        setSaving(true);
        try {
          await addConversationMember(accessToken, convId!, user_id);
          const d = await getConversation(accessToken, convId!);
          setDetail(d);
        } catch (e) {
          Alert.alert("Error", e instanceof Error ? e.message : "Failed to add member");
        } finally {
          setSaving(false);
        }
      })
      .catch((e) => setAddError(e instanceof Error ? e.message : "User not found"));
  }, [accessToken, addPhone, user?.phone_number, detail, convId, contacts]);

  const handleAddFromContact = useCallback(
    async (c: SyncUser) => {
      if (!accessToken || !convId) return;
      if (detail?.members.some((m) => m.user_id === c.user_id)) return;
      setSaving(true);
      try {
        await addConversationMember(accessToken, convId, c.user_id);
        const d = await getConversation(accessToken, convId);
        setDetail(d);
      } catch (e) {
        Alert.alert("Error", e instanceof Error ? e.message : "Failed to add member");
      } finally {
        setSaving(false);
      }
    },
    [accessToken, convId, detail]
  );

  const handleRemove = useCallback(
    (userId: string) => {
      if (!accessToken || !convId) return;
      const isSelf = userId === user?.id;
      Alert.alert(
        isSelf ? "Leave group?" : "Remove member?",
        isSelf
          ? "You will no longer receive messages from this group."
          : "This person will be removed from the group.",
        [
          { text: "Cancel", style: "cancel" },
          {
            text: isSelf ? "Leave" : "Remove",
            style: "destructive",
            onPress: async () => {
              setSaving(true);
              try {
                await removeConversationMember(accessToken, convId, userId);
                if (isSelf) {
                  router.back();
                  return;
                }
                const d = await getConversation(accessToken, convId);
                setDetail(d);
              } catch (e) {
                Alert.alert("Error", e instanceof Error ? e.message : "Failed to remove");
              } finally {
                setSaving(false);
              }
            },
          },
        ]
      );
    },
    [accessToken, convId, user?.id, router]
  );

  if (loading || !detail) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#1F6FEB" />
      </View>
    );
  }

  const displayName = detail.title ?? detail.display_title ?? "Group";

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={90}
    >
      <ScrollView style={styles.scroll} contentContainerStyle={styles.scrollContent}>
        <View style={styles.section}>
          <Text style={styles.label}>Group name</Text>
          {isEditingTitle ? (
            <View style={styles.titleRow}>
              <TextInput
                style={styles.input}
                value={editTitle}
                onChangeText={setEditTitle}
                placeholder="Group name"
                placeholderTextColor="#9CA3AF"
                autoFocus
              />
              <TouchableOpacity
                style={styles.saveBtn}
                onPress={handleSaveTitle}
                disabled={saving}
              >
                {saving ? (
                  <ActivityIndicator size="small" color="#fff" />
                ) : (
                  <Text style={styles.saveBtnText}>Save</Text>
                )}
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.cancelBtn}
                onPress={() => {
                  setEditTitle(displayName);
                  setIsEditingTitle(false);
                }}
                disabled={saving}
              >
                <X color="#6B7280" size={20} />
              </TouchableOpacity>
            </View>
          ) : (
            <TouchableOpacity
              style={styles.titleDisplay}
              onPress={() => setIsEditingTitle(true)}
              activeOpacity={0.7}
            >
              <Text style={styles.titleText}>{displayName}</Text>
              <Text style={styles.editHint}>Tap to rename</Text>
            </TouchableOpacity>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.label}>Members ({detail.members.length})</Text>
          {detail.members.map((m) => (
            <View key={m.user_id} style={styles.memberRow}>
              <Avatar
                avatarUrl={m.avatar_url}
                displayName={memberLabel(m)}
                size={40}
                style={styles.memberAvatar}
              />
              <View style={styles.memberInfo}>
                <Text style={styles.memberName} numberOfLines={1}>
                  {memberLabel(m)}
                </Text>
                {m.display_name && (
                  <Text style={styles.memberPhone} numberOfLines={1}>
                    {m.phone_number}
                  </Text>
                )}
              </View>
              <TouchableOpacity
                style={styles.removeBtn}
                onPress={() => handleRemove(m.user_id)}
                disabled={saving}
              >
                <UserMinus color="#DC2626" size={20} />
              </TouchableOpacity>
            </View>
          ))}
        </View>

        <View style={styles.section}>
          <Text style={styles.label}>Add member</Text>
          <View style={styles.addRow}>
            <TextInput
              style={[styles.input, styles.addInput, addError ? styles.inputError : null]}
              placeholder="+49 151 1234 5678"
              placeholderTextColor="#9CA3AF"
              keyboardType="phone-pad"
              value={addPhone}
              onChangeText={(v) => {
                setAddPhone(v);
                setAddError(null);
              }}
              onSubmitEditing={handleAddByPhone}
              returnKeyType="done"
            />
            <TouchableOpacity
              style={[styles.addBtn, saving && styles.addBtnDisabled]}
              onPress={handleAddByPhone}
              disabled={saving}
            >
              <Plus color="#fff" size={20} />
            </TouchableOpacity>
          </View>
          {addError ? <Text style={styles.errorText}>{addError}</Text> : null}

          {contacts.length > 0 ? (
            <>
              <Text style={styles.subLabel}>Or pick from contacts</Text>
              <View style={styles.contactRow}>
                {contacts
                  .filter((c) => !detail.members.some((m) => m.user_id === c.user_id))
                  .map((c) => (
                    <TouchableOpacity
                      key={c.user_id}
                      style={styles.contactChip}
                      onPress={() => handleAddFromContact(c)}
                      disabled={saving}
                    >
                      <Text style={styles.contactChipText} numberOfLines={1}>
                        {c.display_name || c.phone_number}
                      </Text>
                      <Plus color="#1F6FEB" size={14} />
                    </TouchableOpacity>
                  ))}
              </View>
            </>
          ) : null}
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  center: { flex: 1, alignItems: "center", justifyContent: "center" },
  scroll: { flex: 1 },
  scrollContent: { padding: 16, paddingBottom: 32 },
  section: { marginBottom: 24 },
  label: { fontSize: 14, fontWeight: "600", color: "#374151", marginBottom: 8 },
  subLabel: { fontSize: 13, color: "#6B7280", marginTop: 12, marginBottom: 6 },
  titleDisplay: {
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: "#E5E7EB",
  },
  titleText: { fontSize: 17, fontWeight: "600", color: "#111827" },
  editHint: { fontSize: 12, color: "#6B7280", marginTop: 4 },
  titleRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  input: {
    flex: 1,
    backgroundColor: "#fff",
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 15,
    color: "#111827",
    borderWidth: 1,
    borderColor: "#E5E7EB",
  },
  inputError: { borderColor: "#DC2626" },
  saveBtn: {
    backgroundColor: "#1F6FEB",
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 10,
    minWidth: 60,
    alignItems: "center",
  },
  saveBtnText: { color: "#fff", fontWeight: "600" },
  cancelBtn: { padding: 8 },
  memberRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
  },
  memberAvatar: { marginRight: 12 },
  memberInfo: { flex: 1, minWidth: 0 },
  memberName: { fontSize: 15, fontWeight: "600", color: "#111827" },
  memberPhone: { fontSize: 13, color: "#6B7280", marginTop: 2 },
  removeBtn: { padding: 8 },
  addRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  addInput: { flex: 1 },
  addBtn: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
  },
  addBtnDisabled: { opacity: 0.6 },
  errorText: { fontSize: 13, color: "#DC2626", marginTop: 6 },
  contactRow: { flexDirection: "row", flexWrap: "wrap", gap: 8, marginTop: 8 },
  contactChip: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: "#fff",
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "#E5E7EB",
  },
  contactChipText: { fontSize: 14, color: "#111827", maxWidth: 120 },
});
