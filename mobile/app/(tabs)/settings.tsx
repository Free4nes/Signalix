import { useState } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Platform,
  Alert,
  Modal,
  TextInput,
  KeyboardAvoidingView,
  ActionSheetIOS,
  ScrollView,
} from "react-native";
import { useRouter } from "expo-router";
import Constants from "expo-constants";
import { ChevronRight } from "lucide-react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useAuth } from "../../src/context/auth";
import { Avatar } from "../../src/components/Avatar";
import { API_BASE, patchMe, putMeAvatar, uploadImage } from "../../src/lib/api";

type HealthStatus = "idle" | "loading" | "ok" | "error";

export default function SettingsScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { user, accessToken, signOut, updateUser } = useAuth();
  const [healthStatus, setHealthStatus] = useState<HealthStatus>("idle");
  const [healthDetail, setHealthDetail] = useState<string>("");
  const [profileModalVisible, setProfileModalVisible] = useState(false);
  const [profileNameDraft, setProfileNameDraft] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingAvatar, setSavingAvatar] = useState(false);

  async function checkHealth() {
    setHealthStatus("loading");
    setHealthDetail("");
    try {
      const res = await fetch(`${API_BASE}/health`);
      const body = await res.text();
      setHealthStatus(res.ok ? "ok" : "error");
      setHealthDetail(`${res.status} ${body.trim()}`);
    } catch (e: unknown) {
      setHealthStatus("error");
      setHealthDetail(e instanceof Error ? e.message : String(e));
    }
  }

  function openProfileEdit() {
    setProfileNameDraft(user?.display_name?.trim() ?? "");
    setProfileModalVisible(true);
  }

  async function handleSaveProfile() {
    if (!accessToken || !user) return;
    const trimmed = profileNameDraft.trim();
    setSavingProfile(true);
    try {
      const updated = await patchMe(accessToken, trimmed || null);
      await updateUser(updated);
      setProfileModalVisible(false);
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to update profile");
    } finally {
      setSavingProfile(false);
    }
  }

  async function handlePickAvatarImage() {
    if (!accessToken || !user) return;
    const ImagePicker = await import("expo-image-picker");
    const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (status !== "granted") {
      Alert.alert("Permission required", "Gallery access is needed to set a profile picture.");
      return;
    }
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ["images"],
      quality: 0.8,
      allowsEditing: true,
      aspect: [1, 1],
    });
    if (result.canceled || !result.assets?.[0]) return;
    await uploadAndSetAvatar(result.assets[0].uri, result.assets[0].mimeType ?? "image/jpeg");
  }

  async function handleTakeAvatarPhoto() {
    if (!accessToken || !user) return;
    const ImagePicker = await import("expo-image-picker");
    const { status } = await ImagePicker.requestCameraPermissionsAsync();
    if (status !== "granted") {
      Alert.alert("Permission required", "Camera access is needed to take a profile photo.");
      return;
    }
    const result = await ImagePicker.launchCameraAsync({
      mediaTypes: ["images"],
      quality: 0.8,
    });
    if (result.canceled || !result.assets?.[0]) return;
    await uploadAndSetAvatar(result.assets[0].uri, result.assets[0].mimeType ?? "image/jpeg");
  }

  async function uploadAndSetAvatar(uri: string, mimeType: string) {
    if (!accessToken) return;
    setSavingAvatar(true);
    try {
      const { url } = await uploadImage(accessToken, uri, mimeType);
      const updated = await putMeAvatar(accessToken, url);
      await updateUser(updated);
    } catch (e) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to update profile picture");
    } finally {
      setSavingAvatar(false);
    }
  }

  function openAvatarPicker() {
    if (Platform.OS === "ios") {
      ActionSheetIOS.showActionSheetWithOptions(
        {
          options: ["Cancel", "Choose from gallery", "Take photo"],
          cancelButtonIndex: 0,
        },
        (index) => {
          if (index === 1) handlePickAvatarImage();
          else if (index === 2) handleTakeAvatarPhoto();
        }
      );
    } else {
      Alert.alert("Profile picture", undefined, [
        { text: "Choose from gallery", onPress: handlePickAvatarImage },
        { text: "Take photo", onPress: handleTakeAvatarPhoto },
        { text: "Cancel", style: "cancel" },
      ]);
    }
  }

  async function handleSignOut() {
    Alert.alert("Sign out", "Are you sure?", [
      { text: "Cancel", style: "cancel" },
      { text: "Sign out", style: "destructive", onPress: signOut },
    ]);
  }

  const statusColor: Record<HealthStatus, string> = {
    idle: "#6B7280",
    loading: "#6B7280",
    ok: "#1F6FEB",
    error: "#FF3B30",
  };

  return (
    <ScrollView
      style={styles.screen}
      contentContainerStyle={[styles.contentContainer, { paddingBottom: 28 + insets.bottom }]}
      showsVerticalScrollIndicator={false}
    >
      {user && (
        <>
          <View style={styles.profileCard}>
            <TouchableOpacity
              style={styles.profileRow}
              onPress={openAvatarPicker}
              disabled={savingAvatar}
              activeOpacity={0.7}
            >
              <Avatar
                avatarUrl={user.avatar_url}
                displayName={user.display_name?.trim() || user.phone_number}
                size={72}
              />
              <View style={styles.profileTextWrap}>
                <Text style={styles.profileName} numberOfLines={1}>
                  {user.display_name?.trim() || "No profile name"}
                </Text>
                <Text style={styles.profilePhone} numberOfLines={1}>
                  {user.phone_number}
                </Text>
                <Text style={styles.profileHint}>
                  {savingAvatar ? "Saving profile picture…" : "Tap avatar to change photo"}
                </Text>
              </View>
              {savingAvatar ? (
                <ActivityIndicator color="#1F6FEB" style={styles.profileSpinner} />
              ) : (
                <ChevronRight size={18} color="#9CA3AF" />
              )}
            </TouchableOpacity>
          </View>

          <Text style={styles.sectionHeader}>ACCOUNT</Text>
          <View style={styles.card}>
            <TouchableOpacity
              style={styles.actionRow}
              onPress={openProfileEdit}
              activeOpacity={0.7}
            >
              <View style={styles.actionTextWrap}>
                <Text style={styles.actionLabel}>Profile Name</Text>
                <Text style={styles.actionValue} numberOfLines={1} ellipsizeMode="tail">
                  {user.display_name?.trim() || user.phone_number}
                </Text>
              </View>
              <ChevronRight size={18} color="#9CA3AF" style={styles.rowChevron} />
            </TouchableOpacity>
            <Row label="Phone" value={user.phone_number} />
            <Row label="User ID" value={user.id} />
          </View>

          <Modal visible={profileModalVisible} transparent animationType="fade">
            <TouchableOpacity
              style={styles.modalOverlay}
              activeOpacity={1}
              onPress={() => setProfileModalVisible(false)}
            >
              <KeyboardAvoidingView
                behavior={Platform.OS === "ios" ? "padding" : undefined}
                style={styles.modalContent}
              >
                <TouchableOpacity activeOpacity={1} onPress={(e) => e.stopPropagation()}>
                  <View style={styles.modalBox}>
                    <Text style={styles.modalTitle}>Profile Name</Text>
                    <TextInput
                      style={styles.modalInput}
                      value={profileNameDraft}
                      onChangeText={setProfileNameDraft}
                      placeholder={user.phone_number}
                      placeholderTextColor="#9CA3AF"
                      autoFocus
                    />
                    <View style={styles.modalButtons}>
                      <TouchableOpacity
                        style={styles.modalCancel}
                        onPress={() => setProfileModalVisible(false)}
                      >
                        <Text style={styles.modalCancelText}>Cancel</Text>
                      </TouchableOpacity>
                      <TouchableOpacity
                        style={[styles.modalSave, savingProfile && styles.modalSaveDisabled]}
                        onPress={handleSaveProfile}
                        disabled={savingProfile}
                      >
                        {savingProfile ? (
                          <ActivityIndicator color="#fff" size="small" />
                        ) : (
                          <Text style={styles.modalSaveText}>Save</Text>
                        )}
                      </TouchableOpacity>
                    </View>
                  </View>
                </TouchableOpacity>
              </KeyboardAvoidingView>
            </TouchableOpacity>
          </Modal>
        </>
      )}

      <Text style={styles.sectionHeader}>PRIVACY</Text>
      <View style={styles.card}>
        <TouchableOpacity
          style={styles.actionRow}
          onPress={() => router.push("/blocked-users")}
          activeOpacity={0.7}
        >
          <View style={styles.actionTextWrap}>
            <Text style={styles.actionLabel}>Blocked Users</Text>
            <Text style={styles.actionHint}>Manage people you blocked</Text>
          </View>
          <ChevronRight size={18} color="#9CA3AF" />
        </TouchableOpacity>
      </View>

      <Text style={styles.sectionHeader}>APP INFO</Text>
      <View style={styles.card}>
        <Row label="App" value={Constants.expoConfig?.name ?? "—"} compact />
        <Row label="Version" value={Constants.expoConfig?.version ?? "—"} compact />
        <Row label="SDK" value={Constants.expoConfig?.sdkVersion ?? "—"} compact />
        <Row label="Platform" value={Platform.OS} compact />
      </View>

      <Text style={styles.sectionHeader}>BACKEND</Text>
      <View style={styles.card}>
        <Row label="API base" value={API_BASE} compact />
        <TouchableOpacity
          style={styles.checkHealthBtn}
          onPress={checkHealth}
          activeOpacity={0.8}
          disabled={healthStatus === "loading"}
        >
          {healthStatus === "loading" ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.checkHealthBtnText}>Check /health</Text>
          )}
        </TouchableOpacity>
      </View>

      {healthStatus !== "idle" && healthStatus !== "loading" && (
        <View style={styles.resultBox}>
          <Text style={[styles.resultText, { color: statusColor[healthStatus] }]}>
            {healthStatus === "ok" ? "✓ " : "✗ "}
            {healthDetail}
          </Text>
        </View>
      )}

      <TouchableOpacity style={styles.signOutBtn} onPress={handleSignOut} activeOpacity={0.8}>
        <Text style={styles.signOutText}>Sign out</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

function Row({ label, value, compact = false }: { label: string; value: string; compact?: boolean }) {
  return (
    <View style={[styles.row, compact && styles.rowCompact]}>
      <Text style={[styles.rowLabel, compact && styles.rowLabelCompact]}>{label}</Text>
      <Text
        style={[styles.rowValue, compact && styles.rowValueCompact]}
        numberOfLines={1}
        ellipsizeMode="middle"
      >
        {value}
      </Text>
    </View>
  );
}


const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#F6F8FC" },
  contentContainer: { paddingHorizontal: 16, paddingTop: 16, paddingBottom: 24 },
  sectionHeader: {
    fontSize: 11,
    fontWeight: "600",
    color: "#6B7280",
    marginBottom: 10,
    marginTop: 20,
    letterSpacing: 0.6,
  },
  profileCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 18,
    paddingHorizontal: 16,
    paddingVertical: 16,
    borderWidth: 1,
    borderColor: "#E8ECF4",
    shadowColor: "#000",
    shadowOpacity: 0.04,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 3 },
    elevation: 1,
  },
  profileRow: {
    flexDirection: "row",
    alignItems: "center",
  },
  profileTextWrap: { flex: 1, marginLeft: 14, marginRight: 10, minWidth: 0 },
  profileName: { fontSize: 18, color: "#0F172A", fontWeight: "700", lineHeight: 23 },
  profilePhone: { fontSize: 14, color: "#475569", marginTop: 3, lineHeight: 19 },
  profileHint: { fontSize: 12, color: "#64748B", marginTop: 5, lineHeight: 16 },
  profileSpinner: { marginLeft: 8 },
  card: {
    backgroundColor: "#FFFFFF",
    borderRadius: 16,
    borderWidth: 1,
    borderColor: "#E8ECF4",
    overflow: "hidden",
  },
  actionRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 16,
    paddingVertical: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#E5E7EB",
  },
  actionTextWrap: { flex: 1, minWidth: 0, marginRight: 8 },
  actionLabel: { fontSize: 15, color: "#111827", fontWeight: "600" },
  actionValue: { fontSize: 13, color: "#6B7280", marginTop: 3 },
  actionHint: { fontSize: 13, color: "#6B7280", marginTop: 3 },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: 16,
    paddingVertical: 13,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#E5E7EB",
  },
  rowCompact: { paddingVertical: 10 },
  rowLabel: { fontSize: 14, color: "#334155" },
  rowLabelCompact: { fontSize: 13, color: "#64748B" },
  rowValue: { fontSize: 14, color: "#6B7280", maxWidth: "55%" },
  rowValueCompact: { fontSize: 13, color: "#64748B" },
  rowChevron: { marginLeft: 4 },
  checkHealthBtn: {
    margin: 14,
    backgroundColor: "#1F6FEB",
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: "center",
  },
  checkHealthBtnText: { color: "#fff", fontSize: 15, fontWeight: "600" },
  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.4)",
    justifyContent: "center",
    padding: 24,
  },
  modalContent: { justifyContent: "center" },
  modalBox: {
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 20,
  },
  modalTitle: { fontSize: 18, fontWeight: "700", color: "#111827", marginBottom: 12 },
  modalInput: {
    borderWidth: 1,
    borderColor: "#E5E7EB",
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 16,
    color: "#111827",
    marginBottom: 16,
  },
  modalButtons: { flexDirection: "row", justifyContent: "flex-end", gap: 12 },
  modalCancel: { paddingVertical: 8, paddingHorizontal: 16 },
  modalCancelText: { fontSize: 16, color: "#6B7280" },
  modalSave: {
    backgroundColor: "#1F6FEB",
    paddingVertical: 8,
    paddingHorizontal: 20,
    borderRadius: 10,
    minWidth: 80,
    alignItems: "center",
  },
  modalSaveDisabled: { opacity: 0.6 },
  modalSaveText: { fontSize: 16, fontWeight: "600", color: "#fff" },
  resultBox: {
    marginTop: 12,
    backgroundColor: "#FFFFFF",
    borderRadius: 10,
    padding: 14,
    borderWidth: 1,
    borderColor: "#E8ECF4",
  },
  resultText: {
    fontSize: 13,
    fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
  },
  signOutBtn: {
    marginTop: 24,
    backgroundColor: "#FF3B30",
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
    marginBottom: 6,
    borderWidth: 1,
    borderColor: "#FCA5A5",
  },
  signOutText: { color: "#fff", fontSize: 16, fontWeight: "600" },
});
