import { useLocalSearchParams, useNavigation } from "expo-router";
import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import {
  ActivityIndicator,
  Dimensions,
  Image,
  Modal,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { useAuth } from "../../../src/context/auth";
import { API_BASE, listMessages } from "../../../src/lib/api";
import type { Message } from "../../../src/lib/api";

const COLS = 3;
const GAP = 4;

export default function MediaGalleryScreen() {
  const { id: convId } = useLocalSearchParams<{ id: string }>();
  const navigation = useNavigation();
  const { accessToken } = useAuth();
  const [images, setImages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(true);
  const [fullscreenUri, setFullscreenUri] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!accessToken || !convId) return;
    setLoading(true);
    try {
      const msgs = await listMessages(accessToken, convId, 100);
      const imgMsgs = msgs.filter((m) => m.msg_type === "image" && m.body_preview && !m.deleted_for_everyone);
      setImages(imgMsgs);
    } catch {
      setImages([]);
    } finally {
      setLoading(false);
    }
  }, [accessToken, convId]);

  useEffect(() => {
    load();
  }, [load]);

  useLayoutEffect(() => {
    navigation.setOptions({ title: "Media" });
  }, [navigation]);

  const { width } = Dimensions.get("window");
  const tileSize = (width - 32 - GAP * (COLS - 1)) / COLS;

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#1F6FEB" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {images.length === 0 ? (
        <View style={styles.center}>
          <Text style={styles.emptyText}>No images in this chat</Text>
        </View>
      ) : (
        <View style={styles.grid}>
          {images.map((m) => {
            const uri = m.body_preview?.startsWith("http") ? m.body_preview : `${API_BASE}${m.body_preview}`;
            return (
              <TouchableOpacity
                key={m.id}
                style={[styles.tile, { width: tileSize, height: tileSize }]}
                onPress={() => setFullscreenUri(uri)}
                activeOpacity={0.9}
              >
                <Image source={{ uri }} style={styles.tileImage} resizeMode="cover" />
              </TouchableOpacity>
            );
          })}
        </View>
      )}

      {fullscreenUri ? (
        <Modal visible transparent animationType="fade">
          <TouchableOpacity
            style={styles.fullscreenOverlay}
            activeOpacity={1}
            onPress={() => setFullscreenUri(null)}
          >
            <Image source={{ uri: fullscreenUri }} style={styles.fullscreenImage} resizeMode="contain" />
          </TouchableOpacity>
        </Modal>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  center: { flex: 1, alignItems: "center", justifyContent: "center" },
  emptyText: { fontSize: 16, color: "#6B7280" },
  grid: {
    flexDirection: "row",
    flexWrap: "wrap",
    padding: 16,
    gap: GAP,
  },
  tile: { borderRadius: 8, overflow: "hidden", backgroundColor: "#E5E7EB" },
  tileImage: { width: "100%", height: "100%" },
  fullscreenOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.95)",
    justifyContent: "center",
    alignItems: "center",
  },
  fullscreenImage: { width: "100%", height: "100%" },
});
