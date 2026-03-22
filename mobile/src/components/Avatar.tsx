import React from "react";
import { Image, StyleSheet, Text, View } from "react-native";
import { API_BASE } from "../lib/api";

interface AvatarProps {
  avatarUrl?: string | null;
  displayName?: string;
  size?: number;
  style?: object;
}

export function Avatar({
  avatarUrl,
  displayName,
  size = 48,
  style,
}: AvatarProps) {
  const initial = (displayName?.trim() || "?")[0].toUpperCase();
  const containerStyle = [
    styles.circle,
    { width: size, height: size, borderRadius: size / 2 },
    style,
  ];

  if (avatarUrl?.trim()) {
    const uri = avatarUrl.startsWith("http") ? avatarUrl : `${API_BASE}${avatarUrl}`;
    return (
      <Image
        source={{ uri }}
        style={containerStyle}
        resizeMode="cover"
      />
    );
  }

  return (
    <View style={[containerStyle, styles.initialContainer]}>
      <Text style={[styles.initial, { fontSize: size * 0.45 }]}>{initial}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  circle: {
    overflow: "hidden",
  },
  initialContainer: {
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
  },
  initial: {
    color: "#fff",
    fontWeight: "600",
  },
});
