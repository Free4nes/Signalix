import { useEffect, useRef, useState } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Alert,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useAuth } from "../src/context/auth";

export default function OtpScreen() {
  const router = useRouter();
  const { phone, devOtp } = useLocalSearchParams<{ phone: string; devOtp?: string }>();
  const { confirmOtp } = useAuth();

  const [code, setCode] = useState(devOtp ?? "");
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    // Pre-fill dev OTP and auto-focus
    if (devOtp) setCode(devOtp);
    setTimeout(() => inputRef.current?.focus(), 300);
  }, [devOtp]);

  async function handleVerify() {
    const trimmed = code.trim();
    if (trimmed.length < 4) {
      Alert.alert("Invalid code", "Please enter the 6-digit code.");
      return;
    }
    if (__DEV__) {
      console.log("OTP_VERIFY_START", { phone, otp: trimmed });
    }
    setLoading(true);
    try {
      await confirmOtp(phone, trimmed);
      if (__DEV__) console.log("OTP_VERIFY_SUCCESS");
      // Auth context update triggers root layout redirect to tabs
      router.replace("/(tabs)/chats");
      if (__DEV__) console.log("OTP_VERIFY_NAVIGATION_DONE");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      if (__DEV__) console.warn("OTP_VERIFY_FAIL", { error: msg, err: e });
      Alert.alert("Verification failed", msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <View style={styles.inner}>
        <Text style={styles.title}>Enter code</Text>
        <Text style={styles.subtitle}>
          We sent a code to{"\n"}
          <Text style={styles.phone}>{phone}</Text>
        </Text>

        {devOtp ? (
          <View style={styles.devBanner}>
            <Text style={styles.devText}>DEV MODE — code pre-filled: {devOtp}</Text>
          </View>
        ) : null}

        <TextInput
          ref={inputRef}
          style={styles.input}
          placeholder="123456"
          placeholderTextColor="#aaa"
          keyboardType="number-pad"
          maxLength={6}
          value={code}
          onChangeText={setCode}
          onSubmitEditing={handleVerify}
          returnKeyType="done"
          textAlign="center"
        />

        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={handleVerify}
          disabled={loading}
          activeOpacity={0.8}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Verify</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.back}
          onPress={() => router.back()}
          activeOpacity={0.7}
        >
          <Text style={styles.backText}>← Change number</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff" },
  inner: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 32,
  },
  title: { fontSize: 28, fontWeight: "700", color: "#000", marginBottom: 8 },
  subtitle: {
    fontSize: 15,
    color: "#8E8E93",
    textAlign: "center",
    marginBottom: 32,
    lineHeight: 22,
  },
  phone: { color: "#075E54", fontWeight: "600" },
  devBanner: {
    backgroundColor: "#FFF3CD",
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 6,
    marginBottom: 16,
  },
  devText: { fontSize: 12, color: "#856404" },
  input: {
    width: "100%",
    height: 60,
    borderWidth: 1.5,
    borderColor: "#E5E5EA",
    borderRadius: 12,
    fontSize: 28,
    fontWeight: "700",
    letterSpacing: 8,
    color: "#000",
    marginBottom: 16,
  },
  button: {
    width: "100%",
    height: 52,
    backgroundColor: "#075E54",
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
  },
  buttonDisabled: { opacity: 0.6 },
  buttonText: { color: "#fff", fontSize: 17, fontWeight: "600" },
  back: { marginTop: 20 },
  backText: { color: "#075E54", fontSize: 15 },
});
