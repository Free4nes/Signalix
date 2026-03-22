import { useEffect, useState } from "react";
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
import { useRouter } from "expo-router";
import { useAuth } from "../src/context/auth";
import { API_BASE } from "../src/lib/api";

export default function LoginScreen() {
  const router = useRouter();
  const { sendOtp } = useAuth();

  const [phone, setPhone] = useState("");
  const [loading, setLoading] = useState(false);
  // Temporary debug: remove after network issue is resolved
  const [connectivityStatus, setConnectivityStatus] = useState<string | null>(null);

  // Temporary debug: remove after network issue is resolved
  useEffect(() => {
    let cancelled = false;

    async function testConnectivity() {
      try {
        const url = "http://192.168.0.131:8080/health";
        const res = await fetch(url);
        if (!cancelled) {
          if (res.ok) {
            setConnectivityStatus("OK");
            console.log("CONNECTIVITY_TEST_OK");
          } else {
            const msg = `HTTP ${res.status}`;
            setConnectivityStatus(msg);
            console.log("CONNECTIVITY_TEST_ERROR=" + msg);
          }
        }
      } catch (e: unknown) {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : "Unknown error";
          setConnectivityStatus(msg);
          console.log("CONNECTIVITY_TEST_ERROR=" + msg);
        }
      }
    }

    testConnectivity();

    return () => {
      cancelled = true;
    };
  }, []);

  async function handleContinue() {
    const trimmed = phone.trim();
    if (!trimmed) {
      Alert.alert("Phone required", "Please enter your phone number.");
      return;
    }
    setLoading(true);
    try {
      const { devOtp } = await sendOtp(trimmed);
      // Navigate to OTP screen, pass phone + devOtp (only set in dev mode)
      router.push({ pathname: "/otp", params: { phone: trimmed, devOtp: devOtp ?? "" } });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      Alert.alert("Error", msg);
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
        {false && (
          <>
            <Text style={styles.debugApi}>API: {API_BASE}</Text>
            <Text style={styles.debugApi}>
              CONNECTIVITY: {connectivityStatus ?? "Testing..."}
            </Text>
          </>
        )}
        <Text style={styles.logo}>Signalix</Text>
        <Text style={styles.subtitle}>Enter your phone number to continue</Text>

        <TextInput
          style={styles.input}
          placeholder="+49 151 1234 5678"
          placeholderTextColor="#aaa"
          keyboardType="phone-pad"
          autoFocus
          value={phone}
          onChangeText={setPhone}
          onSubmitEditing={handleContinue}
          returnKeyType="done"
        />

        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={handleContinue}
          disabled={loading}
          activeOpacity={0.8}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Continue</Text>
          )}
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff" },
  debugApi: { fontSize: 11, color: "#999", marginBottom: 8 },
  inner: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 32,
    paddingBottom: Platform.OS === "android" ? 28 : 0,
  },
  logo: {
    fontSize: 36,
    fontWeight: "800",
    color: "#075E54",
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 15,
    color: "#8E8E93",
    textAlign: "center",
    marginBottom: 40,
  },
  input: {
    width: "100%",
    height: 52,
    borderWidth: 1.5,
    borderColor: "#E5E5EA",
    borderRadius: 12,
    paddingHorizontal: 16,
    fontSize: 17,
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
});
