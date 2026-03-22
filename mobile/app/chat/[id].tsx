import { useLocalSearchParams, useNavigation, useRouter, useFocusEffect } from "expo-router";
import { Image as ImageIcon, Info, Mic, MoreVertical, Pause, Play, Search, Send, Smile, Square, X } from "lucide-react-native";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Image,
  Keyboard,
  KeyboardAvoidingView,
  Modal,
  Platform,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { Audio } from "expo-av";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useAuth } from "../../src/context/auth";
import { useClearChat } from "../../src/context/clearChat";
import { useOpenSearchRequest } from "../../src/context/openSearchRequest";
import { useChatList } from "../../src/context/chatList";
import {
  API_BASE,
  ApiError,
  blockUser,
  deleteMessage,
  editMessage,
  getConversation,
  getUserOnlineStatus,
  listMessages,
  sendAudioMessage,
  sendImageMessage,
  sendMessage,
  uploadImage,
  type Message,
} from "../../src/lib/api";
import { Avatar } from "../../src/components/Avatar";
import {
  optimizeImageForUpload,
  getFileSize,
} from "../../src/lib/imageOptimization";
import { useWs } from "../../src/context/ws";
import type { WsEvent, WsMessage } from "../../src/lib/ws";

function wsMessageToMessage(w: WsMessage): Message {
  const audioUrl = typeof w.audio_url === "string" ? w.audio_url : undefined;
  const audioDurationMs = typeof w.audio_duration_ms === "number" ? w.audio_duration_ms : undefined;
  const audioMime = typeof w.audio_mime === "string" ? w.audio_mime : undefined;
  return {
    id: w.id,
    sender_user_id: w.sender_user_id,
    sender_display_name: w.sender_display_name,
    sent_at: w.sent_at,
    body_ciphertext: "",
    body_preview: w.body_preview,
    msg_type: (w.msg_type as "text" | "audio" | "image") || "text",
    audio_url: audioUrl,
    audio_duration_ms: audioDurationMs,
    audio_mime: audioMime,
    deleted_for_everyone: w.deleted_for_everyone ?? false,
    status: (w.status as "sent" | "delivered" | "read") || "sent",
    reply_to_id: w.reply_to_id ?? null,
  };
}

function appendUniqueMessage(prev: Message[], incoming: Message, source: string): Message[] {
  if (prev.some((m) => m.id === incoming.id)) {
    if (__DEV__) console.log("DUPLICATE_MESSAGE_SKIPPED", incoming.id, "source=" + source);
    return prev;
  }
  if (__DEV__) console.log("APPEND_SOURCE=" + source, "id=" + incoming.id, "MESSAGES_COUNT", prev.length + 1);
  return [...prev, incoming];
}

function decodeBody(msg: Message): string {
  if (msg.body_preview) return msg.body_preview;
  try {
    return atob(msg.body_ciphertext);
  } catch {
    return "[encrypted]";
  }
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  const h = d.getHours().toString().padStart(2, "0");
  const m = d.getMinutes().toString().padStart(2, "0");
  return `${h}:${m}`;
}

function formatLastSeen(iso: string): string {
  return "last seen " + formatTime(iso);
}

function formatAudioDuration(durationMs?: number): string {
  if (!durationMs || durationMs < 1000) return "0:00";
  const totalSec = Math.floor(durationMs / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = String(totalSec % 60).padStart(2, "0");
  return `${min}:${sec}`;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function HighlightedText({
  text,
  highlight,
  style,
  highlightStyle,
}: {
  text: string;
  highlight: string;
  style?: object;
  highlightStyle?: object;
}) {
  if (!highlight.trim()) return <Text style={style}>{text}</Text>;
  const re = new RegExp(`(${escapeRegex(highlight)})`, "gi");
  const parts = text.split(re);
  return (
    <Text style={style}>
      {parts.map((part, i) =>
        part.toLowerCase() === highlight.toLowerCase() ? (
          <Text key={i} style={[style, highlightStyle]}>{part}</Text>
        ) : (
          part
        )
      )}
    </Text>
  );
}

const REACTIONS = ["👍", "❤️", "😂", "😮", "😢"];
const EMOJI_PICKER_EMOJIS = ["😀", "😂", "😍", "👍", "❤️", "😢", "😮", "😡", "🎉", "🔥"];

function StatusIcon({
  status,
  isMine,
}: {
  status?: "sent" | "delivered" | "read";
  isMine: boolean;
}) {
  if (!isMine) return null;
  const s = status ?? "sent";
  if (s === "sent") {
    return <Text style={styles.statusIcon}>✓</Text>;
  }
  return (
    <Text
      style={[
        styles.statusIcon,
        s === "delivered" && styles.statusDelivered,
        s === "read" && styles.statusRead,
      ]}
    >
      ✓✓
    </Text>
  );
}

export default function ChatScreen() {
  const { id, title, otherUserId, otherAvatarUrl, isGroup } = useLocalSearchParams<{
    id: string;
    title?: string;
    otherUserId?: string;
    otherAvatarUrl?: string;
    isGroup?: string;
  }>();
  const isGroupChat = isGroup === "true";
  const navigation = useNavigation();
  const router = useRouter();
  const { accessToken, user } = useAuth();
  const { subscribe, send } = useWs();
  const { setActiveChatId, resetUnread } = useChatList();
  const { register: registerClear, unregister: unregisterClear } = useClearChat();
  const { consumeOpenSearchRequest } = useOpenSearchRequest();
  const insets = useSafeAreaInsets();

  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [text, setText] = useState("");
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const [editDraft, setEditDraft] = useState("");
  const [savingEdit, setSavingEdit] = useState(false);
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [otherUserTyping, setOtherUserTyping] = useState(false);
  const [onlineStatus, setOnlineStatus] = useState<{
    online: boolean;
    lastSeen?: string;
  } | null>(null);
  const [reactionPickerMsg, setReactionPickerMsg] = useState<Message | null>(null);
  const [fullscreenImageUri, setFullscreenImageUri] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [emojiPickerOpen, setEmojiPickerOpen] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [recordingStartedAt, setRecordingStartedAt] = useState<number | null>(null);
  const [playingMessageId, setPlayingMessageId] = useState<string | null>(null);
  const [selection, setSelection] = useState({ start: 0, end: 0 });
  const [displayTitle, setDisplayTitle] = useState(title ?? "Chat");
  const [highlightedMessageId, setHighlightedMessageId] = useState<string | null>(null);
  const [isKeyboardOpen, setIsKeyboardOpen] = useState(false);
  const [androidKeyboardOffset, setAndroidKeyboardOffset] = useState(0);

  const listRef = useRef<FlatList>(null);
  const recordingRef = useRef<Audio.Recording | null>(null);
  const soundRef = useRef<Audio.Sound | null>(null);
  const typingDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const typingIdleRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const typingSafetyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTypingSentRef = useRef<boolean | null>(null);
  const idRef = useRef(id);
  const userRef = useRef(user);

  idRef.current = id;
  userRef.current = user;

  useEffect(() => {
    if (title) setDisplayTitle(title);
  }, [title]);

  useFocusEffect(
    useCallback(() => {
      if (!accessToken || !id || !isGroupChat) return;
      getConversation(accessToken, id)
        .then((d) => setDisplayTitle(d.display_title ?? d.title ?? "Group"))
        .catch(() => {});
    }, [accessToken, id, isGroupChat])
  );

  useFocusEffect(
    useCallback(() => {
      if (id && consumeOpenSearchRequest(id)) setSearchOpen(true);
    }, [id, consumeOpenSearchRequest])
  );

  useEffect(() => {
    if (!id) return;
    registerClear(id, () => setMessages([]));
    return () => unregisterClear(id);
  }, [id, registerClear, unregisterClear]);

  const handleBlockUser = useCallback(async () => {
    if (!accessToken || !otherUserId) return;
    try {
      await blockUser(accessToken, otherUserId);
      Alert.alert("User blocked");
    } catch (e: unknown) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to block user");
    }
  }, [accessToken, otherUserId]);

  useLayoutEffect(() => {
    const showBlockOption = !isGroupChat && !!otherUserId;
    const onHeaderPress = isGroupChat
      ? () => router.push({ pathname: "/chat/group/[id]", params: { id } })
      : otherUserId
        ? () => router.push({ pathname: "/chat/info/[id]", params: { id } })
        : undefined;

    navigation.setOptions({
      headerTitleAlign: "left",
      headerTitle: () => (
        <TouchableOpacity
          style={styles.headerTitleContainer}
          onPress={onHeaderPress}
          disabled={!onHeaderPress}
          activeOpacity={onHeaderPress ? 0.7 : 1}
        >
          {!isGroupChat && (
            <Avatar
              avatarUrl={otherAvatarUrl}
              displayName={displayTitle}
              size={32}
              style={styles.headerAvatar}
            />
          )}
          <View style={styles.headerTitleTextWrap}>
            <Text style={styles.headerTitle} numberOfLines={1}>{displayTitle}</Text>
            {otherUserTyping ? (
              <Text style={styles.headerSubtitle}>schreibt...</Text>
            ) : onlineStatus ? (
              <Text style={styles.headerSubtitle}>
                {onlineStatus.online
                  ? "online"
                  : onlineStatus.lastSeen
                    ? formatLastSeen(onlineStatus.lastSeen)
                    : ""}
              </Text>
            ) : null}
          </View>
        </TouchableOpacity>
      ),
      headerRight: () => (
        <View style={styles.headerRightRow}>
          <TouchableOpacity
            onPress={() => setSearchOpen((o) => !o)}
            style={styles.headerRightBtn}
            hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
          >
            <Search color="#fff" size={22} />
          </TouchableOpacity>
          {isGroupChat ? (
            <TouchableOpacity
              onPress={() => router.push({ pathname: "/chat/group/[id]", params: { id } })}
              style={styles.headerRightBtn}
              hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
            >
              <Info color="#fff" size={22} />
            </TouchableOpacity>
          ) : showBlockOption ? (
            <TouchableOpacity
              onPress={() =>
                Alert.alert("Chat options", undefined, [
                  { text: "Block User", onPress: handleBlockUser },
                  { text: "Cancel", style: "cancel" },
                ])
              }
              style={styles.headerRightBtn}
              hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
            >
              <MoreVertical color="#fff" size={24} />
            </TouchableOpacity>
          ) : null}
        </View>
      ),
    });
  }, [displayTitle, otherUserTyping, onlineStatus, navigation, isGroupChat, otherUserId, handleBlockUser, id, router, otherAvatarUrl]);

  useEffect(() => {
    if (__DEV__) {
      console.log(otherUserTyping ? "TYPING_UI_VISIBLE" : "TYPING_UI_HIDDEN");
    }
  }, [otherUserTyping]);

  const emitTyping = useCallback(
    (isTyping: boolean) => {
      if (!id || !user?.id) return;
      if (lastTypingSentRef.current === isTyping) return;
      lastTypingSentRef.current = isTyping;
      send({
        type: "typing",
        conversation_id: id,
        user_id: user.id,
        is_typing: isTyping,
      });
      if (__DEV__) console.log("TYPING_EVENT_SENT", { is_typing: isTyping });
    },
    [id, user?.id, send]
  );

  const clearTyping = useCallback(() => {
    if (typingDebounceRef.current) {
      clearTimeout(typingDebounceRef.current);
      typingDebounceRef.current = null;
    }
    if (typingIdleRef.current) {
      clearTimeout(typingIdleRef.current);
      typingIdleRef.current = null;
    }
  }, []);

  const load = useCallback(async () => {
    if (!accessToken || !id) return;
    try {
      const data = await listMessages(accessToken, id);
      if (__DEV__ && data.length > 0) {
        console.log("MESSAGE_SHAPE", JSON.stringify(data[0], null, 2));
      }
      setMessages([...data].reverse());
    } catch (e: unknown) {
      Alert.alert("Error", e instanceof Error ? e.message : "Failed to load messages");
    } finally {
      setLoading(false);
    }
  }, [accessToken, id]);

  const messageMap = useMemo(
    () => new Map(messages.map((m) => [m.id, m])),
    [messages]
  );

  const filteredMessages = useMemo(() => {
    if (!searchQuery.trim()) return messages;
    const q = searchQuery.trim().toLowerCase();
    return messages.filter((m) => {
      const body = decodeBody(m);
      return (m.msg_type === "text" || !m.msg_type) && body.toLowerCase().includes(q);
    });
  }, [messages, searchQuery]);

  useEffect(() => {
    load();
  }, [load]);

  useFocusEffect(
    useCallback(() => () => setEmojiPickerOpen(false), [])
  );

  const insertEmoji = useCallback((emoji: string) => {
    setSelection((sel) => {
      const { start, end } = sel;
      setText((prev) => prev.slice(0, start) + emoji + prev.slice(end));
      return { start: start + emoji.length, end: start + emoji.length };
    });
  }, []);

  const handleScrollToReplyTarget = useCallback(
    (replyToId: string, list: Message[]) => {
      const index = list.findIndex((m) => m.id === replyToId);
      if (index === -1) {
        Alert.alert("Original message not found");
        return;
      }
      listRef.current?.scrollToIndex({
        index,
        viewPosition: 0.3,
        animated: true,
        viewOffset: 40,
      });
      setHighlightedMessageId(replyToId);
      setTimeout(() => setHighlightedMessageId(null), 1500);
    },
    []
  );

  useEffect(() => {
    if (!accessToken || !otherUserId || isGroupChat) return;
    getUserOnlineStatus(accessToken, otherUserId)
      .then((s) => {
        setOnlineStatus({ online: s.online, lastSeen: s.last_seen });
        if (__DEV__) console.log("ONLINE_STATUS_UPDATE", s);
      })
      .catch(() => {});
  }, [accessToken, otherUserId, isGroupChat]);

  useFocusEffect(
    useCallback(() => {
      if (id) {
        setActiveChatId(id);
        resetUnread(id);
        send({ type: "active_chat", conversation_id: id });
      }
      load();
      return () => {
        setActiveChatId(null);
        send({ type: "active_chat", conversation_id: "" });
      };
    }, [load, id, setActiveChatId, resetUnread, send])
  );

  useEffect(() => {
    if (!id) return;
    const unsub = subscribe((event: WsEvent) => {
      if (__DEV__) console.log("CHAT_SCREEN_WS_EVENT", event.type, event.conversation_id ?? "");
      if (event.type === "typing") {
        const currentChatId = String(idRef.current ?? "").toLowerCase();
        const incomingConversationId = String(event.conversation_id ?? "").toLowerCase();
        const currentUserId = String(userRef.current?.id ?? "").toLowerCase();
        const incomingUserId = String(event.user_id ?? "").toLowerCase();
        const isTyping = event.is_typing === true;

        if (__DEV__) {
          console.log("TYPING_EVENT_RECEIVED", {
            currentChatId,
            incomingConversationId,
            currentUserId,
            incomingUserId,
            is_typing: event.is_typing,
          });
        }

        const chatMatch =
          String(event.conversation_id ?? "").toLowerCase() === String(idRef.current ?? "").toLowerCase();
        if (!chatMatch) {
          if (__DEV__) console.log("TYPING_EVENT_IGNORED_WRONG_CHAT");
          return;
        }
        if (__DEV__) console.log("TYPING_EVENT_MATCHED_CHAT");

        const isOtherUser =
          String(event.user_id ?? "").toLowerCase() !== String(userRef.current?.id ?? "").toLowerCase();
        if (!isOtherUser) {
          if (__DEV__) console.log("TYPING_EVENT_IGNORED_SELF");
          return;
        }
        if (__DEV__) console.log("TYPING_EVENT_RECEIVED_MATCHED", { is_typing: isTyping });

        if (typingSafetyTimeoutRef.current) {
          clearTimeout(typingSafetyTimeoutRef.current);
          typingSafetyTimeoutRef.current = null;
        }
        if (isTyping) {
          typingSafetyTimeoutRef.current = setTimeout(() => {
            typingSafetyTimeoutRef.current = null;
            setOtherUserTyping(false);
            if (__DEV__) console.log("TYPING_UI_HIDDEN (safety timeout)");
          }, 5000);
        }
        setOtherUserTyping(isTyping);
        return;
      }
      if (event.type === "online_status" && event.user_id) {
        const targetId = String(event.user_id ?? "").toLowerCase();
        const otherId = String((otherUserId ?? "")).toLowerCase();
        if (targetId === otherId) {
          setOnlineStatus({
            online: event.online === true,
            lastSeen: event.last_seen,
          });
          if (__DEV__) console.log("ONLINE_STATUS_UPDATE", event);
        }
        return;
      }
      const currentChatId = String(idRef.current ?? "").toLowerCase();
      const incomingConversationId = String(event.conversation_id ?? "").toLowerCase();
      if (currentChatId !== incomingConversationId) return;
      if (__DEV__) console.log("ACTIVE_CHAT_WS_EVENT", event.type, event.conversation_id);
      if (event.type === "message.created" && event.message) {
        const msg = wsMessageToMessage(event.message);
        if (String(msg.sender_user_id ?? "").toLowerCase() !== String(userRef.current?.id ?? "").toLowerCase()) {
          setOtherUserTyping(false);
          if (__DEV__) console.log("TYPING_INDICATOR_HIDDEN (message received from that user)");
        }
        if (__DEV__) console.log("WS_MESSAGE_CREATED", msg.id, event.conversation_id);
        setMessages((prev) => appendUniqueMessage(prev, msg, "ws"));
        setTimeout(() => listRef.current?.scrollToEnd({ animated: true }), 50);
      } else if (event.type === "message.updated" && event.message) {
        const msg = wsMessageToMessage(event.message);
        setMessages((prev) =>
          prev.map((m) => (m.id === msg.id ? msg : m))
        );
        if (__DEV__) console.log("[WS] message updated", msg.id);
      } else if (event.type === "message.reaction") {
        const mid = event.message_id;
        const uid = String(event.user_id ?? "").toLowerCase();
        const myId = String(userRef.current?.id ?? "").toLowerCase();
        const r = event.reaction ?? "";
        if (!mid || !r) return;
        setMessages((prev) =>
          prev.map((m) => {
            if (m.id !== mid) return m;
            const counts = { ...(m.reactions ?? {}) };
            if (uid === myId) return m;
            counts[r] = (counts[r] ?? 0) + 1;
            return { ...m, reactions: counts };
          })
        );
      } else if (event.type === "message.deleted" && event.message_id) {
        const mid = event.message_id;
        const evMsg = event.message;
        setMessages((prev) => {
          if (evMsg?.deleted_for_everyone) {
            return prev.map((m) =>
              m.id === mid ? wsMessageToMessage(evMsg) : m
            );
          }
          return prev.filter((m) => m.id !== mid);
        });
        if (__DEV__) console.log("[WS] message deleted", mid);
      }
    });
    return () => unsub();
  }, [id, otherUserId, subscribe]);

  useEffect(() => {
    setOtherUserTyping(false);
    if (typingSafetyTimeoutRef.current) {
      clearTimeout(typingSafetyTimeoutRef.current);
      typingSafetyTimeoutRef.current = null;
    }
  }, [id]);

  useEffect(() => {
    setOnlineStatus(null);
  }, [id, otherUserId]);

  useEffect(() => {
    return () => {
      recordingRef.current?.stopAndUnloadAsync().catch(() => {});
      soundRef.current?.unloadAsync().catch(() => {});
    };
  }, []);

  useEffect(() => {
    return () => {
      clearTyping();
      emitTyping(false);
    };
  }, [id, clearTyping, emitTyping]);

  useEffect(() => {
    const showEvent = Platform.OS === "ios" ? "keyboardWillShow" : "keyboardDidShow";
    const hideEvent = Platform.OS === "ios" ? "keyboardWillHide" : "keyboardDidHide";

    const showSub = Keyboard.addListener(showEvent, (event) => {
      setIsKeyboardOpen(true);
      if (Platform.OS === "android") {
        const keyboardHeight = event.endCoordinates?.height ?? 0;
        setAndroidKeyboardOffset(keyboardHeight * 0.35);
      }
    });

    const hideSub = Keyboard.addListener(hideEvent, () => {
      setIsKeyboardOpen(false);
      if (Platform.OS === "android") {
        setAndroidKeyboardOffset(0);
      }
    });

    return () => {
      showSub.remove();
      hideSub.remove();
    };
  }, []);

  const handleTextChange = useCallback(
    (newText: string) => {
      setText(newText);
      clearTyping();
      if (newText.trim().length === 0) {
        if (__DEV__) console.log("TYPING_STOP");
        lastTypingSentRef.current = null;
        emitTyping(false);
        return;
      }
      if (__DEV__ && lastTypingSentRef.current !== true) console.log("TYPING_START");
      typingDebounceRef.current = setTimeout(() => {
        typingDebounceRef.current = null;
        emitTyping(true);
        typingIdleRef.current = setTimeout(() => {
          typingIdleRef.current = null;
          if (__DEV__) console.log("TYPING_STOP");
          lastTypingSentRef.current = null;
          emitTyping(false);
        }, 2000);
      }, 300);
    },
    [clearTyping, emitTyping]
  );

  useEffect(() => {
    if (messages.length > 0) {
      setTimeout(() => listRef.current?.scrollToEnd({ animated: false }), 100);
    }
  }, [messages.length]);

  async function processAndSendImage(uri: string, mimeType: string) {
    if (!accessToken || !id) return;
    const replyId = replyingTo?.id ?? null;

    const originalSize = await getFileSize(uri);
    if (__DEV__) console.log("IMAGE_PICKED", { uri: uri.slice(0, 50), sizeBytes: originalSize });

    setSending(true);
    try {
      const optimized = await optimizeImageForUpload(uri, mimeType);
      if (__DEV__) {
        console.log("IMAGE_OPTIMIZED", {
          sizeBytes: optimized.sizeBytes,
          width: optimized.width,
          height: optimized.height,
          beforeBytes: originalSize,
        });
      }

      if (__DEV__) console.log("IMAGE_UPLOAD_START", { sizeBytes: optimized.sizeBytes });
      const { url } = await uploadImage(accessToken, optimized.uri, optimized.mimeType);
      if (!url.startsWith("/")) {
        throw new Error("Invalid upload response");
      }
      if (__DEV__) console.log("IMAGE_UPLOAD_SUCCESS");
      const msg = await sendImageMessage(accessToken, id, url, replyId ?? undefined);
      setMessages((prev) => appendUniqueMessage(prev, msg, "rest"));
      setReplyingTo(null);
      setTimeout(() => listRef.current?.scrollToEnd({ animated: true }), 50);
    } catch (e: unknown) {
      if (__DEV__) console.log("IMAGE_UPLOAD_ERROR", e);
      if (e instanceof ApiError && e.status === 429) {
        Alert.alert("Slow down", "Too many messages. Please slow down.");
        return;
      }
      const msg = e instanceof ApiError && e.status === 403 && String(e.message).toLowerCase().includes("block")
        ? "You cannot send messages to this user."
        : (e instanceof Error ? e.message : "Failed to send image");
      Alert.alert("Send failed", msg);
    } finally {
      setSending(false);
    }
  }

  function handleImageButtonPress() {
    Alert.alert("Send image", undefined, [
      { text: "Take Photo", onPress: handleTakePhotoAndSend },
      { text: "Choose from Gallery", onPress: handlePickAndSendImage },
      { text: "Cancel", style: "cancel" },
    ]);
  }

  async function handlePickAndSendImage() {
    if (!accessToken || !id) return;
    const ImagePicker = await import("expo-image-picker");
    const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (status !== "granted") {
      Alert.alert("Permission required", "Gallery access is needed to send images.");
      return;
    }
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ["images"],
      quality: 1,
      allowsEditing: false,
    });
    if (result.canceled || !result.assets?.[0]) return;
    const asset = result.assets[0];
    await processAndSendImage(asset.uri, asset.mimeType ?? "image/jpeg");
  }

  async function handleTakePhotoAndSend() {
    if (!accessToken || !id) return;
    const ImagePicker = await import("expo-image-picker");
    const { status } = await ImagePicker.requestCameraPermissionsAsync();
    if (status !== "granted") {
      Alert.alert("Permission required", "Camera access is needed to take photos.");
      return;
    }
    const result = await ImagePicker.launchCameraAsync({
      mediaTypes: ["images"],
      quality: 1,
    });
    if (result.canceled || !result.assets?.[0]) return;
    const asset = result.assets[0];
    await processAndSendImage(asset.uri, asset.mimeType ?? "image/jpeg");
  }

  async function handleSend() {
    const trimmed = text.trim();
    if (!trimmed || !accessToken || !id) return;
    setEmojiPickerOpen(false);
    if (__DEV__) console.log("TYPING_STOP");
    lastTypingSentRef.current = null;
    emitTyping(false);
    const replyId = replyingTo?.id ?? null;
    if (__DEV__) {
      console.log("SEND_MESSAGE_PAYLOAD", { body: trimmed, reply_to_id: replyId });
    }
    setText("");
    setReplyingTo(null);
    setSending(true);
    try {
      const msg = await sendMessage(accessToken, id, trimmed, replyId ?? undefined);
      if (__DEV__) console.log("SEND_SUCCESS_APPEND", msg.id);
      setMessages((prev) => appendUniqueMessage(prev, msg, "rest"));
      setTimeout(() => listRef.current?.scrollToEnd({ animated: true }), 50);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 429) {
        Alert.alert("Slow down", "Too many messages. Please slow down.");
        setText(trimmed);
        return;
      }
      const msg = e instanceof ApiError && e.status === 403 && String(e.message).toLowerCase().includes("block")
        ? "You cannot send messages to this user."
        : (e instanceof Error ? e.message : "Unknown error");
      Alert.alert("Send failed", msg);
      setText(trimmed);
    } finally {
      setSending(false);
    }
  }

  async function handleRecordButtonPress() {
    if (!accessToken || !id || sending) return;
    if (isRecording) {
      const activeRecording = recordingRef.current;
      if (!activeRecording) return;
      setIsRecording(false);
      setSending(true);
      try {
        await activeRecording.stopAndUnloadAsync();
        const uri = activeRecording.getURI();
        const status = await activeRecording.getStatusAsync();
        const statusDuration = (status as { durationMillis?: number }).durationMillis;
        const durationMs =
          typeof statusDuration === "number" && statusDuration > 0
            ? statusDuration
            : recordingStartedAt
              ? Math.max(0, Date.now() - recordingStartedAt)
              : 0;
        if (!uri) throw new Error("Recording file not available");
        await sendAudioMessage(accessToken, id, uri, durationMs, "audio/m4a");
        setTimeout(() => listRef.current?.scrollToEnd({ animated: true }), 50);
        load();
      } catch (e: unknown) {
        Alert.alert("Send failed", e instanceof Error ? e.message : "Failed to send voice message");
      } finally {
        recordingRef.current = null;
        setRecordingStartedAt(null);
        setSending(false);
        await Audio.setAudioModeAsync({
          allowsRecordingIOS: false,
          playsInSilentModeIOS: true,
        }).catch(() => {});
      }
      return;
    }

    try {
      const permission = await Audio.requestPermissionsAsync();
      if (permission.status !== "granted") {
        Alert.alert("Permission required", "Microphone access is needed for voice messages.");
        return;
      }
      await Audio.setAudioModeAsync({
        allowsRecordingIOS: true,
        playsInSilentModeIOS: true,
      });
      const rec = new Audio.Recording();
      await rec.prepareToRecordAsync(Audio.RecordingOptionsPresets.HIGH_QUALITY);
      await rec.startAsync();
      recordingRef.current = rec;
      setRecordingStartedAt(Date.now());
      setIsRecording(true);
      setEmojiPickerOpen(false);
    } catch (e: unknown) {
      Alert.alert("Recording failed", e instanceof Error ? e.message : "Could not start recording");
      setIsRecording(false);
      recordingRef.current = null;
    }
  }

  async function handleAudioPress(message: Message) {
    const rawUrl = message.audio_url;
    if (!rawUrl) return;
    const uri = rawUrl.startsWith("http") ? rawUrl : `${API_BASE}${rawUrl}`;
    try {
      if (playingMessageId === message.id && soundRef.current) {
        const status = await soundRef.current.getStatusAsync();
        if (status.isLoaded && status.isPlaying) {
          await soundRef.current.pauseAsync();
          setPlayingMessageId(null);
          return;
        }
        await soundRef.current.playAsync();
        setPlayingMessageId(message.id);
        return;
      }

      if (soundRef.current) {
        await soundRef.current.unloadAsync();
        soundRef.current = null;
      }
      const { sound } = await Audio.Sound.createAsync(
        { uri },
        { shouldPlay: true },
        (status) => {
          if (!status.isLoaded || status.didJustFinish) {
            setPlayingMessageId((prev) => (prev === message.id ? null : prev));
          }
        }
      );
      soundRef.current = sound;
      setPlayingMessageId(message.id);
    } catch (e: unknown) {
      setPlayingMessageId(null);
      Alert.alert("Playback failed", e instanceof Error ? e.message : "Unable to play audio");
    }
  }

  function sendReaction(messageId: string, reaction: string) {
    if (!id) return;
    send({ type: "reaction", message_id: messageId, reaction });
    setMessages((prev) =>
      prev.map((m) => {
        if (m.id !== messageId) return m;
        const counts = { ...(m.reactions ?? {}) };
        const prevMine = m.my_reaction;
        if (prevMine && counts[prevMine] !== undefined) {
          counts[prevMine] = Math.max(0, counts[prevMine] - 1);
          if (counts[prevMine] === 0) delete counts[prevMine];
        }
        counts[reaction] = (counts[reaction] ?? 0) + 1;
        return { ...m, reactions: counts, my_reaction: reaction };
      })
    );
    setReactionPickerMsg(null);
  }

  function handleLongPressMessage(msg: Message) {
    setReactionPickerMsg(msg);
  }

  function openMoreActions() {
    const msg = reactionPickerMsg;
    setReactionPickerMsg(null);
    if (!msg) return;
    const isMine = msg.sender_user_id === user?.id;
    const isDeleted = msg.deleted_for_everyone === true;
    const canEdit = isMine && !isDeleted && msg.msg_type === "text";
    const buttons: Array<{ text: string; onPress?: () => void; style?: "cancel" }> = [];
    buttons.push({ text: "Reply", onPress: () => setReplyingTo(msg) });
    if (canEdit) {
      buttons.push({ text: "Edit", onPress: () => { setEditDraft(decodeBody(msg)); setEditingMessage(msg); } });
    }
    buttons.push({ text: "Delete", onPress: () => {
      Alert.alert("Delete", undefined, [
        { text: "Delete for me", onPress: () => performDelete(msg.id, "me") },
        { text: "Delete for everyone", onPress: () => performDelete(msg.id, "everyone") },
        { text: "Cancel", style: "cancel" },
      ]);
    } });
    buttons.push({ text: "Cancel", style: "cancel" });
    Alert.alert("Message", undefined, buttons);
  }

  async function handleSaveEdit() {
    if (!editingMessage || !accessToken) return;
    const trimmed = editDraft.trim();
    if (!trimmed) return;
    setSavingEdit(true);
    try {
      const updated = await editMessage(accessToken, editingMessage.id, trimmed);
      setMessages((prev) =>
        prev.map((m) => (m.id === editingMessage.id ? updated : m))
      );
      setEditingMessage(null);
      setEditDraft("");
    } catch (e: unknown) {
      Alert.alert(
        "Edit failed",
        e instanceof Error ? e.message : "Unknown error"
      );
    } finally {
      setSavingEdit(false);
    }
  }

  async function performDelete(messageId: string, mode: "everyone" | "me") {
    if (!accessToken || !id) return;
    try {
      const updated = await deleteMessage(accessToken, id, messageId, mode);
      if (mode === "everyone") {
        setMessages((prev) =>
          prev.map((m) => (m.id === messageId ? updated : m))
        );
      } else {
        setMessages((prev) => prev.filter((m) => m.id !== messageId));
      }
    } catch (e: unknown) {
      Alert.alert(
        "Delete failed",
        e instanceof Error ? e.message : "Unknown error"
      );
    }
  }

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#1F6FEB" />
      </View>
    );
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1 }}
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      keyboardVerticalOffset={0}
    >
      <View style={styles.container}>
        {searchOpen ? (
          <View style={styles.searchBar}>
            <TextInput
              style={styles.searchInput}
              placeholder="Search messages..."
              placeholderTextColor="#9CA3AF"
              value={searchQuery}
              onChangeText={setSearchQuery}
              autoFocus
              autoCapitalize="none"
              autoCorrect={false}
            />
            <TouchableOpacity
              onPress={() => {
                setSearchOpen(false);
                setSearchQuery("");
              }}
              style={styles.searchCloseBtn}
              hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
            >
              <X color="#6B7280" size={20} />
            </TouchableOpacity>
          </View>
        ) : null}

        <FlatList
          ref={listRef}
          data={filteredMessages}
          keyExtractor={(item) => item.id}
          keyboardShouldPersistTaps="handled"
          contentContainerStyle={styles.listContent}
          onScrollToIndexFailed={() => setHighlightedMessageId(null)}
          ListEmptyComponent={
            <View style={styles.center}>
              <Text style={styles.emptyText}>
                {searchOpen && searchQuery.trim() ? "No matching messages" : "No messages yet"}
              </Text>
              {!searchOpen || !searchQuery.trim() ? (
                <Text style={styles.emptyHint}>Say hello 👋</Text>
              ) : null}
            </View>
          }
          renderItem={({ item }) => {
            const message = item;
            const isMine = message.sender_user_id === user?.id;
            const isDeleted = message.deleted_for_everyone === true;
            const isImage = message.msg_type === "image";
            const isAudio = message.msg_type === "audio" && !!message.audio_url;
            const isPlayingThisAudio = playingMessageId === message.id;
            const imageUrl = isImage && message.body_preview ? `${API_BASE}${message.body_preview}` : null;
            const displayText = isDeleted ? "This message was deleted" : decodeBody(message);
            const isHighlighted = message.id === highlightedMessageId;

            return (
              <TouchableOpacity
                style={[
                  styles.bubbleRow,
                  isMine ? styles.bubbleRowRight : styles.bubbleRowLeft,
                  isHighlighted && styles.bubbleRowHighlighted,
                ]}
                onLongPress={() => handleLongPressMessage(message)}
                onPress={isImage && imageUrl && !isDeleted ? () => setFullscreenImageUri(imageUrl) : undefined}
                activeOpacity={1}
              >
                <View style={styles.bubbleWrapper}>
                  {isGroupChat && !isMine && (
                    <Text style={styles.senderName} numberOfLines={1}>
                      {message.sender_display_name?.trim() || message.sender_user_id?.slice(0, 8) || "?"}
                    </Text>
                  )}
                  <View style={[styles.bubble, isMine ? styles.bubbleMine : styles.bubbleTheirs, isImage && styles.bubbleImage]}>
                    {message.reply_to_id ? (
                      <TouchableOpacity
                        style={styles.replyContainer}
                        onPress={() => handleScrollToReplyTarget(message.reply_to_id!, filteredMessages)}
                        activeOpacity={0.8}
                      >
                        <Text style={styles.replyText} numberOfLines={1}>
                          {messageMap.get(message.reply_to_id)?.msg_type === "image"
                            ? "Image"
                            : messageMap.get(message.reply_to_id)?.body_preview || "Message"}
                        </Text>
                      </TouchableOpacity>
                    ) : null}
                    {isImage && imageUrl && !isDeleted ? (
                      <Image
                        source={{ uri: imageUrl }}
                        style={styles.imageBubble}
                        resizeMode="cover"
                      />
                    ) : isAudio && !isDeleted ? (
                      <View style={styles.audioContent}>
                        <TouchableOpacity
                          style={styles.audioPlayBtn}
                          onPress={() => handleAudioPress(message)}
                          activeOpacity={0.8}
                        >
                          {isPlayingThisAudio ? <Pause color="#1F6FEB" size={18} /> : <Play color="#1F6FEB" size={18} />}
                        </TouchableOpacity>
                        <View style={styles.audioTextWrap}>
                          <Text style={styles.audioLabel}>Voice message</Text>
                          <Text style={styles.audioDuration}>{formatAudioDuration(message.audio_duration_ms)}</Text>
                        </View>
                      </View>
                    ) : (
                      <HighlightedText
                        text={displayText}
                        highlight={searchQuery.trim()}
                        style={[
                          styles.messageText,
                          isMine && styles.bubbleTextMine,
                          isDeleted && styles.bubbleTextDeleted,
                        ]}
                        highlightStyle={styles.searchHighlight}
                      />
                    )}
                    <View style={styles.bubbleFooter}>
                      <Text style={[styles.bubbleTime, isMine && styles.bubbleTimeMine]}>
                        {formatTime(message.sent_at)}
                        {message.edited_at ? " (edited)" : ""}
                      </Text>
                      <StatusIcon status={message.status} isMine={isMine} />
                    </View>
                    {message.reactions && Object.keys(message.reactions).length > 0 ? (
                      <View style={styles.reactionsRow}>
                        {Object.entries(message.reactions).map(([emoji, count]) => (
                          <View
                            key={emoji}
                            style={[
                              styles.reactionChip,
                              message.my_reaction === emoji && styles.reactionChipMine,
                            ]}
                          >
                            <Text style={styles.reactionEmoji}>{emoji}</Text>
                            {count > 1 ? <Text style={styles.reactionCount}>{count}</Text> : null}
                          </View>
                        ))}
                      </View>
                    ) : null}
                  </View>
                </View>
              </TouchableOpacity>
            );
          }}
        />

        {reactionPickerMsg ? (
          <Modal visible transparent animationType="fade">
            <TouchableOpacity
              style={styles.reactionPickerOverlay}
              activeOpacity={1}
              onPress={() => setReactionPickerMsg(null)}
            >
              <View style={styles.reactionPickerBubble}>
                {REACTIONS.map((emoji) => (
                  <TouchableOpacity
                    key={emoji}
                    style={styles.reactionPickerEmoji}
                    onPress={() => sendReaction(reactionPickerMsg.id, emoji)}
                  >
                    <Text style={styles.reactionPickerEmojiText}>{emoji}</Text>
                  </TouchableOpacity>
                ))}
                <TouchableOpacity style={styles.reactionPickerMore} onPress={openMoreActions}>
                  <Text style={styles.reactionPickerMoreText}>More</Text>
                </TouchableOpacity>
              </View>
            </TouchableOpacity>
          </Modal>
        ) : null}

        <View style={styles.bottomComposerWrap}>
          {replyingTo ? (
            <View style={styles.replyBar}>
              <View style={styles.replyBarContent}>
                <Text style={styles.replyBarLabel}>Replying to:</Text>
                <Text style={styles.replyBarText} numberOfLines={1}>
                  {replyingTo.msg_type === "image" ? "Image" : decodeBody(replyingTo)}
                </Text>
              </View>
              <TouchableOpacity
                style={styles.replyBarCancel}
                onPress={() => setReplyingTo(null)}
                hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
              >
                <X color="#666" size={20} />
              </TouchableOpacity>
            </View>
          ) : null}

          {emojiPickerOpen ? (
            <View style={styles.emojiPickerRow}>
              {EMOJI_PICKER_EMOJIS.map((emoji) => (
                <TouchableOpacity
                  key={emoji}
                  style={styles.emojiPickerBtn}
                  onPress={() => insertEmoji(emoji)}
                  activeOpacity={0.7}
                >
                  <Text style={styles.emojiPickerEmoji}>{emoji}</Text>
                </TouchableOpacity>
              ))}
            </View>
          ) : null}

          {isRecording ? (
            <View style={styles.recordingRow}>
              <Text style={styles.recordingText}>Recording voice message...</Text>
            </View>
          ) : null}

          <View
            style={[
              styles.inputRow,
              {
                paddingBottom:
                  Platform.OS === "android" && isKeyboardOpen
                    ? 10 + androidKeyboardOffset
                    : 10 + (isKeyboardOpen ? 0 : insets.bottom),
              },
            ]}
          >
            <TouchableOpacity
              style={styles.imageBtn}
              onPress={() => setEmojiPickerOpen((o) => !o)}
              disabled={isRecording}
              activeOpacity={0.7}
            >
              <Smile color={emojiPickerOpen ? "#1F6FEB" : "#6B7280"} size={24} />
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.imageBtn}
              onPress={handleImageButtonPress}
              disabled={sending || isRecording}
              activeOpacity={0.7}
            >
              <ImageIcon color="#1F6FEB" size={24} />
            </TouchableOpacity>
            <TextInput
              style={styles.input}
              placeholder="Message..."
              placeholderTextColor="#9CA3AF"
              value={text}
              onChangeText={handleTextChange}
              selection={selection}
              onSelectionChange={(e) => {
                setSelection(e.nativeEvent.selection);
              }}
              multiline
              maxLength={2000}
              returnKeyType="default"
            />
            <TouchableOpacity
              style={[styles.audioRecordBtn, isRecording && styles.audioRecordBtnActive]}
              onPress={handleRecordButtonPress}
              disabled={sending}
              activeOpacity={0.8}
            >
              {isRecording ? <Square color="#fff" size={18} /> : <Mic color="#fff" size={18} />}
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.sendBtn, sending && styles.sendBtnDisabled]}
              onPress={handleSend}
              disabled={sending || isRecording || !text.trim()}
              activeOpacity={0.8}
            >
              {sending ? (
                <ActivityIndicator color="#fff" size="small" />
              ) : (
                <Send color="#fff" size={20} />
              )}
            </TouchableOpacity>
          </View>
        </View>

        {fullscreenImageUri ? (
          <Modal visible transparent animationType="fade">
            <TouchableOpacity
              style={styles.fullscreenImageOverlay}
              activeOpacity={1}
              onPress={() => setFullscreenImageUri(null)}
            >
              <Image
                source={{ uri: fullscreenImageUri }}
                style={styles.fullscreenImage}
                resizeMode="contain"
              />
            </TouchableOpacity>
          </Modal>
        ) : null}

        <Modal
          visible={!!editingMessage}
          transparent
          animationType="fade"
          onRequestClose={() => setEditingMessage(null)}
        >
          <TouchableOpacity
            style={styles.modalOverlay}
            activeOpacity={1}
            onPress={() => setEditingMessage(null)}
          >
            <TouchableOpacity
              style={styles.editModal}
              activeOpacity={1}
              onPress={(e) => e.stopPropagation()}
            >
              <Text style={styles.editModalTitle}>Edit message</Text>
              <TextInput
                style={styles.editInput}
                placeholder="Message"
                placeholderTextColor="#aaa"
                value={editDraft}
                onChangeText={setEditDraft}
                multiline
                maxLength={2000}
                autoFocus
              />
              <View style={styles.editModalButtons}>
                <TouchableOpacity
                  style={styles.editCancelBtn}
                  onPress={() => setEditingMessage(null)}
                >
                  <Text style={styles.editCancelText}>Cancel</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[styles.editSaveBtn, (savingEdit || !editDraft.trim()) && styles.editSaveBtnDisabled]}
                  onPress={handleSaveEdit}
                  disabled={savingEdit || !editDraft.trim()}
                >
                  {savingEdit ? (
                    <ActivityIndicator color="#fff" size="small" />
                  ) : (
                    <Text style={styles.editSaveText}>Save</Text>
                  )}
                </TouchableOpacity>
              </View>
            </TouchableOpacity>
          </TouchableOpacity>
        </Modal>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F6F8FC" },
  center: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32 },

  headerTitleContainer: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "flex-start",
    flex: 1,
    minWidth: 0,
  },
  headerAvatar: { marginRight: 8 },
  headerTitleTextWrap: {
    flex: 1,
    minWidth: 0,
    justifyContent: "center",
  },
  headerTitle: {
    color: "#fff",
    fontSize: 18,
    fontWeight: "700",
    lineHeight: 22,
  },
  headerSubtitle: {
    color: "rgba(255,255,255,0.9)",
    fontSize: 12,
    lineHeight: 15,
    marginTop: 1,
  },
  headerRightRow: { flexDirection: "row", alignItems: "center", marginRight: 2 },
  headerRightBtn: { paddingVertical: 8, paddingHorizontal: 6 },

  searchBar: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: "#FFFFFF",
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#E5E7EB",
  },
  searchInput: {
    flex: 1,
    fontSize: 16,
    color: "#111827",
    paddingVertical: 8,
    paddingHorizontal: 12,
    backgroundColor: "#F3F4F6",
    borderRadius: 10,
  },
  searchCloseBtn: { padding: 8, marginLeft: 4 },
  searchHighlight: { backgroundColor: "#FEF08A", fontWeight: "600" },

  emptyText: { fontSize: 17, fontWeight: "600", color: "#111827", marginBottom: 4 },
  emptyHint: { fontSize: 14, color: "#6B7280" },

  listContent: { paddingVertical: 12, paddingHorizontal: 12, flexGrow: 1 },

  bubbleRow: { marginVertical: 4, flexDirection: "row" },
  bubbleRowLeft: { justifyContent: "flex-start" },
  bubbleRowRight: { justifyContent: "flex-end" },
  bubbleRowHighlighted: {
    backgroundColor: "rgba(31,111,235,0.1)",
    borderRadius: 12,
  },
  bubbleWrapper: { maxWidth: "85%", minWidth: 120 },
  senderName: { fontSize: 12, color: "#1F6FEB", fontWeight: "600", marginBottom: 2 },

  bubble: {
    paddingVertical: 9,
    paddingHorizontal: 12,
    borderRadius: 18,
    maxWidth: "100%",
    alignSelf: "flex-start",
  },
  bubbleMine: {
    backgroundColor: "#DCF4FF",
  },
  bubbleTheirs: {
    backgroundColor: "#FFFFFF",
    elevation: 1,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 2,
  },
  bubbleImage: {
    padding: 4,
    overflow: "hidden",
  },
  imageBubble: {
    width: 200,
    maxWidth: "100%",
    height: 200,
    borderRadius: 14,
    backgroundColor: "#E5E7EB",
  },

  audioContent: {
    flexDirection: "row",
    alignItems: "center",
    minWidth: 180,
  },
  audioPlayBtn: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: "#E8F0FF",
    alignItems: "center",
    justifyContent: "center",
    marginRight: 8,
  },
  audioTextWrap: { flex: 1 },
  audioLabel: { fontSize: 13, color: "#111827", fontWeight: "600", lineHeight: 16 },
  audioDuration: { fontSize: 11, color: "#6B7280", marginTop: 1, lineHeight: 14 },

  fullscreenImageOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.9)",
    justifyContent: "center",
    alignItems: "center",
  },
  fullscreenImage: {
    width: "100%",
    height: "100%",
  },

  bubbleText: { fontSize: 15, color: "#111827", lineHeight: 20 },
  bubbleTextMine: { color: "#111827" },
  bubbleTextDeleted: { color: "#6B7280", fontStyle: "italic" },
  bubbleFooter: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "flex-end",
    marginTop: 4,
    gap: 4,
  },
  bubbleTime: { fontSize: 10, color: "#6B7280" },
  bubbleTimeMine: { color: "#1F6FEB" },
  statusIcon: { fontSize: 11, color: "#6B7280" },
  statusDelivered: { color: "#6B7280" },
  statusRead: { color: "#1F6FEB" },

  replyContainer: {
    backgroundColor: "#E5E7EB",
    borderLeftWidth: 4,
    borderLeftColor: "#1F6FEB",
    paddingVertical: 4,
    paddingHorizontal: 6,
    marginBottom: 6,
    borderRadius: 6,
  },
  replyText: {
    fontSize: 12,
    color: "#374151",
  },
  messageText: {
    fontSize: 15,
    color: "#111827",
    lineHeight: 21,
  },

  bottomComposerWrap: {
    backgroundColor: "#F6F8FC",
  },

  replyBar: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: "#FFFFFF",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: "#ccc",
  },
  replyBarContent: { flex: 1 },
  replyBarLabel: { fontSize: 12, color: "#666", marginBottom: 2 },
  replyBarText: { fontSize: 14, color: "#333" },
  replyBarCancel: { padding: 8 },

  emojiPickerRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: "#FFFFFF",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: "#E5E7EB",
    gap: 4,
  },
  emojiPickerBtn: {
    padding: 8,
  },
  emojiPickerEmoji: { fontSize: 22 },

  recordingRow: {
    paddingHorizontal: 14,
    paddingVertical: 6,
    backgroundColor: "#FFF5F5",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: "#FECACA",
  },
  recordingText: { color: "#B91C1C", fontSize: 13, fontWeight: "600" },

  inputRow: {
    flexDirection: "row",
    alignItems: "flex-end",
    paddingHorizontal: 12,
    paddingVertical: 10,
    backgroundColor: "#F6F8FC",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: "#E5E7EB",
  },
  imageBtn: {
    width: 44,
    height: 44,
    alignItems: "center",
    justifyContent: "center",
  },
  input: {
    flex: 1,
    height: 44,
    minHeight: 44,
    maxHeight: 120,
    backgroundColor: "#FFFFFF",
    borderRadius: 24,
    paddingHorizontal: 16,
    paddingVertical: 10,
    fontSize: 15,
    color: "#111827",
    marginHorizontal: 8,
  },
  audioRecordBtn: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
    marginRight: 8,
  },
  audioRecordBtnActive: { backgroundColor: "#EF4444" },
  sendBtn: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: "#1F6FEB",
    alignItems: "center",
    justifyContent: "center",
  },
  sendBtnDisabled: { backgroundColor: "#93C5FD", opacity: 0.7 },

  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.4)",
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
  },
  editModal: {
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 20,
    width: "100%",
    maxWidth: 340,
  },
  editModalTitle: { fontSize: 18, fontWeight: "700", color: "#000", marginBottom: 12 },
  editInput: {
    borderWidth: 1.5,
    borderColor: "#E5E5EA",
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
    color: "#000",
    minHeight: 80,
    maxHeight: 120,
    marginBottom: 16,
  },
  editModalButtons: { flexDirection: "row", justifyContent: "flex-end", gap: 12 },
  editCancelBtn: { paddingVertical: 8, paddingHorizontal: 16 },
  editCancelText: { fontSize: 16, color: "#8E8E93" },
  editSaveBtn: {
    backgroundColor: "#1F6FEB",
    paddingVertical: 8,
    paddingHorizontal: 20,
    borderRadius: 8,
    minWidth: 80,
    alignItems: "center",
  },
  editSaveBtnDisabled: { opacity: 0.6 },
  editSaveText: { fontSize: 16, fontWeight: "600", color: "#fff" },

  reactionsRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    marginTop: 4,
    gap: 4,
    alignSelf: "stretch",
  },
  reactionChip: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "rgba(0,0,0,0.06)",
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 10,
  },
  reactionChipMine: { backgroundColor: "rgba(31,111,235,0.2)" },
  reactionEmoji: { fontSize: 14 },
  reactionCount: { fontSize: 11, color: "#666", marginLeft: 2 },

  reactionPickerOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.3)",
    justifyContent: "center",
    alignItems: "center",
  },
  reactionPickerBubble: {
    flexDirection: "row",
    backgroundColor: "#fff",
    borderRadius: 24,
    paddingHorizontal: 8,
    paddingVertical: 6,
    alignItems: "center",
    gap: 4,
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 4,
  },
  reactionPickerEmoji: { padding: 8 },
  reactionPickerEmojiText: { fontSize: 24 },
  reactionPickerMore: { paddingHorizontal: 12, paddingVertical: 8 },
  reactionPickerMoreText: { fontSize: 14, color: "#1F6FEB", fontWeight: "600" },
});