# Real-device push notification test checklist

Use this to verify the full push flow on a **physical Android device** (emulator/Expo Go is not sufficient).

---

## 1. Missing pieces

- **None.** The flow is implemented end-to-end:
  - Register on login → save token to backend → send push on new message → tap opens correct chat.
  - Logs and Android channel are in place; token invalidation (DeviceNotRegistered) is handled safely.

**Optional for real-device debugging:** On a dev build, client logs (`PUSH_*`) appear in Metro/console only when the app is in foreground or attached. For tap-from-killed-state, confirm navigation by eye (correct chat opens); no extra code change required.

---

## 2. Log reference (for readiness check)

| Log | Where | When |
|-----|--------|------|
| `PUSH_REGISTER_START` | Client: `pushNotifications.ts`; Server: `auth.go` (HandleSavePushToken) | Start of push registration / token save request |
| `PUSH_TOKEN_SAVE_SUCCESS` | Client: `pushNotifications.ts`; Server: `auth.go` | After token saved to backend |
| `PUSH_SKIPPED_EXPO_GO` / `PUSH_SKIPPED_EMULATOR` | Client: `pushNotifications.ts` | Skipped in Expo Go or emulator |
| `PUSH_PERMISSION_DENIED` | Client: `pushNotifications.ts` | User denied notification permission |
| `PUSH_REGISTER_ERROR` | Client: `pushNotifications.ts` | Registration or save failed |
| `PUSH sending to N token(s) conv=...` | Server: `chat.go` (sendPushForNewMessage) | Before calling Expo API |
| `PUSH_SENT tokens=N ok=X invalid=Y` | Server: `push/expo.go` | After Expo API response (or receipt check skipped) |
| `PUSH_ERROR ...` | Server: `auth.go`, `chat.go`, `push/expo.go` | Save/list/send/marshal/DeviceNotRegistered/etc. |
| `PUSH_TAP_NAVIGATE conversationId=...` | Client: `PushNotificationHandler.tsx` | User tapped notification; app navigates to chat |

**Android channel:** App creates channel `"default"` (name: "Messages", HIGH importance) in `pushNotifications.ts`; server sends `ChannelID: "default"` in `expo.go`. No change needed.

**Token invalidation:** On Expo `DeviceNotRegistered`, server logs `PUSH_ERROR DeviceNotRegistered`, calls `MarkTokenInvalid` for that token; `GetTokensForUser` only returns tokens with `invalid_at IS NULL`. Safe.

---

## 3. Real-device test steps

1. **Install** a dev or production build (EAS or local) on a **physical Android device**. Do not use Expo Go or emulator.
2. **Log in** with account A. Allow notification permission if prompted.
3. **Confirm token save:** In server logs, expect `PUSH_REGISTER_START user=<id> platform=android` and `PUSH_TOKEN_SAVE_SUCCESS user=<id>`. Optionally in Metro (if app in foreground): `PUSH_REGISTER_START`, `PUSH_TOKEN_SAVE_SUCCESS`.
4. **Send a message from another account:** From a second device/session, log in as account B and send a message to a conversation with A.
5. **Receive push:** On device A (with app in background or killed), a notification should appear (e.g. "Neuer Chat", "Sender: preview").
6. **Tap notification:** Tap the notification.
7. **Correct conversation opens:** The app opens to the chat with B (same conversation as the message). Optionally in Metro: `PUSH_TAP_NAVIGATE conversationId=<uuid>`.

**Pass criteria:** Token is saved after login; push is received when B sends to A; tapping the notification opens the correct chat. Any failure: check server logs for `PUSH_ERROR` and client logs for `PUSH_*`.

---

## 4. Quick checklist (copy-paste)

- [ ] Build installed on physical Android (not Expo Go, not emulator)
- [ ] Logged in as account A; notification permission granted
- [ ] Server logs: `PUSH_REGISTER_START` and `PUSH_TOKEN_SAVE_SUCCESS` for A
- [ ] Message sent from account B to a conversation with A
- [ ] Push received on device A
- [ ] Tapped push; correct conversation opened
