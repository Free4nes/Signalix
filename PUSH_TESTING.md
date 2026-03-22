# Push Notifications – Testanleitung und Stand

## Geänderte Dateien

| Datei | Änderung |
|-------|----------|
| `mobile/src/services/pushNotifications.ts` | Logs bereinigt, Emulator-Skip, Android-Channel, PUSH_* Log-Präfixe |
| `mobile/src/components/PushNotificationHandler.tsx` | Android-Channel-Setup, Deep-Link-Navigation angepasst |
| `mobile/src/components/PushRegistration.tsx` | Redundante Logs entfernt |
| `mobile/src/lib/api.ts` | savePushToken: Verbose Logs entfernt |
| `server/internal/push/expo.go` | Response-Parsing, DeviceNotRegistered, channelId, OnInvalidToken |
| `server/internal/repo/push_token_repo.go` | MarkTokenInvalid, UPSERT, GetTokensForUser filtert invalid_at |
| `server/internal/http/handlers/auth.go` | PUSH_* Logs statt [push] |
| `server/internal/http/handlers/chat.go` | PUSH_* Logs, OnInvalidToken für Expo-Response |
| `server/internal/db/migrations/20260314120000_push_tokens_invalid.sql` | **NEU** Spalte `invalid_at` für ungültige Tokens |

---

## Was wurde angepasst / verbessert

### Frontend
- **Logs**: Einheitliche PUSH_* Logs (PUSH_REGISTER_START, PUSH_TOKEN_SAVE_SUCCESS, PUSH_SKIPPED_*)
- **Emulator**: Expliziter Skip mit PUSH_SKIPPED_EMULATOR (kein Push-Support im Emulator)
- **Expo Go**: Expliziter Skip mit PUSH_SKIPPED_EXPO_GO
- **Android Channel**: Standard-Channel "Messages" mit HIGH Importance
- **Deep Link**: Notification-Tap navigiert zu `/chat/{conversationId}` (Vordergrund, Hintergrund, beendet)

### Backend
- **Expo-Response**: Parsing der Push-Tickets, DeviceNotRegistered wird erkannt
- **Invalid Tokens**: `invalid_at` Spalte, MarkTokenInvalid() markiert ungültige Tokens
- **GetTokensForUser**: Nur Tokens mit `invalid_at IS NULL`
- **UPSERT**: Gleicher Token wird aktualisiert (platform, invalid_at zurückgesetzt)
- **Logs**: PUSH_REGISTER_START, PUSH_TOKEN_SAVE_SUCCESS, PUSH_SENT, PUSH_ERROR

### Robustheit
- Mehrere Geräte pro User (mehrere Tokens) werden unterstützt
- Keine doppelten Tokens (UNIQUE user_id, expo_push_token)
- Ungültige Tokens werden bei DeviceNotRegistered markiert
- Bei Re-Registrierung wird invalid_at zurückgesetzt

---

## Testanleitung

### 1. Emulator (Eingeschränkt)

**Wichtig:** Push Notifications funktionieren im Android-Emulator nicht (kein FCM/Google Play Services).

- App starten: `npx expo run:android` (Development Build)
- Erwartete Logs: `PUSH_SKIPPED_EMULATOR`
- Der übrige Push-Flow (Permissons, Handler, Deep Link) kann im Emulator nicht getestet werden.

### 2. Echtes Android-Handy (Entwicklung)

1. **Development Build**
   ```bash
   cd mobile
   npx expo run:android
   ```
   (Nicht Expo Go – dort kein Push-Support)

2. **Backend lokal**
   - Server mit PostgreSQL starten
   - Migrationen laufen beim Start (inkl. `invalid_at`)

3. **Handy konfigurieren**
   - `google-services.json` im `mobile/`-Verzeichnis vorhanden
   - App-Paket: `com.signalix` (muss mit Firebase-Projekt übereinstimmen)

4. **Tests**
   - Einloggen → Log: `PUSH_REGISTER_START`, `PUSH_TOKEN_SAVE_SUCCESS`
   - Zweites Gerät: Anderen User einloggen, Nachricht senden
   - Erwartung: Push auf dem ersten Gerät
   - Notification tippen → App öffnet den richtigen Chat

5. **Vordergrund**
   - App offen, Chat-Liste sichtbar
   - Neue Nachricht von anderem User
   - Erwartung: In-App-Banner (Banner + Sound)

6. **Hintergrund**
   - App in den Hintergrund schieben
   - Neue Nachricht
   - Erwartung: System-Notification, Tap öffnet Chat

7. **Beendet**
   - App komplett schließen
   - Neue Nachricht
   - Erwartung: System-Notification, Tap startet App und öffnet Chat

### 3. Play-Store-Release

1. **EAS Build**
   ```bash
   eas build --platform android --profile production
   ```

2. **Firebase / FCM**
   - FCM V1 Credentials im EAS Dashboard hinterlegen:
     - EAS Dashboard → Projekt → Credentials → Android → FCM V1 Service Account Key
   - `google-services.json` wird über `app.config.js` geladen (`googleServicesFile`)

3. **Vor dem Release prüfen**
   - [ ] FCM V1 Credentials im EAS Dashboard konfiguriert
   - [ ] `google-services.json` im Repo (oder über ENV/CI)
   - [ ] APK/AAB auf echtem Gerät: Push-Registration und Empfang
   - [ ] Notification-Tap öffnet den richtigen Chat
   - [ ] Mehrere Geräte für denselben User getestet

---

## App-Verhalten (definiert)

| Zustand | Verhalten |
|---------|-----------|
| **Vordergrund** | In-App-Banner (shouldShowAlert, shouldPlaySound), Tap öffnet Chat |
| **Hintergrund** | System-Notification, Tap öffnet App und Chat |
| **Beendet** | System-Notification, Tap startet App und öffnet Chat |

---

## Fertig vs. noch zu testen

### Fertig implementiert
- [x] Push-Registration beim Login
- [x] Permission-Handling
- [x] Expo-Push-Token an Backend senden
- [x] Token-UPSERT (Update bei erneutem Registrieren)
- [x] Mehrere Geräte pro User
- [x] DeviceNotRegistered: Tokens werden markiert
- [x] Deep-Link bei Notification-Tap
- [x] Android Notification Channel
- [x] Saubere PUSH_* Logs

### Für echtes Release noch prüfen
- [ ] FCM V1 Credentials im EAS Dashboard für Production-Build
- [ ] Push auf echtem Gerät mit Production-Build
- [ ] Notification-Tap bei kaltem App-Start
- [ ] Verhalten bei Abmeldung / Token-Invalidierung
- [ ] Do-not-disturb / Android-Standard-Einstellungen (Benutzer-Setup)
