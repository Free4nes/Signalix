# Signalix Server

Zero-Knowledge Messaging Backend MVP in Go.

## Voraussetzungen

- Go 1.21 oder höher
- PostgreSQL 12 oder höher
- pgcrypto Extension (wird automatisch durch Migrationen aktiviert)

## Umgebungsvariablen

Die API benötigt folgende Variablen. Du kannst sie in PowerShell setzen oder eine `.env`-Datei im `server/`-Verzeichnis verwenden (siehe unten). **Gesetzte Umgebungsvariablen überschreiben Werte aus `.env`.**

| Variable       | Pflicht | Beschreibung |
|----------------|--------|--------------|
| `DATABASE_URL` | ja     | PostgreSQL-Connection-String |
| `JWT_SECRET`   | ja     | Geheimer Schlüssel (min. 32 Zeichen) |
| `OTP_SALT`     | ja     | Salt für OTP-Hashing |
| `PORT`         | nein   | Server-Port (Standard: 8080) |
| `OTP_DEV_MODE` | nein   | `true` = Dev-OTP aktiv (`123456`), `false` = echtes OTP via Twilio Verify |
| `TWILIO_ACCOUNT_SID` | bei `OTP_DEV_MODE=false` | Twilio Account SID |
| `TWILIO_AUTH_TOKEN` | bei `OTP_DEV_MODE=false` | Twilio Auth Token |
| `TWILIO_VERIFY_SERVICE_SID` | bei `OTP_DEV_MODE=false` | Twilio Verify Service SID |

### DATABASE_URL (wichtig)

- **Format:** `postgres://BENUTZER:PASSWORT@HOST:PORT/DBNAME?sslmode=disable`
- **Beispiel:**
  ```text
  postgres://postgres:Ricardo-Leticia100@127.0.0.1:5432/messenger?sslmode=disable
  ```
- **Sonderzeichen im Passwort:** Wenn das Passwort Zeichen wie `@`, `:`, `/`, `#`, `%` enthält, musst du sie URL-kodieren (percent-encoding), z. B. `@` → `%40`, `:` → `%3A`, `/` → `%2F`, `#` → `%23`, `%` → `%25`. Sonst wird der Connection-String ungültig.

### Optional: .env-Datei

Im Verzeichnis `server/` kannst du eine Datei `.env` anlegen. **Vorlage:** `server/.env.example` nach `server/.env` kopieren (Passwort bereits gesetzt). Beim Start lädt die API `.env` automatisch (`godotenv`); bereits gesetzte Umgebungsvariablen haben Vorrang. Ohne `.env` müssen alle Werte in der Shell gesetzt werden.

## Installation

1. Ins Projektverzeichnis wechseln und Dependencies laden:
   ```bash
   cd server
   go mod download
   ```
2. Die API **muss aus dem Verzeichnis `server/`** gestartet werden (dort liegt `go.mod`):
   ```bash
   cd server
   go run ./cmd/api
   ```

Migrationen laufen automatisch beim Start. Schlägt eine Migration fehl, startet der Server nicht.

### Dev Bootstrap (empfohlen)

Im Repo-Root ausführen:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1
```

Das Skript:
- legt `server/.env` aus `server/.env.example` an, falls sie fehlt
- prüft, ob `DATABASE_URL`, `JWT_SECRET`, `OTP_SALT` gesetzt sind
- startet den Server mit `go run ./cmd/api`
- zeigt einen Hinweis für das Web-Frontend (zweites Terminal: `cd web; npm run dev`)

### Schnellstart (manuell, Windows PowerShell)

Alle Befehle **einzeln** ausführen, keine Zeilenumbrüche in der Mitte eines Befehls. Erst Umgebungsvariablen setzen, dann Server starten:

```powershell
cd server
$env:DATABASE_URL = "postgres://postgres:Ricardo-Leticia100@127.0.0.1:5432/messenger?sslmode=disable"
$env:JWT_SECRET = "your-secret-key-at-least-32-characters-long"
$env:OTP_SALT = "your-otp-salt"
$env:OTP_DEV_MODE = "true"
go run ./cmd/api
```

In einem **zweiten** PowerShell-Fenster prüfst du, ob der Server läuft (Sanity-Check):

```powershell
curl.exe http://localhost:8080/health
```

Erwartete Antwort: `{"ok":true}` (oder ähnlich). Tritt „URL rejected: Port number…“ auf, wurde vermutlich ein Befehl mit Zeilenumbrüchen oder Backticks kopiert – jeden Befehl als **eine Zeile** ausführen.

## Migrationen

Migrationen werden automatisch beim Serverstart ausgeführt. Sie befinden sich in `internal/db/migrations/`.

### Manuelle Migration (optional)

Falls du Migrationen manuell ausführen möchtest:

```bash
goose -dir internal/db/migrations postgres "DATABASE_URL" up
```

## Projektstruktur

```
server/
├── cmd/
│   └── api/
│       └── main.go              # Entry Point
├── internal/
│   ├── config/
│   │   └── config.go            # Konfigurationsmanagement
│   ├── db/
│   │   ├── pg.go                # Datenbankverbindung
│   │   └── migrations/          # DB Migrationen
│   ├── http/
│   │   ├── router.go            # HTTP Router Setup
│   │   └── handlers/
│   │       └── health.go        # Health Check Handler
│   ├── model/
│   │   └── types.go             # Domain Models
│   └── repo/
│       ├── user_repo.go         # User Repository
│       └── device_repo.go      # Device Repository
├── go.mod
└── README.md
```

## API Endpoints

### GET /health

Health Check Endpoint.

**Response:**
```json
{
  "ok": true
}
```

### POST /auth/request_otp

Request an OTP for a phone number.
- In dev mode (`OTP_DEV_MODE=true`), the response includes `dev_otp: "123456"`.
- In production mode (`OTP_DEV_MODE=false`), the server triggers Twilio Verify SMS and does **not** return any OTP value.

**Request:**
```json
{
  "phone_number": "+491234567890"
}
```

**Bash / Linux / macOS (cURL):**
```bash
curl -s -X POST http://localhost:8080/auth/request_otp -H "Content-Type: application/json" -d '{"phone_number": "+491234567890"}'
```

**PowerShell (Windows)** – einzeilig ausführen; `curl.exe` verwenden (nicht das `curl`-Alias), damit die URL nicht als „Port number“ fehlinterpretiert wird:
```powershell
curl.exe -s -X POST http://localhost:8080/auth/request_otp -H "Content-Type: application/json" -d "{\"phone_number\": \"+491234567890\"}"
```

**PowerShell (Invoke-RestMethod, ohne cURL):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/auth/request_otp" -Method POST -ContentType "application/json" -Body '{"phone_number": "+491234567890"}'
```

**Response (200):**
```json
{
  "message": "otp_sent",
  "dev_otp": "123456"
}
```
(`dev_otp` only when `OTP_DEV_MODE=true`; never returned in SMS mode)

---

### POST /auth/verify_otp

Verify OTP and receive an access token.
- In dev mode, use `otp: "123456"`.
- In Twilio Verify mode, use the code received by SMS.
Max 5 attempts per session; min 2 seconds between attempts.

**Request:**
```json
{
  "phone_number": "string",
  "otp": "string"
}
```

**Bash / Linux / macOS (cURL):**
```bash
curl -s -X POST http://localhost:8080/auth/verify_otp -H "Content-Type: application/json" -d '{"phone_number": "+491234567890", "otp": "123456"}'
```

**PowerShell (Windows, einzeilig):**
```powershell
curl.exe -s -X POST http://localhost:8080/auth/verify_otp -H "Content-Type: application/json" -d "{\"phone_number\": \"+491234567890\", \"otp\": \"123456\"}"
```

**PowerShell (Invoke-RestMethod):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/auth/verify_otp" -Method POST -ContentType "application/json" -Body '{"phone_number": "+491234567890", "otp": "123456"}'
```

**Response (200):**
```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": "...",
    "phone_number": "+491234567890"
  }
}
```

---

### GET /me

Returns the authenticated user. Requires `Authorization: Bearer <access_token>`.

**Bash / Linux / macOS (cURL):**
```bash
TOKEN="eyJhbGciOiJIUzI1NiIs..."
curl -s http://localhost:8080/me -H "Authorization: Bearer $TOKEN"
```

**PowerShell (Windows, einzeilig)** – `$TOKEN` zuerst aus der Antwort von `verify_otp` (Feld `access_token`) setzen:
```powershell
$TOKEN = "PASTE_ACCESS_TOKEN_HERE"
curl.exe -s http://localhost:8080/me -H "Authorization: Bearer $TOKEN"
```

**PowerShell (Invoke-RestMethod):**
```powershell
$TOKEN = "PASTE_ACCESS_TOKEN_HERE"
Invoke-RestMethod -Uri "http://localhost:8080/me" -Headers @{ Authorization = "Bearer $TOKEN" }
```

**Response (200):**
```json
{
  "id": "...",
  "phone_number": "+491234567890"
}
```

### Debug: /me liefert „invalid or expired token“

**Relevante Stellen:**  
- Handler/Router: `internal/http/handlers/auth.go` (HandleMe), `internal/http/router.go` (GET /me mit AuthMiddleware).  
- JWT-Validierung: `internal/auth/jwt.go` (VerifyToken), `internal/middleware/auth.go` (AuthMiddleware ruft VerifyToken auf).  
- Login gibt ein **Access-Token** aus: `internal/auth/service.go` → `SignAccessToken`; Response-Feld `access_token` in `handlers/auth.go` (verifyOTPResponse).  
- Ein einziges `JWTService` mit `cfg.JWTSecret` wird in `cmd/api/main.go` erzeugt und für Auth und /me genutzt; es gibt **kein** neu generiertes Secret pro Start (JWT_SECRET kommt aus Env und ist erforderlich).

**Häufige Ursachen:**  
1. **Clock-Skew / Ablauf:** JWT v5 prüft `exp` ohne Leeway; wenn die Serveruhr vor der „Token-Zeit“ liegt oder der Token schon abgelaufen ist, schlägt die Validierung fehl.  
2. **Falscher Token:** Refresh-Token oder abgeschnittenes Token statt des kompletten `access_token` aus der Login-Antwort.

**Eingebauter Fix:**  
- In `internal/auth/jwt.go`: `VerifyToken` nutzt jetzt `jwt.WithLeeway(1*time.Minute)` und gibt Fehler unverändert zurück (für `errors.Is`).  
- In `internal/middleware/auth.go`: Bei Token-Fehlern wird der **Grund** geloggt (z. B. `expired`, `signature_invalid`, `missing_required_claim`, `malformed`), **ohne** den Token zu loggen.

**So testen (PowerShell, einzeilig):**

```powershell
# 1) OTP anfordern
$body1 = '{"phone_number":"+491234567890"}'
$r1 = Invoke-RestMethod -Uri "http://localhost:8080/auth/request_otp" -Method POST -Body $body1 -ContentType "application/json"

# 2) OTP verifizieren (OTP_DEV_MODE=true: OTP ist "123456")
$body2 = '{"phone_number":"+491234567890","otp":"123456"}'
$r2 = Invoke-RestMethod -Uri "http://localhost:8080/auth/verify_otp" -Method POST -Body $body2 -ContentType "application/json"

# 3) Access-Token aus Antwort verwenden
$TOKEN = $r2.access_token

# 4) GET /me mit diesem Token
Invoke-RestMethod -Uri "http://localhost:8080/me" -Headers @{ Authorization = "Bearer $TOKEN" }
```

**Erwartung:** Schritt 4 liefert 200 und ein Objekt mit `id`, `phone_number` (und ggf. `display_name`). Bei Fehler: Server-Log prüfen; dort steht z. B. `auth: token validation failed: expired` oder `signature_invalid`.

**cURL (Bash/PowerShell mit curl.exe):**

```powershell
# Nach Login $TOKEN setzen (z. B. aus verify_otp-Antwort)
curl.exe -s http://localhost:8080/me -H "Authorization: Bearer $TOKEN"
```

Erwarteter Output bei Erfolg: JSON mit `id`, `phone_number`. Bei 401: `{"error":"invalid or expired token"}` und im Server-Log der konkrete Grund.

## Troubleshooting

### „password authentication failed for user …“ (Postgres)

- **Ursache:** Falsches Passwort in `DATABASE_URL` oder Postgres akzeptiert keine Passwort-Auth.
- **Lösung:**
  1. Passwort in der URL prüfen: `postgres://USER:PASSWORT@HOST:PORT/DB?sslmode=disable`
  2. Sonderzeichen im Passwort URL-kodieren: `@` → `%40`, `:` → `%3A`, `#` → `%23`, `%` → `%25`
  3. `pg_hba.conf` prüfen – für `host ... all all md5` muss ein Passwort gesetzt sein
  4. Passwort mit `psql` testen: `psql -h 127.0.0.1 -U postgres -d messenger -W`

### „invalid or expired token“ (/me, PATCH /me, …)

- **Ursache:** JWT wird abgelehnt (abgelaufen, falsche Signatur, falscher Token).
- **Typische Fälle:**
  1. **JWT_SECRET wechselt:** Bei jedem Neustart neues Secret → alte Tokens ungültig. `JWT_SECRET` in `.env` stabil halten.
  2. **Falscher Token:** Für `Authorization: Bearer …` muss der **access_token** aus der Login-Response genutzt werden, nicht der **refresh_token**.
  3. **Token abgeschnitten:** Token vollständig kopieren (oft sehr lang).
- **Schnelltest (PowerShell):** Token direkt aus der API holen und für `/me` verwenden:

```powershell
# Login
$r = Invoke-RestMethod -Uri "http://localhost:8080/auth/verify_otp" -Method POST -ContentType "application/json" -Body '{"phone_number":"+491234567890","otp":"123456"}'
# access_token kopieren (nicht refresh_token)
$TOKEN = $r.access_token
Invoke-RestMethod -Uri "http://localhost:8080/me" -Headers @{ Authorization = "Bearer $TOKEN" }
```

- **Server-Log:** Bei Fehlern steht dort der Grund (z. B. `auth: token validation failed: expired` oder `signature_invalid`).

### CORS: PATCH /me + Authorization

CORS ist bereits so konfiguriert, dass `PATCH` und der `Authorization`-Header erlaubt sind:
- `AllowedMethods`: `GET, POST, PUT, PATCH, DELETE, OPTIONS`
- `AllowedHeaders`: `Authorization, Content-Type, X-API-Key`

Bei Problemen mit Preflight: Browser-DevTools → Network → OPTIONS-Request prüfen (sollte 200 mit CORS-Headern sein).

## Datenbankschema

Das MVP enthält folgende Tabellen:

- `users` - Benutzer mit Telefonnummer
- `otp_sessions` - OTP-Sessions (phone_number, otp_hash, expires_at, consumed_at, attempt_count, last_attempt_at, request_ip, user_agent); max. eine aktive Session pro Nummer
- `devices` - Geräte pro Benutzer mit Identity Keys
- `refresh_sessions` - Refresh-Token-Sessions mit Rotation und Reuse-Detection
- `projects` - Projekte eines Users (owner_user_id, name)
- `project_api_keys` - API Keys pro Projekt (key_hash SHA-256, last4, revoked_at); Plaintext wird nie gespeichert
- `conversations` - Chat-Unterhaltungen
- `conversation_members` - Mitglieder pro Unterhaltung (conversation_id, user_id)
- `messages` - Nachrichten (body_ciphertext für spätere E2E-Verschlüsselung, body_preview für Chat-Liste)

## Projects & API Keys

### POST /projects
Requires `Authorization: Bearer <access_token>`.

```json
{ "name": "My Project" }
```
Response `201`: `{ "id": "...", "name": "My Project", "created_at": "..." }`

### GET /projects
Returns all projects owned by the authenticated user.

### POST /projects/{projectId}/keys
Creates a new API key. The plaintext key (`api_key`) is returned **once** and never stored.

```json
{ "name": "Default Key" }
```
Response `201`:
```json
{
  "id": "...", "name": "Default Key", "last4": "xYzW",
  "created_at": "...",
  "api_key": "sk_live_<base64url>"
}
```

### GET /projects/{projectId}/keys
Lists all keys (including revoked). Does **not** return `api_key`.

### POST /projects/{projectId}/keys/{keyId}/revoke
Revokes a key. Response `204 No Content`.

### API Key Auth (middleware stub)
Routes can use `middleware.APIKeyMiddleware(projectSvc)` to authenticate via `X-API-Key: sk_live_...`.
The middleware hashes the key (SHA-256 + optional `API_KEY_PEPPER` env var), looks up the hash, and attaches `project_id` to the request context.

### Optional: API_KEY_PEPPER
Set `API_KEY_PEPPER` in your `.env` to add a pepper to the SHA-256 hash for extra security.

## Chat

WhatsApp-ähnlicher Chat (ohne Drittanbieter). Alle Endpoints erfordern `Authorization: Bearer <access_token>`. Membership wird für Lesen und Senden enforced (Nicht-Mitglieder erhalten 403).

### POST /conversations

Erstellt eine neue Unterhaltung mit den angegebenen Mitgliedern. `member_user_ids` enthält die User-IDs (inkl. des Callers, falls gewünscht).

**Request:**
```json
{ "member_user_ids": ["<uuid-user1>", "<uuid-user2>"] }
```

**Response `201`:**
```json
{ "conversation_id": "<uuid>" }
```

**PowerShell (cURL):**
```powershell
$TOKEN = "PASTE_ACCESS_TOKEN_HERE"
$USER_B = "PASTE_OTHER_USER_UUID_HERE"
curl.exe -s -X POST http://localhost:8080/conversations -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{`"member_user_ids`": [`"$USER_B`"]}"
```

**PowerShell (Invoke-RestMethod):**
```powershell
$TOKEN = "PASTE_ACCESS_TOKEN_HERE"
$USER_B = "PASTE_OTHER_USER_UUID_HERE"
Invoke-RestMethod -Uri "http://localhost:8080/conversations" -Method POST -Headers @{ Authorization = "Bearer $TOKEN" } -ContentType "application/json" -Body "{`"member_user_ids`": [`"$USER_B`"]}"
```

### GET /conversations

Listet alle Unterhaltungen des Users mit `last_message_preview` und `last_message_at`.

**Response `200`:**
```json
[
  {
    "id": "<uuid>",
    "members": ["<uuid1>", "<uuid2>"],
    "last_message_preview": "Hello!",
    "last_message_at": "2026-02-23T12:00:00Z"
  }
]
```

**PowerShell (cURL):**
```powershell
curl.exe -s http://localhost:8080/conversations -H "Authorization: Bearer $TOKEN"
```

### GET /conversations/:id/messages

Listet Nachrichten einer Unterhaltung, neueste zuerst. Query: `limit` (default 50, max 100), optional `before` (ISO8601 für Pagination).

**PowerShell (cURL):**
```powershell
$CONV_ID = "PASTE_CONVERSATION_UUID_HERE"
curl.exe -s "http://localhost:8080/conversations/$CONV_ID/messages?limit=50" -H "Authorization: Bearer $TOKEN"
```

### POST /conversations/:id/messages

Sendet eine Nachricht. `body_ciphertext_base64` ist Base64-kodierter Opaque-Bytes (für spätere E2E). `body_preview` optional für Chat-Liste.

**Request:**
```json
{
  "body_ciphertext_base64": "aGVsbG8gd29ybGQ=",
  "body_preview": "Hello world"
}
```

**Response `201`:**
```json
{
  "id": "<uuid>",
  "sender_user_id": "<uuid>",
  "sent_at": "2026-02-23T12:00:00Z",
  "body_ciphertext": "aGVsbG8gd29ybGQ=",
  "body_preview": "Hello world"
}
```

**PowerShell (cURL):**
```powershell
$BODY = '{"body_ciphertext_base64":"aGVsbG8gd29ybGQ=","body_preview":"Hello world"}'
curl.exe -s -X POST "http://localhost:8080/conversations/$CONV_ID/messages" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d $BODY
```

## Ingest

`POST /ingest` accepts arbitrary event payloads authenticated via an API key.
No JWT is required — pass the key in the `X-API-Key` header.

### Request

```http
POST /ingest HTTP/1.1
X-API-Key: sk_live_<your-key>
Content-Type: application/json

{
  "event": "user.signup",
  "timestamp": "2026-02-21T14:00:00Z",
  "data": { "plan": "free" }
}
```

`timestamp` is optional (defaults to server time). `data` is an arbitrary JSON object.

### Response `200`

```json
{
  "ok": true,
  "project_id": "<uuid>",
  "received_at": "2026-02-21T14:00:01Z",
  "event": "user.signup"
}
```

### Error responses

| Condition | Status | `error` field |
|---|---|---|
| `X-API-Key` header missing | 401 | `missing_api_key` |
| Key hash not found in DB | 401 | `invalid_api_key` |
| Key exists but is revoked | 401 | `revoked_api_key` |
| `event` field empty or body invalid | 400 | `invalid_payload` |

### cURL example

```bash
# 1. Get an API key from the dashboard (or via API)
KEY="sk_live_<your-key>"

# 2. Send an event
curl -s -X POST http://localhost:8080/ingest \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"event":"page.view","data":{"path":"/home"}}'
```

**PowerShell:**
```powershell
$KEY = "sk_live_<your-key>"
Invoke-RestMethod -Uri "http://localhost:8080/ingest" -Method POST `
  -Headers @{ "X-API-Key" = $KEY } `
  -ContentType "application/json" `
  -Body '{"event":"page.view","data":{"path":"/home"}}'
```

### Dev UI

Open `http://localhost:3000/ingest-test` to send test events interactively.
After creating an API key in the dashboard, click **"Test ingest →"** in the modal to open the test page with the key pre-filled.

## Entwicklung

### Dependencies hinzufügen

```bash
go get <package>
go mod tidy
```

### Tests

Run all tests from the `server/` directory (where `go.mod` is):

```bash
cd server
go test ./... -v
```

- **Unit tests** (e.g. `internal/auth`) run without a database.
- **Integration tests** (`internal/tests`) use a **real PostgreSQL** database. If `DATABASE_URL` is not set, they are **skipped** with a clear message so `go test ./...` still passes.

#### How to run integration and E2E tests

1. **Create a test database** (do not use production):

   ```bash
   # PostgreSQL: create dedicated test DB (required for TestAuthIntegration, TestAuthE2E)
   createdb messenger_test
   ```

2. **Set DATABASE_URL** to your test DB (`127.0.0.1` recommended instead of `localhost`):

   ```bash
   # Linux/macOS
   export DATABASE_URL="postgres://postgres:Ricardo-Leticia100@127.0.0.1:5432/messenger_test?sslmode=disable"
   ```

   ```powershell
   # Windows PowerShell (einzeilig)
   $env:DATABASE_URL = "postgres://postgres:Ricardo-Leticia100@127.0.0.1:5432/messenger_test?sslmode=disable"
   ```

   Use percent-encoding for special characters in password (`@`, `:`, `/`, `#`, `%`).

3. **Integration- und E2E-Tests ausführen:**

   ```bash
   cd server
   make test-integration
   ```

   Oder direkt mit `go test` (führt `TestAuthIntegration` und `TestAuthE2E` aus):

   ```bash
   go test ./internal/tests/... -v
   ```

   **Windows PowerShell** (aus dem Ordner `server`):
   ```powershell
   cd server
   go test ./internal/tests/... -v
   ```
   Ohne gesetztes `DATABASE_URL` werden die Integration/E2E-Tests übersprungen; `go test ./... -v` läuft trotzdem durch (nur Unit-Tests).

Integration and E2E tests use an in-process server (`httptest`), run migrations on the test DB, truncate auth tables between subtests, and verify: health, request_otp (with `dev_otp`), verify_otp (`access_token`), GET /me (Bearer token), invalid OTP (401), rate limit (429 on 4th request), and production mode (no `dev_otp`). Chat integration tests cover 1:1 and group conversations, membership checks (403 for non-members), and message send/list.

### Migrationen manuell ausführen

```bash
cd server
goose -dir internal/db/migrations postgres "$DATABASE_URL" up
```

### Integration-Tests (inkl. Chat) ausführen

```bash
cd server
export DATABASE_URL="postgres://user:pass@127.0.0.1:5432/messenger_test?sslmode=disable"
go test ./internal/tests/... -v -run "TestChatIntegration|TestAuthIntegration|TestProjectIntegration"
```

**PowerShell:**
```powershell
cd server
$env:DATABASE_URL = "postgres://user:pass@127.0.0.1:5432/messenger_test?sslmode=disable"
go test ./internal/tests/... -v -run "TestChatIntegration|TestAuthIntegration|TestProjectIntegration"
```

## Nächste Schritte

- Authentication/Authorization
- Key Exchange Endpoints
- Messaging Businesslogik
- Rate Limiting
- Logging & Monitoring
