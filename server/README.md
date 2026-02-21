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
| `OTP_DEV_MODE` | nein   | `true` = OTP immer "123456" für Entwicklung |

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

### Schnellstart (Windows PowerShell)

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

Request an OTP for a phone number. In dev mode (`OTP_DEV_MODE=true`) the response includes `dev_otp: "123456"`.

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
(`dev_otp` only when `OTP_DEV_MODE=true`)

---

### POST /auth/verify_otp

Verify OTP and receive an access token. In dev mode, use `otp: "123456"`. Max 5 attempts per session; min 2 seconds between attempts.

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

## Datenbankschema

Das MVP enthält folgende Tabellen:

- `users` - Benutzer mit Telefonnummer
- `otp_sessions` - OTP-Sessions (phone_number, otp_hash, expires_at, consumed_at, attempt_count, last_attempt_at, request_ip, user_agent); max. eine aktive Session pro Nummer
- `devices` - Geräte pro Benutzer mit Identity Keys
- `prekeys` - Signed PreKeys pro Gerät
- `one_time_prekeys` - One-Time PreKeys pro Gerät
- `messages_queue` - Nachrichtenwarteschlange

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

Integration and E2E tests use an in-process server (`httptest`), run migrations on the test DB, truncate auth tables between subtests, and verify: health, request_otp (with `dev_otp`), verify_otp (`access_token`), GET /me (Bearer token), invalid OTP (401), rate limit (429 on 4th request), and production mode (no `dev_otp`).

## Nächste Schritte

- OTP/Twilio Integration
- Authentication/Authorization
- Key Exchange Endpoints
- Messaging Businesslogik
- Rate Limiting
- Logging & Monitoring
