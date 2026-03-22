# Signalix – Local Development Runbook (Windows PowerShell)

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Docker Desktop | 4.x (running) |
| Node.js | 18 LTS or later |
| npm | 9 or later (bundled with Node) |
| Go | 1.22 or later (only needed to run tests) |

---

## 1. Start the backend (DB + API)

Run from the **repo root** (`C:\Users\Ricardo\Signalix`):

```powershell
# Start Postgres and the API server in the background
docker compose up -d db api

# Wait until both containers are healthy/running
docker compose ps
```

### Health check

```powershell
# Expect: StatusCode 200, Content {"status":"ok"}
Invoke-WebRequest -Uri http://127.0.0.1:8080/health -UseBasicParsing | Select-Object StatusCode, Content
```

---

## 2. Start the web frontend

Run from the **`web/` directory**:

```powershell
Set-Location .\web

# First time (or after pulling new commits): install exact locked deps
npm ci

# Start the Next.js dev server
npm run dev
```

The dev server starts on **http://localhost:3000**.

### Verify in browser

Open: http://localhost:3000/dashboard

---

## 3. Full cold-start sequence (copy-paste)

```powershell
# From repo root
Set-Location C:\Users\Ricardo\Signalix

# 1. Tear down any stale containers and volumes
docker compose down -v

# 2. Start DB and API fresh
docker compose up -d db api

# 3. Wait for DB to be healthy
while ((docker inspect -f "{{.State.Health.Status}}" (docker compose ps -q db)) -ne "healthy") {
    Start-Sleep -Seconds 1
}
Write-Host "DB is healthy"

# 4. Health-check the API (retry up to 15s)
$deadline = (Get-Date).AddSeconds(15)
do {
    try {
        $r = Invoke-WebRequest -Uri http://127.0.0.1:8080/health -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) { Write-Host "API healthy"; break }
    } catch {}
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)

# 5. Start the web frontend
Set-Location .\web
npm ci
npm run dev
```

---

## 4. Running integration tests

```powershell
Set-Location C:\Users\Ricardo\Signalix\server
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:55432/messenger?sslmode=disable"
go test ./internal/tests -count=1
```

> **Note:** Docker maps Postgres to host port **55432** (not 5432) because port 5432 is occupied by a local Windows service. The `DATABASE_URL` above reflects this.

---

## 5. Stopping everything

```powershell
Set-Location C:\Users\Ricardo\Signalix
docker compose down        # stop containers, keep volumes
# docker compose down -v  # stop containers AND delete all data
```

---

## Port reference

| Service | Host address |
|---------|-------------|
| Postgres | `127.0.0.1:55432` |
| API | `http://127.0.0.1:8080` |
| Web (dev) | `http://localhost:3000` |
