# Signalix Dev Bootstrap - Run from repo root
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1
#
# Prerequisites: Go, PostgreSQL running, npm (for web)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

$ServerDir = Join-Path $RepoRoot "server"
$EnvExample = Join-Path $ServerDir ".env.example"
$EnvFile = Join-Path $ServerDir ".env"

# 1) Copy .env from example if missing
if (-not (Test-Path $EnvFile)) {
    if (-not (Test-Path $EnvExample)) {
        Write-Host "ERROR: server/.env.example not found. Create it with DATABASE_URL, JWT_SECRET, OTP_SALT." -ForegroundColor Red
        exit 1
    }
    Copy-Item $EnvExample $EnvFile
    Write-Host "Created server/.env from .env.example - please edit with your values." -ForegroundColor Yellow
    Write-Host "  Edit: $EnvFile" -ForegroundColor Gray
    Write-Host ""
}

# 2) Load .env into current process
function Load-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    foreach ($line in Get-Content $Path -ErrorAction SilentlyContinue) {
        $line = $line.Trim()
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$' -and $line -notmatch '^\s*#') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            if ($val -match '^["''](.*)["'']$') { $val = $matches[1] }
            Set-Item -Path "Env:$key" -Value $val -ErrorAction SilentlyContinue
        }
    }
}
Load-DotEnv $EnvFile

# 3) Validate required vars
$missing = @()
if (-not $env:DATABASE_URL) { $missing += "DATABASE_URL" }
if (-not $env:JWT_SECRET)  { $missing += "JWT_SECRET" }
if (-not $env:OTP_SALT)    { $missing += "OTP_SALT" }
if ($missing.Count -gt 0) {
    Write-Host "ERROR: Required env vars not set. Edit server/.env and set:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "Example: DATABASE_URL=postgres://user:pass@127.0.0.1:5432/messenger?sslmode=disable" -ForegroundColor Gray
    Write-Host "         JWT_SECRET=your-secret-at-least-32-chars" -ForegroundColor Gray
    Write-Host "         OTP_SALT=your-otp-salt" -ForegroundColor Gray
    exit 1
}

Write-Host "=== Signalix Server (dev) ===" -ForegroundColor Cyan
Write-Host "Starting API on http://localhost:8080" -ForegroundColor Gray
Write-Host ""
Write-Host "Web (optional): In a second terminal run:" -ForegroundColor Yellow
Write-Host "  cd web; npm run dev" -ForegroundColor White
Write-Host "  -> http://localhost:3000" -ForegroundColor Gray
Write-Host ""

# 4) Start server
Push-Location $ServerDir
try {
    go run ./cmd/api
} finally {
    Pop-Location
}
