# Signalix Integration Test Runner - clean cold-restart
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
# Run from repo root OR from anywhere (script resolves paths itself)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

# 1) Stop all containers and wipe volumes
Write-Host "Stopping containers and removing volumes..." -ForegroundColor Cyan
docker compose down -v

# 2) Start only the DB
Write-Host "Starting DB container..." -ForegroundColor Cyan
docker compose up -d db

# 3) Wait until healthcheck reports healthy
Write-Host "Waiting for DB to become healthy..." -ForegroundColor Cyan
$containerId = docker compose ps -q db
while ((docker inspect -f "{{.State.Health.Status}}" $containerId) -ne "healthy") {
    Start-Sleep -Seconds 1
}
Write-Host "DB is healthy." -ForegroundColor Green

# 4) Confirm container state
docker compose ps db

# 5) Move into Go module directory
Set-Location (Join-Path $RepoRoot "server")

# 6) Set DATABASE_URL for local tests
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:55432/messenger?sslmode=disable"
Write-Host "DATABASE_URL = $env:DATABASE_URL" -ForegroundColor Gray

# 7) Run tests (no cache)
Write-Host "Running tests..." -ForegroundColor Cyan
go test ./... -count=1
