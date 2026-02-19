#Requires -Version 5.1
<#
.SYNOPSIS
  E2E script: env, tests, server smoke (health/OTP/me), rate limit 429, production mode (no dev_otp).
.DESCRIPTION
  Run from repo root or server/. Uses 127.0.0.1 for DB. Prompts for Postgres password if
  DATABASE_URL not set. Never logs password. Invoke-RestMethod only. CI runs Go tests only (no script).
#>

$ErrorActionPreference = "Stop"

# --- Constants ---
$HealthTimeoutSec = 30
$HealthPollIntervalSec = 1
$ServerStartDelaySec = 2
$PortRangeStart = 8080
$PortRangeEnd = 8999
$TestPhoneNumber = "+491234567890"
$DevOtpValue = "123456"
$RateLimitRequestsTotal = 4
$HttpTooManyRequests = 429

# --- Resolve server directory (where go.mod lives) ---
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Get-Item $scriptRoot).Parent.FullName
$serverDir = Join-Path $repoRoot "server"
if (-not (Test-Path (Join-Path $serverDir "go.mod"))) {
    $serverDir = $repoRoot
    if (-not (Test-Path (Join-Path $serverDir "go.mod"))) {
        Write-Error "go.mod not found in $repoRoot or $repoRoot\server. Run from repo root or server."
    }
}
Set-Location $serverDir
Write-Host "[E2E] Working directory: $serverDir"

# --- Environment: DATABASE_URL (no placeholders) ---
if (-not $env:DATABASE_URL -or $env:DATABASE_URL -match "<.*>") {
    Write-Host "[E2E] DATABASE_URL not set or contains placeholder. Prompting for Postgres password (user=postgres, host=127.0.0.1, db=messenger)."
    $secure = Read-Host -AsSecureString -Prompt "Postgres password"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $encoded = [uri]::EscapeDataString($plain)
        $env:DATABASE_URL = "postgres://postgres:$encoded@127.0.0.1:5432/messenger?sslmode=disable"
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
    Write-Host "[E2E] DATABASE_URL set (password masked)."
} else {
    Write-Host "[E2E] Using existing DATABASE_URL (masked)."
}

# --- Other env defaults ---
if (-not $env:JWT_SECRET) { $env:JWT_SECRET = "e2e-jwt-secret-at-least-32-characters-long" }
if (-not $env:OTP_SALT)   { $env:OTP_SALT   = "e2e-otp-salt" }
if (-not $env:OTP_DEV_MODE) { $env:OTP_DEV_MODE = "true" }

# --- Find free port ---
function Find-FreePort {
    param([int]$StartPort = $PortRangeStart, [int]$EndPort = $PortRangeEnd)
    for ($p = $StartPort; $p -le $EndPort; $p++) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $p)
            $tcp.Close()
        } catch {
            return $p
        }
    }
    return $null
}

function Wait-ServerReady {
    param([string]$BaseUrl)
    $deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -TimeoutSec 3
            if ($r.ok -eq $true) { return $true }
        } catch {
            Start-Sleep -Seconds $HealthPollIntervalSec
        }
    }
    return $false
}

function Stop-ServerIfRunning {
    param([System.Diagnostics.Process]$Proc)
    if ($Proc -and -not $Proc.HasExited) {
        Write-Host "[E2E] Stopping server (PID $($Proc.Id)) ..."
        $Proc.Kill()
        $Proc.WaitForExit(5000)
    }
}

function Start-ServerAtPort {
    param([string]$WorkDir, [int]$Port)
    $env:PORT = $Port
    $proc = Start-Process -FilePath "go" -ArgumentList "run", "./cmd/api" -WorkingDirectory $WorkDir -NoNewWindow -PassThru
    Start-Sleep -Seconds $ServerStartDelaySec
    return $proc
}

# --- Find port and run Go tests ---
$freePort = Find-FreePort
if (-not $freePort) { Write-Error "No free port in $PortRangeStart..$PortRangeEnd." }
$env:PORT = $freePort
Write-Host "[E2E] Using PORT=$freePort"

Write-Host "[E2E] Running unit tests: go test ./... -v"
$unitResult = 0
try {
    & go test ./... -v 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { $unitResult = $LASTEXITCODE }
} catch {
    Write-Host "[E2E] Unit tests failed: $_"
    $unitResult = 1
}

Write-Host "[E2E] Running integration tests: go test ./internal/tests/... -v -run TestAuthIntegration"
$intResult = 0
try {
    & go test ./internal/tests/... -v -run TestAuthIntegration 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { $intResult = $LASTEXITCODE }
} catch {
    Write-Host "[E2E] Integration tests failed (check DATABASE_URL and DB): $_"
    $intResult = 1
}

if ($unitResult -ne 0 -or $intResult -ne 0) {
    Write-Host "[E2E] FAILED: Tests failed (unit=$unitResult integration=$intResult). Aborting E2E."
    exit 1
}

$baseUrl = "http://127.0.0.1:$freePort"
$bodyRequestOtp = "{`"phone_number`":`"$TestPhoneNumber`"}"
$bodyVerifyOtp = "{`"phone_number`":`"$TestPhoneNumber`",`"otp`":`"$DevOtpValue`"}"

# --- Start server (first run: smoke + rate limit) ---
Write-Host "[E2E] Starting server on port $freePort ..."
$proc = Start-ServerAtPort -WorkDir $serverDir -Port $freePort
try {
    if (-not (Wait-ServerReady -BaseUrl $baseUrl)) {
        Write-Host "[E2E] FAILED: Server did not become ready within ${HealthTimeoutSec}s (check DB/migrations)."
        exit 1
    }
    Write-Host "[E2E] Server ready."

    # --- Smoke: health ---
    $health = Invoke-RestMethod -Uri "$baseUrl/health" -Method Get
    if ($health.ok -ne $true) {
        Write-Host "[E2E] FAILED: GET /health expected ok:true, got: $($health | ConvertTo-Json)"
        exit 1
    }
    Write-Host "[E2E] GET /health OK"

    # --- Smoke: request_otp ---
    try {
        $requestOtp = Invoke-RestMethod -Uri "$baseUrl/auth/request_otp" -Method Post -Body $bodyRequestOtp -ContentType "application/json"
    } catch {
        $msg = if ($_.Exception.Response) { "status=$($_.Exception.Response.StatusCode.value__) body=$($_.ErrorDetails.Message)" } else { $_.Exception.Message }
        Write-Host "[E2E] FAILED: POST /auth/request_otp failed (rate limit? invalid body?): $msg"
        exit 1
    }
    if ($requestOtp.message -ne "otp_sent") {
        Write-Host "[E2E] FAILED: POST /auth/request_otp expected message=otp_sent, got: $($requestOtp | ConvertTo-Json)"
        exit 1
    }
    if ($env:OTP_DEV_MODE -eq "true" -and $requestOtp.dev_otp -ne $DevOtpValue) {
        Write-Host "[E2E] FAILED: POST /auth/request_otp expected dev_otp=$DevOtpValue (OTP_DEV_MODE), got: $($requestOtp.dev_otp)"
        exit 1
    }
    Write-Host "[E2E] POST /auth/request_otp OK (dev_otp present in dev mode)"

    # --- Smoke: verify_otp ---
    try {
        $verifyOtp = Invoke-RestMethod -Uri "$baseUrl/auth/verify_otp" -Method Post -Body $bodyVerifyOtp -ContentType "application/json"
    } catch {
        $msg = if ($_.Exception.Response) { "status=$($_.Exception.Response.StatusCode.value__) body=$($_.ErrorDetails.Message)" } else { $_.Exception.Message }
        Write-Host "[E2E] FAILED: POST /auth/verify_otp failed (invalid OTP?): $msg"
        exit 1
    }
    if (-not $verifyOtp.access_token) {
        Write-Host "[E2E] FAILED: POST /auth/verify_otp expected access_token, got: $($verifyOtp | ConvertTo-Json)"
        exit 1
    }
    Write-Host "[E2E] POST /auth/verify_otp OK (access_token received)"

    # --- Smoke: GET /me ---
    $headers = @{ Authorization = "Bearer $($verifyOtp.access_token)" }
    $me = Invoke-RestMethod -Uri "$baseUrl/me" -Method Get -Headers $headers
    if (-not $me.phone_number -or $me.phone_number -ne $TestPhoneNumber) {
        Write-Host "[E2E] FAILED: GET /me expected phone_number=$TestPhoneNumber, got: $($me | ConvertTo-Json)"
        exit 1
    }
    if (-not $me.id) {
        Write-Host "[E2E] FAILED: GET /me expected id, got: $($me | ConvertTo-Json)"
        exit 1
    }
    Write-Host "[E2E] GET /me OK (id=$($me.id), phone_number=$($me.phone_number))"

    # --- Rate limit: 1 request_otp already done in smoke; 3 more => 4th must be 429 ---
    $fourthWas429 = $false
    for ($i = 1; $i -le ($RateLimitRequestsTotal - 1); $i++) {
        try {
            $null = Invoke-RestMethod -Uri "$baseUrl/auth/request_otp" -Method Post -Body $bodyRequestOtp -ContentType "application/json"
            if ($i -eq ($RateLimitRequestsTotal - 1)) {
                Write-Host "[E2E] FAILED: 4th request_otp expected HTTP $HttpTooManyRequests (rate limit), got 200"
                exit 1
            }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($i -lt ($RateLimitRequestsTotal - 1)) {
                Write-Host "[E2E] FAILED: request_otp #$($i+1) got HTTP $code (expected 200 before 4th)"
                exit 1
            }
            if ($code -ne $HttpTooManyRequests) {
                Write-Host "[E2E] FAILED: 4th request_otp expected HTTP $HttpTooManyRequests, got $code"
                exit 1
            }
            $fourthWas429 = $true
        }
    }
    if (-not $fourthWas429) {
        Write-Host "[E2E] FAILED: 4th request_otp did not return 429"
        exit 1
    }
    Write-Host "[E2E] RateLimit OK (429 received)"

} finally {
    Stop-ServerIfRunning -Proc $proc
}

# --- Production mode: no dev_otp exposed ---
$env:OTP_DEV_MODE = "false"
Write-Host "[E2E] Starting server (OTP_DEV_MODE=false) for production-mode check ..."
$proc2 = Start-ServerAtPort -WorkDir $serverDir -Port $freePort
try {
    if (-not (Wait-ServerReady -BaseUrl $baseUrl)) {
        Write-Host "[E2E] FAILED: Server (prod mode) did not become ready within ${HealthTimeoutSec}s."
        exit 1
    }
    try {
        $prodResp = Invoke-RestMethod -Uri "$baseUrl/auth/request_otp" -Method Post -Body $bodyRequestOtp -ContentType "application/json"
    } catch {
        Write-Host "[E2E] FAILED: POST /auth/request_otp in prod mode failed: $($_.Exception.Message)"
        exit 1
    }
    if ($prodResp.message -ne "otp_sent") {
        Write-Host "[E2E] FAILED: Production mode expected message=otp_sent, got: $($prodResp | ConvertTo-Json)"
        exit 1
    }
    if ($prodResp.dev_otp) {
        Write-Host "[E2E] FAILED: Production mode must not expose dev_otp; got dev_otp=$($prodResp.dev_otp)"
        exit 1
    }
    Write-Host "[E2E] Production Mode OK (no dev_otp exposed)"
} finally {
    Stop-ServerIfRunning -Proc $proc2
}

$env:OTP_DEV_MODE = "true"

Write-Host ""
Write-Host "====================================="
Write-Host "E2E: ALL OK (CI + RateLimit + Prod)"
Write-Host "====================================="
exit 0
