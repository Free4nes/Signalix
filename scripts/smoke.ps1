# Signalix OTP Auth API Smoke Test
# Run from repo root: powershell -ExecutionPolicy Bypass -File .\scripts\smoke.ps1

$BaseUrl = "http://localhost:8080"
$Phone = "+491234567890"
$ErrorActionPreference = "Stop"

Write-Host "=== Signalix OTP Auth Smoke Test ===" -ForegroundColor Cyan
Write-Host ""

# 1) Health check
Write-Host "[1/6] GET /health" -ForegroundColor Yellow
$health = Invoke-RestMethod -Uri "$BaseUrl/health" -Method GET
Write-Host ($health | ConvertTo-Json)
if (-not $health.ok) {
    Write-Host "FAIL: health must return ok:true" -ForegroundColor Red
    exit 1
}
Write-Host "OK" -ForegroundColor Green
Write-Host ""

# 2) Request OTP
Write-Host "[2/6] POST /auth/request_otp" -ForegroundColor Yellow
$reqBody = @{ phone_number = $Phone } | ConvertTo-Json
$reqResp = Invoke-RestMethod -Uri "$BaseUrl/auth/request_otp" -Method POST -ContentType "application/json" -Body $reqBody
Write-Host ($reqResp | ConvertTo-Json)
if (-not $reqResp.dev_otp) {
    Write-Host "FAIL: response must contain dev_otp (OTP_DEV_MODE=true)" -ForegroundColor Red
    exit 1
}
$otp = $reqResp.dev_otp
Write-Host "OK (dev_otp=$otp)" -ForegroundColor Green
Write-Host ""

# 3) Verify OTP
Write-Host "[3/6] POST /auth/verify_otp" -ForegroundColor Yellow
$verifyBody = @{ phone_number = $Phone; otp = $otp } | ConvertTo-Json
$verifyResp = Invoke-RestMethod -Uri "$BaseUrl/auth/verify_otp" -Method POST -ContentType "application/json" -Body $verifyBody
Write-Host ($verifyResp | ConvertTo-Json)
if (-not $verifyResp.access_token) {
    Write-Host "FAIL: response must contain access_token" -ForegroundColor Red
    exit 1
}
if (-not $verifyResp.refresh_token) {
    Write-Host "FAIL: response must contain refresh_token" -ForegroundColor Red
    exit 1
}
$accessToken = $verifyResp.access_token
$refreshToken = $verifyResp.refresh_token
Write-Host "OK" -ForegroundColor Green
Write-Host ""

# 4) POST /auth/refresh
Write-Host "[4/7] POST /auth/refresh" -ForegroundColor Yellow
$refreshBody = @{ refresh_token = $refreshToken } | ConvertTo-Json
$refreshResp = Invoke-RestMethod -Uri "$BaseUrl/auth/refresh" -Method POST -ContentType "application/json" -Body $refreshBody
Write-Host ($refreshResp | ConvertTo-Json)
if (-not $refreshResp.access_token -or -not $refreshResp.refresh_token) {
    Write-Host "FAIL: refresh must return access_token and refresh_token" -ForegroundColor Red
    exit 1
}
$newAccessToken = $refreshResp.access_token
$newRefreshToken = $refreshResp.refresh_token
Write-Host "OK" -ForegroundColor Green
Write-Host ""

# 5) GET /me with new access_token
Write-Host "[5/7] GET /me (with refreshed access_token)" -ForegroundColor Yellow
$meResp = Invoke-RestMethod -Uri "$BaseUrl/me" -Method GET -Headers @{ Authorization = "Bearer $newAccessToken" }
Write-Host ($meResp | ConvertTo-Json)
if (-not $meResp.id -and -not $meResp.phone_number) {
    Write-Host "FAIL: /me must return user (id, phone_number)" -ForegroundColor Red
    exit 1
}
Write-Host "OK" -ForegroundColor Green
Write-Host ""

# 6) Verify old refresh token is invalid (rotation)
Write-Host "[6/7] POST /auth/refresh (old token -> 401)" -ForegroundColor Yellow
try {
    $oldRefreshBody = @{ refresh_token = $refreshToken } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/auth/refresh" -Method POST -ContentType "application/json" -Body $oldRefreshBody -ErrorAction Stop
    Write-Host "FAIL: old refresh token must be rejected (401)" -ForegroundColor Red
    exit 1
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "OK (old token rejected as expected)" -ForegroundColor Green
    } else {
        Write-Host "FAIL: expected 401, got $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# 7) Reuse detection: present the same old token again -> 401 refresh_token_reuse_detected,
#    and the new token (refresh_token_2) must also be revoked as a result.
Write-Host "[7/7] Reuse detection: old token presented again -> 401 refresh_token_reuse_detected" -ForegroundColor Yellow
try {
    $reuseBody = @{ refresh_token = $refreshToken } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/auth/refresh" -Method POST -ContentType "application/json" -Body $reuseBody -ErrorAction Stop
    Write-Host "FAIL: reused token must be rejected (401)" -ForegroundColor Red
    exit 1
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "OK (reuse detected, 401 returned)" -ForegroundColor Green
    } else {
        Write-Host "FAIL: expected 401, got $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
        exit 1
    }
}
# Confirm new token is also revoked (global revoke)
try {
    $newTokenBody = @{ refresh_token = $newRefreshToken } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/auth/refresh" -Method POST -ContentType "application/json" -Body $newTokenBody -ErrorAction Stop
    Write-Host "FAIL: new refresh token must also be revoked after reuse detection" -ForegroundColor Red
    exit 1
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "OK (new token also revoked by global revoke)" -ForegroundColor Green
    } else {
        Write-Host "FAIL: expected 401 for globally revoked token, got $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

Write-Host "Smoke test done." -ForegroundColor Cyan
