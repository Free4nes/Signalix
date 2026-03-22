# PATCH /me Test - Set $token before running
# Usage: $token = "..."; powershell -ExecutionPolicy Bypass -File .\scripts\test-patch-me.ps1

$BaseUrl = "http://localhost:8080"
$Headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer $token"
}

Write-Host "PATCH /me" -ForegroundColor Cyan
$patchBody = '{"display_name": "Ricardo"}'
$patch = Invoke-RestMethod -Uri "$BaseUrl/me" -Method PATCH -Headers $Headers -Body $patchBody
$patch | ConvertTo-Json

Write-Host ""
Write-Host "GET /me" -ForegroundColor Cyan
$get = Invoke-RestMethod -Uri "$BaseUrl/me" -Method GET -Headers @{ Authorization = "Bearer $token" }
$get | ConvertTo-Json
