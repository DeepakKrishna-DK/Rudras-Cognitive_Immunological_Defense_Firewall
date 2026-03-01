# =============================================================================
# Rudras Maintenance Token Generator
# Creates a HMAC-SHA256 signed maintenance.token file that authorises
# trusted IT tools (Wireshark, x64dbg, etc.) for a specified window.
#
# SECURITY: The token is signed with a machine-derived HMAC key (hostname +
# boot time + username), making it hardware-bound and non-transferable.
# Run this script on the SAME machine that will validate the token.
#
# Usage:
#   .\scripts\generate_maintenance_token.ps1 -DurationMinutes 60 -Purpose "Network audit"
#   .\scripts\generate_maintenance_token.ps1 -DurationMinutes 30
# =============================================================================
param(
    [int]$DurationMinutes = 60,
    [string]$Purpose = "Planned maintenance",
    [string]$OutputFile = "maintenance.token"
)

$ErrorActionPreference = "Stop"

# ── Derive matching HMAC key (must match Rust: derive_hmac_key()) ─────────────
$hostname = [System.Net.Dns]::GetHostName()
$bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$bootEpoch = [int64]([System.DateTimeOffset]$bootTime).ToUnixTimeSeconds()
$username = [System.Environment]::UserName
$keyMaterial = "rudras-hmac-v4:${hostname}:${bootEpoch}:${username}"

# ── Build payload ─────────────────────────────────────────────────────────────
$now = [int64]([System.DateTimeOffset]::UtcNow).ToUnixTimeSeconds()
$uptime = [int64]((Get-CimInstance -ClassName Win32_OperatingSystem).SystemUpTime.TotalSeconds)
$duration = $DurationMinutes * 60

$payloadStr = "UPTIME_START=${uptime},NTP_START=${now},DURATION=${duration},PURPOSE=${Purpose}"
$payloadB64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadStr))

# ── Compute HMAC-SHA256 ───────────────────────────────────────────────────────
$keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($keyMaterial)
$hmac      = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key  = $keyBytes
$sigBytes  = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadB64))
$sigHex    = ($sigBytes | ForEach-Object { "{0:x2}" -f $_ }) -join ''

# ── Write token file ──────────────────────────────────────────────────────────
$tokenContent = @"
# Rudras HMAC-signed maintenance token
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC
# Purpose:   $Purpose
# Machine:   $hostname / $username
# Duration:  $DurationMinutes minutes (expires approx. $(((Get-Date).AddMinutes($DurationMinutes)).ToString('HH:mm')))
# WARNING:   This file is hardware-bound and machine-specific.
#            It CANNOT be reused on another machine.
PAYLOAD:$payloadB64
SIGNATURE:$sigHex
"@

Set-Content -Path $OutputFile -Value $tokenContent -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Rudras Maintenance Token Generated" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  File:     $OutputFile" -ForegroundColor White
Write-Host "  Duration: $DurationMinutes minutes" -ForegroundColor White
Write-Host "  Purpose:  $Purpose" -ForegroundColor White
Write-Host "  Machine:  $hostname" -ForegroundColor White
Write-Host ""
Write-Host "NOTE: Token is valid only ON THIS MACHINE." -ForegroundColor Yellow
Write-Host "      Delete $OutputFile when maintenance is complete." -ForegroundColor Yellow
Write-Host ""
