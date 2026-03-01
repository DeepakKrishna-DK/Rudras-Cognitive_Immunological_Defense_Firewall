# =============================================================================
# Rudras Config Signature Tool
# Signs config/rudras.toml with SHA-256 so Rudras can detect tampering.
#
# Usage:
#   .\scripts\sign_config.ps1                     # signs config/rudras.toml
#   .\scripts\sign_config.ps1 -ConfigPath custom/path.toml
#
# After editing rudras.toml, always run this script to update the signature.
# =============================================================================
param(
    [string]$ConfigPath = "config\rudras.toml"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found: $ConfigPath"
    exit 1
}

$hash = (Get-FileHash $ConfigPath -Algorithm SHA256).Hash.ToLower()
$sigFile = "${ConfigPath}.sig"
"sha256:${hash}" | Set-Content $sigFile -Encoding UTF8

Write-Host "Config signed:" -ForegroundColor Green
Write-Host "  File:      $ConfigPath" -ForegroundColor White
Write-Host "  Signature: $sigFile" -ForegroundColor White
Write-Host "  SHA-256:   $hash" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Run this script again after any config change." -ForegroundColor Yellow
