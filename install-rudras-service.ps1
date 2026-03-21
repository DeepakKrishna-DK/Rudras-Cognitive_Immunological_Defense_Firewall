# ============================================================================
# install-rudras-service.ps1 - Install Rudras as a Windows Service
#
# This script:
#   1. Builds the release binary if not already built
#   2. Registers Rudras as a Windows service (auto-start)
#   3. Configures it to restart automatically on crash
#   4. Sets required environment variables on the service
#   5. Starts the service
#
# Usage:
#   .\install-rudras-service.ps1          (default/auto mode)
#   .\install-rudras-service.ps1 -Mode client
#   .\install-rudras-service.ps1 -Mode server
#   .\install-rudras-service.ps1 -Uninstall
# ============================================================================

param (
    [Parameter(Position = 0)]
    [string]$Mode = "client",

    [switch]$Uninstall,

    [Parameter()]
    [string]$AdminToken = ""
)

$ServiceName    = "RudrasFirewall"
$ServiceDisplay = "Rudras Enterprise Firewall"
$ServiceDesc    = "Rudras 5-Zone Defense-in-Depth Firewall. Cognitive Immunological Defense"
$ProjectRoot    = $PSScriptRoot
$ReleaseBinary  = Join-Path $ProjectRoot "target\release\rudras.exe"
$ConfigFile     = Join-Path $ProjectRoot "config\rudras.toml"
$LogDir         = Join-Path $ProjectRoot "logs"

# -- Auto-elevate --------------------------------------------------------------
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "[!] Requires Administrator. Re-launching elevated..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" `"$Mode`""
    if ($Uninstall) { $argList += " -Uninstall" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit 0
}

# -- Uninstall path ------------------------------------------------------------
if ($Uninstall) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "  UNINSTALLING Rudras Windows Service" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Host "Stopping service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
        Write-Host "Removing service..." -ForegroundColor Yellow
        sc.exe delete $ServiceName | Out-Null
        Write-Host "[+] Service '$ServiceName' removed." -ForegroundColor Green
    } else {
        Write-Host "Service '$ServiceName' not found. Nothing to remove." -ForegroundColor Gray
    }
    exit 0
}

# -- Banner --------------------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  RUDRAS FIREWALL - Windows Service Installer" -ForegroundColor Cyan
Write-Host "  Mode: $($Mode.ToUpper())" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# -- Build release binary if missing ------------------------------------------
if (-Not (Test-Path $ReleaseBinary)) {
    Write-Host ""
    Write-Host "Building release binary (this may take a few minutes)..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    $env:PCAP_LIB_PATH = "C:\npcap-sdk\Lib\x64"
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Build FAILED. Fix compilation errors before installing service." -ForegroundColor Red
        exit 1
    }
    Pop-Location
    Write-Host "[+] Release binary built: $ReleaseBinary" -ForegroundColor Green
} else {
    Write-Host "[+] Release binary found: $ReleaseBinary" -ForegroundColor Green
}

# -- Ensure log directory exists -----------------------------------------------
if (-Not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
    Write-Host "[+] Created log directory: $LogDir" -ForegroundColor Green
}

# -- Generate or prompt for API admin token ------------------------------------
if ([string]::IsNullOrWhiteSpace($AdminToken)) {
    # Generate cryptographically random token
    $tokenBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $AdminToken = [Convert]::ToBase64String($tokenBytes).Replace("+","").Replace("/","").Replace("=","").Substring(0, 40)
    Write-Host ""
    Write-Host "[KEY] Generated API Admin Token: $AdminToken" -ForegroundColor Yellow
    Write-Host "      SAVE THIS. It will be set as RUDRAS_API_ADMIN_TOKEN on the service." -ForegroundColor Yellow
}

# -- Check/remove existing service --------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host ""
    Write-Host "Existing service found. Removing old registration..." -ForegroundColor Yellow
    if ($existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# -- Build service command line ------------------------------------------------
$Mode = $Mode.ToLower()
if ($Mode -notin @("client", "server", "default")) { $Mode = "client" }
$BinCmd = "`"$ReleaseBinary`" --mode $Mode --config `"$ConfigFile`""

# -- Create Windows Service ----------------------------------------------------
Write-Host ""
Write-Host "Registering Windows service '$ServiceName'..." -ForegroundColor Cyan

$result = sc.exe create $ServiceName `
    binPath= $BinCmd `
    DisplayName= $ServiceDisplay `
    start= auto `
    obj= LocalSystem

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] sc.exe create FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
    Write-Host $result
    exit 1
}

# -- Set description -----------------------------------------------------------
sc.exe description $ServiceName $ServiceDesc | Out-Null

# -- Configure recovery: restart on crash (3 attempts, then wait 60s) ---------
Write-Host "Configuring crash recovery (auto-restart on failure)..." -ForegroundColor Cyan
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

# -- Set environment variables on the service ---------------------------------
Write-Host "Setting service environment variables..." -ForegroundColor Cyan
# Set via registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$envVars = @(
    "RUDRAS_MODE=$Mode",
    "RUDRAS_API_ADMIN_TOKEN=$AdminToken",
    "RUDRAS_METRICS_TOKEN=$AdminToken",
    "PCAP_LIB_PATH=C:\npcap-sdk\Lib\x64",
    "RUST_LOG=info"
)
Set-ItemProperty -Path $regPath -Name "Environment" -Value $envVars -Type MultiString

Write-Host "[+] Environment variables configured on service" -ForegroundColor Green

# -- Start the service now -----------------------------------------------------
Write-Host ""
Write-Host "Starting Rudras service..." -ForegroundColor Cyan
Start-Service -Name $ServiceName -ErrorAction Stop

Start-Sleep -Seconds 3

$status = (Get-Service -Name $ServiceName).Status
if ($status -eq "Running") {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "  [+] RUDRAS SERVICE INSTALLED AND RUNNING" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "  Service Name : $ServiceName" -ForegroundColor White
    Write-Host "  Display Name : $ServiceDisplay" -ForegroundColor White
    Write-Host "  Mode         : $($Mode.ToUpper())" -ForegroundColor White
    Write-Host "  Start Type   : Automatic (auto-starts on boot)" -ForegroundColor White
    Write-Host "  Recovery     : Auto-restart on crash (3 attempts)" -ForegroundColor White
    Write-Host "  API Token    : $AdminToken" -ForegroundColor Yellow
    Write-Host "  Log Path     : $LogDir\Rudras.log.*" -ForegroundColor White
    Write-Host "  API Endpoint : http://127.0.0.1:7443" -ForegroundColor White
    Write-Host "  Metrics      : http://127.0.0.1:9091" -ForegroundColor White
    Write-Host ""
    Write-Host "  To stop  : Stop-Service $ServiceName" -ForegroundColor Gray
    Write-Host "  To remove: .\install-rudras-service.ps1 -Uninstall" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[!] Service registered but status is '$status'" -ForegroundColor Yellow
    Write-Host "    Check logs at: $LogDir" -ForegroundColor Yellow
    Write-Host "    Try: Start-Service $ServiceName manually" -ForegroundColor Yellow
}
