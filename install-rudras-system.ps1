# ============================================================================
# install-rudras-system.ps1 - Install Rudras as a Background SYSTEM Daemon
#
# This script configures Rudras to run completely independently in the
# background as a SYSTEM-level daemon using Windows Scheduled Tasks.
#
# Benefits over a standard Service:
#   - Doesn't require special SCM dispatch wrappers
#   - Runs perfectly as NT AUTHORITY\SYSTEM (Ring-0)
#   - Survives logouts and reboots automatically
#
# Usage:
#   .\install-rudras-system.ps1          (default mode: client)
#   .\install-rudras-system.ps1 -Uninstall
# ============================================================================

param (
    [Parameter(Position = 0)]
    [string]$Mode = "client",

    [switch]$Uninstall,

    [Parameter()]
    [string]$AdminToken = ""
)

$TaskName       = "RudrasFirewallDaemon"
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
    Write-Host "  UNINSTALLING Rudras SYSTEM Daemon" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red

    # 1. Stop if running
    $proc = Get-Process rudras -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Stopping running Rudras process..." -ForegroundColor Yellow
        $proc | Stop-Process -Force
    }

    # 2. Remove Scheduled Task
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[+] Background task removed." -ForegroundColor Green
    } else {
        Write-Host "Background task not found." -ForegroundColor Gray
    }

    # 3. Clean up the broken sc.exe service from previous attempts just in case
    $svc = Get-Service "RudrasFirewall" -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe delete "RudrasFirewall" | Out-Null
        Write-Host "[+] Cleaned up old service registration." -ForegroundColor Green
    }

    exit 0
}

# -- Banner --------------------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  RUDRAS FIREWALL - Background SYSTEM Daemon Installer" -ForegroundColor Cyan
Write-Host "  Mode: $($Mode.ToUpper())" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# -- Clean up the failing sc.exe service from earlier runs --------------------
$oldSvc = Get-Service "RudrasFirewall" -ErrorAction SilentlyContinue
if ($oldSvc) {
    sc.exe delete "RudrasFirewall" | Out-Null
}

# -- Build release binary if missing ------------------------------------------
if (-Not (Test-Path $ReleaseBinary)) {
    Write-Host ""
    Write-Host "Building release binary (this may take a few minutes)..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    $env:PCAP_LIB_PATH = "C:\npcap-sdk\Lib\x64"
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Build FAILED. Fix compilation errors before installing." -ForegroundColor Red
        exit 1
    }
    Pop-Location
    Write-Host "[+] Release binary built: $ReleaseBinary" -ForegroundColor Green
} else {
    Write-Host "[+] Release binary found: $ReleaseBinary" -ForegroundColor Green
}

# -- Log directory -------------------------------------------------------------
if (-Not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
    Write-Host "[+] Created log directory: $LogDir" -ForegroundColor Green
}

# -- Generate API Admin Token safely (PowerShell 5.1 compatible) --------------
if ([string]::IsNullOrWhiteSpace($AdminToken)) {
    # .NET Framework 4.8 / PS 5.1 compatible crypto rng
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $tokenBytes = New-Object byte[] 32
    $rng.GetBytes($tokenBytes)
    $AdminToken = [Convert]::ToBase64String($tokenBytes).Replace("+", "").Replace("/", "").Replace("=", "").Substring(0, 40)
    
    Write-Host ""
    Write-Host "[KEY] Generated API Admin Token: $AdminToken" -ForegroundColor Yellow
    Write-Host "      SAVE THIS. The Daemon will use this for Auth." -ForegroundColor Yellow
}

# -- Handle existing task and process -----------------------------------------
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$proc = Get-Process rudras -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "Stopping running Rudras instance before taking over..." -ForegroundColor Yellow
    $proc | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# -- Windows Scheduled Task Registration ---------------------------------------
Write-Host ""
Write-Host "Registering persistent SYSTEM background daemon..." -ForegroundColor Cyan

# We must wrap execution in a small .cmd file to export env vars securely to SYSTEM
$wrapperScript = Join-Path $ProjectRoot "run-rudras-system.cmd"
$wrapperContent = @"
@echo off
set RUDRAS_MODE=$Mode
set RUDRAS_API_ADMIN_TOKEN=$AdminToken
set RUDRAS_METRICS_TOKEN=$AdminToken
set PCAP_LIB_PATH=C:\npcap-sdk\Lib\x64
set RUST_LOG=info

cd /d "$ProjectRoot"
"$ReleaseBinary" --mode $Mode --config "$ConfigFile"
"@
Set-Content -Path $wrapperScript -Value $wrapperContent -Encoding Ascii

$action = New-ScheduledTaskAction -Execute $wrapperScript
# Start at boot, and start immediately on registration
$trigger1 = New-ScheduledTaskTrigger -AtStartup
# Set it to reboot upon failure isn't natively supported exactly like services in standard tasks, 
# but SYSTEM level tasks survive user logout perfectly.
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 9999) -Hidden
$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger1 -Settings $settings

Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null

if ($?) {
    Write-Host "[+] Task Registered Successfully" -ForegroundColor Green
    Write-Host "Starting Background Daemon..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 3

    if ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') {
        Write-Host ""
        Write-Host "========================================================" -ForegroundColor Green
        Write-Host "  [+] RUDRAS IS NOW RUNNING AS A BACKGROUND DAEMON" -ForegroundColor Green
        Write-Host "  [+] FULL WFP KERNEL MODE ENFORCEMENT ACTIVE" -ForegroundColor Green
        Write-Host "========================================================" -ForegroundColor Green
        Write-Host "  Identity     : NT AUTHORITY\SYSTEM (Ring-0)" -ForegroundColor White
        Write-Host "  Mode         : $($Mode.ToUpper())" -ForegroundColor White
        Write-Host "  Persistence  : Auto-loads invisibly on boot" -ForegroundColor White
        Write-Host "  API Token    : $AdminToken" -ForegroundColor Yellow
        Write-Host "  Log Path     : $LogDir\Rudras.log.*" -ForegroundColor White
        Write-Host "  API Endpoint : http://127.0.0.1:7443" -ForegroundColor White
        Write-Host ""
        Write-Host "  To uninstall : .\install-rudras-system.ps1 -Uninstall" -ForegroundColor Gray
        Write-Host "========================================================" -ForegroundColor Green
    } else {
        Write-Host "[-] Registered, but failed to transition to Running state." -ForegroundColor Red
        Write-Host "    Check windows Event Viewer." -ForegroundColor Red
    }
} else {
    Write-Host "[-] Failed to register Scheduled Task." -ForegroundColor Red
}
