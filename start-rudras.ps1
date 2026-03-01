param (
    [Parameter(Position = 0, Mandatory = $false)]
    [string]$Mode = ""
)

# ============================================================
# start-rudras.ps1 - Launch Rudras Enterprise Firewall
# Usage: 
#   .\start-rudras.ps1            (Prompts for mode)
#   .\start-rudras.ps1 client     (Client / Endpoint Mode)
#   .\start-rudras.ps1 server     (Server / Gateway Mode)
# Requires: Administrator privileges
# ============================================================

# Ensure admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: Must run as Administrator" -ForegroundColor Red
    Write-Host "   Right-click PowerShell -> 'Run as Administrator', then re-run this script." -ForegroundColor Yellow
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Mode)) {
    Write-Host ""
    Write-Host "Please select the deployment mode for Rudras Firewall:" -ForegroundColor Yellow
    Write-Host "[1] Client (Endpoint/Workstation Mode - Protects this device)"
    Write-Host "[2] Server (Gateway/Perimeter Mode - Protects inbound traffic)"
    
    $choice = Read-Host -Prompt "Enter your choice (1 or 2)"
    
    if ($choice -eq "2") {
        $Mode = "server"
    }
    else {
        $Mode = "client" # Default to client for any other input
    }
}

$Mode = $Mode.ToLower()
if ($Mode -notin @("client", "server")) {
    Write-Host "Invalid mode: $Mode. Defaulting to client mode." -ForegroundColor Red
    $Mode = "client"
}

if ($Mode -eq "client") {
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "  RUDRAS FIREWALL -- CLIENT / ENDPOINT MODE                      " -ForegroundColor Cyan
    Write-Host "  Protecting: This workstation / laptop / developer machine      " -ForegroundColor Cyan
    Write-Host "  Focus:      Outbound C2 blocking, malware callbacks, exfil     " -ForegroundColor Cyan
    Write-Host "  AI Level:   Aggressive (threshold 0.50 susp / 0.75 block)      " -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan
}
else {
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Magenta
    Write-Host "  RUDRAS FIREWALL -- SERVER / GATEWAY / PERIMETER MODE           " -ForegroundColor Magenta
    Write-Host "  Protecting: Web server | API gateway | Internal services       " -ForegroundColor Magenta
    Write-Host "  Focus:      Inbound attack blocking, port scans, brute force   " -ForegroundColor Magenta
    Write-Host "  IPS:        Aggressive -- RateLimit:20 | Block:80 | BL:280     " -ForegroundColor Magenta
    Write-Host "==================================================================" -ForegroundColor Magenta
}

# Set Npcap SDK path
$env:PCAP_LIB_PATH = "C:\npcap-sdk\Lib\x64"

# Check binary exists
$exe = ".\target\release\rudras.exe"
if (-Not (Test-Path $exe)) {
    $exe = ".\target\debug\rudras.exe"
    if (-Not (Test-Path $exe)) {
        Write-Host "Binary not found -- building now..." -ForegroundColor Yellow
        cargo build --release
        $exe = ".\target\release\rudras.exe"
    }
}

if ($Mode -eq "client") {
    Write-Host "Starting Rudras in CLIENT mode..." -ForegroundColor Green
    Write-Host "   Config: config\rudras.toml (Client Overrides)" -ForegroundColor Gray
    Write-Host "   Press Ctrl+C to stop the firewall gracefully." -ForegroundColor Gray
    Write-Host ""
    & $exe --mode client --config "config\rudras.toml"
}
else {
    Write-Host "Starting Rudras in SERVER mode..." -ForegroundColor Green
    Write-Host "   Config: config\rudras.toml (Server Overrides)" -ForegroundColor Gray
    Write-Host "   Press Ctrl+C to stop the firewall gracefully." -ForegroundColor Gray
    Write-Host ""
    & $exe --mode server --config "config\rudras.toml"
}
