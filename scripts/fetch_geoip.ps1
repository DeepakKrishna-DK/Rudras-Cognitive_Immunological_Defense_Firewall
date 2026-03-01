# =============================================================================
# Rudras GeoIP CIDR Downloader
# Downloads country IP CIDR ranges from public RIR delegation files and
# writes them to data/geoip/<CC>.cidr for Rudras' GeoIP blocking engine.
#
# Usage:
#   .\scripts\fetch_geoip.ps1 -Countries CN,RU,KP,IR
#   .\scripts\fetch_geoip.ps1 -Countries CN -OutputDir custom/path
#
# SOURCES (public, no API key required):
#   RIPE NCC (Europe / Russia)  : ftp.ripe.net
#   APNIC    (Asia-Pacific)     : ftp.apnic.net
#   ARIN     (North America)    : ftp.arin.net
#   LACNIC   (Latin America)    : ftp.lacnic.net
#   AFRINIC  (Africa)           : ftp.afrinic.net
# =============================================================================
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Countries,
    [string]$OutputDir = "data\geoip"
)

$ErrorActionPreference = "Stop"

# RIR delegation files
$RIR_URLS = @(
    "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest"
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
)

function Get-CIDRNotation {
    param([string]$ip, [int]$count)
    # Convert base IP + count to CIDR notation
    $prefixLen = 32 - [Math]::Log($count, 2)
    return "$ip/$([int]$prefixLen)"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$CountriesUpper = $Countries | ForEach-Object { $_.ToUpper().Trim() }

Write-Host "Fetching GeoIP data for countries: $($CountriesUpper -join ', ')" -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan

# Initialise output dictionaries
$results = @{}
foreach ($cc in $CountriesUpper) { $results[$cc] = [System.Collections.Generic.List[string]]::new() }

foreach ($url in $RIR_URLS) {
    $rir = ($url -split '/' | Where-Object {$_ -match 'delegated'} | Select-Object -First 1)
    Write-Host "  [$rir] $url" -ForegroundColor DarkGray
    try {
        $content = (Invoke-WebRequest -Uri $url -TimeoutSec 60 -UseBasicParsing).Content
        foreach ($line in ($content -split "`n")) {
            $parts = $line.Trim() -split '\|'
            if ($parts.Count -lt 7) { continue }
            if ($parts[2] -ne 'ipv4') { continue }
            $cc = $parts[1].ToUpper()
            if (-not $CountriesUpper.Contains($cc)) { continue }
            $baseIp = $parts[3]
            $count  = [int]$parts[4]
            if ($count -lt 1) { continue }
            $cidr = Get-CIDRNotation -ip $baseIp -count $count
            $results[$cc].Add($cidr)
        }
    } catch {
        Write-Warning "  Failed to fetch $url : $_"
    }
}

foreach ($cc in $CountriesUpper) {
    $cidrs = $results[$cc]
    $outFile = Join-Path $OutputDir "$($cc.ToLower()).cidr"
    if ($cidrs.Count -gt 0) {
        $header = "# Rudras GeoIP — $cc — Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC"
        ($header, [string]::Join("`n", $cidrs)) | Set-Content $outFile -Encoding UTF8
        Write-Host "  [$cc] Written $($cidrs.Count) CIDRs to $outFile" -ForegroundColor Green
    } else {
        Write-Warning "  [$cc] No data found — check country code and RIR availability"
    }
}

Write-Host "`nDone. Restart Rudras to reload GeoIP data." -ForegroundColor Cyan
