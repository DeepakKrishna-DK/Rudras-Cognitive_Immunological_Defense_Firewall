# ============================================================================
# test-ai-layers.ps1
# This script artificially generates highly anomalous traffic to intentionally 
# trigger Rudras Firewall's Machine Learning and Behavioral engines. 
# It then extracts the resulting logs (AI blocks, Suspicion scores, Escaltions)
# and writes them to: Testing\ai_test_results.txt
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir
$ResultsFile = Join-Path $ScriptDir "ai_test_results.txt"
$LogPath = (Get-ChildItem -Path (Join-Path $ProjectRoot "logs") | Sort-Object LastWriteTime -Descending)[0].FullName

Write-Host "[*] Starting AI Anomaly Simulation..." -ForegroundColor Cyan
Set-Content -Path $ResultsFile -Value "==========================================="
Add-Content -Path $ResultsFile -Value " RUDRAS AI/ML ENGINE TEST RESULTS          "
Add-Content -Path $ResultsFile -Value "==========================================="

# Note the last log line before we start so we only grab new events
$StartLines = (Get-Content $LogPath).Count

# ----------------------------------------------------------------------------
# Test 1: UEBA (Behavioral Anomaly) - Sending strange outbound port sequence
# ----------------------------------------------------------------------------
Write-Host "   -> Triggering Behavioral Anomaly (UEBA/Port Sweeps)..."
try {
    # Send quick rapid-fire connections to highly unusual consecutive ports
    $ports = @(54321, 54322, 54323, 54324, 7777, 8888, 9999)
    foreach ($p in $ports) {
        $sock = New-Object System.Net.Sockets.TcpClient
        $sock.ConnectAsync("1.1.1.1", $p).Wait(50) | Out-Null
        $sock.Close()
    }
} catch { }
Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# Test 2: DPI-ML (High Entropy Payload) - Simulating Encrypted C2 Malware
# ----------------------------------------------------------------------------
Write-Host "   -> Triggering DPI-ML Deep Packet Anomaly (High Entropy)..."
try {
    # Generate pure, random high-entropy bytes resembling encrypted malware
    $bytes = New-Object byte[] 1024
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    # Ping an obscure port with it
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Connect("8.8.8.8", 12345)
    $udp.Send($bytes, $bytes.Length) | Out-Null
    $udp.Close()
} catch { }
Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# Test 3: WAF / Advanced Threat - Sending SQLi / Directory Traversal 
# ----------------------------------------------------------------------------
Write-Host "   -> Triggering Advanced WAF / Framework Analytics..."
try {
    # Send a classic application-layer attack string over a custom port
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("example.com", 80)
    $stream = $tcp.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.WriteLine("GET /login?user=admin'-- AND 1=1 HTTP/1.1")
    $writer.WriteLine("Host: example.com")
    $writer.WriteLine("User-Agent: curl/7.68.0")
    $writer.WriteLine("")
    $writer.Flush()
    $tcp.Close()
} catch { }

Write-Host "[*] Waiting 5 seconds for Rudras AI to process risk aggregation..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# ----------------------------------------------------------------------------
# Extract Results
# ----------------------------------------------------------------------------
Write-Host "[*] Extracting logs to: Testing\ai_test_results.txt" -ForegroundColor Cyan
$EndLines = (Get-Content $LogPath).Count
$LinesToRead = $EndLines - $StartLines
if ($LinesToRead -lt 0) { $LinesToRead = 50 }

$NewLogs = Get-Content $LogPath -Tail $LinesToRead | Where-Object { 
    $_ -match "AI|ML|risk|threat|UEBA|DPI|Reinforcement|blocked|COMP-BLOCK|IDS" 
}

Add-Content -Path $ResultsFile -Value "`n[--- RAW AI ENGINE LOG DETECTIONS ---]"
foreach ($log in $NewLogs) {
    # Pretty parsing of JSON log file
    if ($log -match '"message":"([^"]+)"') {
        $msg = $matches[1].Replace('\u001b[0m','').Replace('\u001b[31m','').Replace('\u001b[33m','')
        
        # Determine strict AI layer
        $layer = "General Detection"
        if ($msg -match "AI|risk") { $layer = "[Q-Learning Risk AI]" }
        if ($msg -match "DPI-ML") { $layer = "[Deep Packet ML]" }
        if ($msg -match "UEBA") { $layer = "[Behavioral AI]" }
        if ($msg -match "COMP-BLOCK") { $layer = "[WAF/Defense]" }
        if ($msg -match "IDS") { $layer = "[IDS Heuristics]" }
        
        Add-Content -Path $ResultsFile -Value "$layer  $msg"
    } else {
        Add-Content -Path $ResultsFile -Value $log
    }
}

Write-Host "[+] DONE! Read the results from the Testing folder." -ForegroundColor Green
