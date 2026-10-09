<#
    demo/run_all.ps1 - Windows entry point for the demo suite.

    * runs demo/run_all.sh through Git Bash (located automatically) and
    * runs one native PowerShell scenario (no bash, no python) that starts the release binary
      directly: the camouflage fallback must answer 200, the client's HTTP proxy must fail for a
      loopback destination (the server refuses private destinations).

    usage:  powershell -ExecutionPolicy Bypass -File demo\run_all.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBash
)

$ErrorActionPreference = 'Stop'
$demoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = Split-Path -Parent $demoDir
$runDir = Join-Path $demoDir '.run'
$logDir = Join-Path $runDir 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$script:passed = 0
$script:failed = 0

function Write-Pass([string]$message) {
    $script:passed++
    Write-Host "    [PASS] $message"
}

function Write-Fail([string]$message) {
    $script:failed++
    Write-Host "    [FAIL] $message"
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

function Wait-Port([int]$port, [int]$timeoutSeconds = 15) {
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $client.Connect('127.0.0.1', $port)
            $client.Close()
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 150
        }
    }
    return $false
}

function Wait-FileMatch([string]$path, [string]$pattern, [int]$timeoutSeconds = 5) {
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $path) -and (Select-String -Path $path -Pattern $pattern -Quiet -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Get-OvertlsBinary {
    foreach ($candidate in @(
            (Join-Path $repoDir 'target\release\overtls-bin.exe'),
            (Join-Path $repoDir 'target\debug\overtls-bin.exe'))) {
        if (Test-Path $candidate) { return $candidate }
    }
    throw "overtls-bin.exe not found - run 'cargo build --release' first"
}

function Format-HexBytes([byte[]]$bytes) {
    if (-not $bytes -or $bytes.Length -eq 0) { return '<empty>' }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join ' ')
}

# Send raw bytes to a loopback port and return what comes back (empty on timeout/close). The comma
# operator keeps the byte array intact instead of unrolling it into the pipeline.
function Invoke-RawProbe {
    param(
        [int]$port,
        [byte[]]$request,
        [int]$timeoutMs = 5000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $port)
    $client.ReceiveTimeout = $timeoutMs
    $stream = $client.GetStream()
    $stream.Write($request, 0, $request.Length)
    $buffer = New-Object byte[] 2048
    $received = New-Object byte[] 0
    try {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -gt 0) {
            $received = New-Object byte[] $read
            [Array]::Copy($buffer, $received, $read)
        }
    }
    catch { }
    $client.Close()
    return , $received
}

# ---------------------------------------------------------------------------------------------
# part 1: the shell scenarios through Git Bash
# ---------------------------------------------------------------------------------------------

if (-not $SkipBash) {
    Write-Host "`n=== part 1: demo/run_all.sh through Git Bash ===" -ForegroundColor Cyan
    # Join-Path throws on a null root, so every candidate root is checked first (the x86 Program
    # Files and LOCALAPPDATA variables are absent in some shells).
    $bashCandidates = @()
    if ($env:ProgramFiles) { $bashCandidates += Join-Path $env:ProgramFiles 'Git\bin\bash.exe' }
    if (${env:ProgramFiles(x86)}) { $bashCandidates += Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe' }
    if ($env:LOCALAPPDATA) { $bashCandidates += Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe' }
    $bashCandidates = @($bashCandidates | Where-Object { Test-Path $_ })

    if ($bashCandidates.Count -eq 0) {
        $found = Get-Command bash.exe -ErrorAction SilentlyContinue
        if ($found) { $bashCandidates = @($found.Source) }
    }

    if ($bashCandidates.Count -eq 0) {
        Write-Host "    Git Bash not found - skipping the shell scenarios (-SkipBash to silence)" -ForegroundColor Yellow
    }
    else {
        $bash = $bashCandidates[0]
        $repoPosix = ($repoDir -replace '\\', '/')
        Write-Host "    using $bash"
        & $bash -c "cd '$repoPosix' && sh demo/run_all.sh"
        if ($LASTEXITCODE -eq 0) { Write-Pass "demo/run_all.sh (Git Bash)" } else { Write-Fail "demo/run_all.sh (exit $LASTEXITCODE)" }
    }
}

# ---------------------------------------------------------------------------------------------
# part 2: native PowerShell scenario
# ---------------------------------------------------------------------------------------------

Write-Host "`n=== part 2: native PowerShell scenario (server + client + camouflage fallback) ===" -ForegroundColor Cyan

$binary = Get-OvertlsBinary
Write-Host "    binary: $binary"

$srvPort = Get-FreePort
$clientPort = Get-FreePort
$targetPort = Get-FreePort
$marker = 'PS-NATIVE-TARGET'
$targetLog = Join-Path $logDir 'ps-target.log'

# A minimal HTTP target built on HttpListener, running in a background job. The accept loop waits
# with a short timeout so `Stop-Job` can interrupt it promptly.
$targetScript = {
    param($port, $marker, $log)
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
    "listening on $port" | Out-File -FilePath $log -Encoding utf8
    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.Wait(200)) {
            if (-not $listener.IsListening) { return }
        }
        $context = $task.Result
        "$($context.Request.HttpMethod) $($context.Request.RawUrl)" | Out-File -FilePath $log -Append -Encoding utf8
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($marker)
        $context.Response.StatusCode = 200
        $context.Response.ContentType = 'text/plain; charset=utf-8'
        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $context.Response.Close()
    }
}
$targetJob = Start-Job -ScriptBlock $targetScript -ArgumentList $targetPort, $marker, $targetLog
# Poll for the target's readiness line instead of sleeping blindly: HttpListener prefix registration
# can fail (access denied) and that must be reported with the job's own error, not as a mysterious
# connection refusal two steps later.
if (-not (Wait-FileMatch -Path $targetLog -Pattern 'listening on' -TimeoutSeconds 5)) {
    $jobErrors = @()
    $jobOutput = Receive-Job -Job $targetJob -ErrorAction SilentlyContinue -ErrorVariable jobErrors | Out-String
    $detail = "$jobOutput$($jobErrors | Out-String)".Trim()
    if (-not $detail) { $detail = "job state: $($targetJob.State)" }
    Write-Fail "the HttpListener target did not start within 5s: $detail"
    Write-Host "    (the HTTP prefix needs an elevated shell, or reserve it once with:" -ForegroundColor Yellow
    Write-Host "     netsh http add urlacl url=http://127.0.0.1:$targetPort/ user=$env:USERNAME)" -ForegroundColor Yellow
}

$serverConfig = Join-Path $runDir 'ps-server.json'
$clientConfig = Join-Path $runDir 'ps-client.json'
# `Set-Content -Encoding utf8` on Windows PowerShell 5.1 prepends a BOM, which serde_json rejects,
# so the files are written through .NET without one.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$serverJson = @{
    tunnel_path         = '/ps/'
    test_timeout_secs   = 10
    server_settings     = @{
        disable_tls  = $true
        listen_host  = '127.0.0.1'
        listen_port  = $srvPort
        forward_addr = "http://127.0.0.1:$targetPort"
    }
} | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($serverConfig, $serverJson, $utf8NoBom)
$clientJson = @{
    tunnel_path       = '/ps/'
    test_timeout_secs = 10
    client_settings   = @{
        disable_tls  = $true
        server_host  = '127.0.0.1'
        server_port  = $srvPort
        listen       = "mixed://127.0.0.1:$clientPort"
        advertise_ip = '127.0.0.1'
        pool_max_size = 8
    }
} | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($clientConfig, $clientJson, $utf8NoBom)

$server = Start-Process -FilePath $binary -ArgumentList @('-r', 'server', '-c', $serverConfig, '-v', 'debug') `
    -WorkingDirectory $runDir -PassThru -RedirectStandardOutput (Join-Path $logDir 'ps-server.log') `
    -RedirectStandardError (Join-Path $logDir 'ps-server.err')
$client = Start-Process -FilePath $binary -ArgumentList @('-r', 'client', '-c', $clientConfig, '-v', 'debug') `
    -WorkingDirectory $runDir -PassThru -RedirectStandardOutput (Join-Path $logDir 'ps-client.log') `
    -RedirectStandardError (Join-Path $logDir 'ps-client.err')

try {
    if (Wait-Port $srvPort) { Write-Pass "server listens on 127.0.0.1:$srvPort" } else { Write-Fail "server did not listen" }
    if (Wait-Port $clientPort) { Write-Pass "client listens on 127.0.0.1:$clientPort" } else { Write-Fail "client did not listen" }

    Write-Host "`n--- unmatched path -> camouflage fallback (native HTTP stack)"
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$srvPort/ps-check" -UseBasicParsing -TimeoutSec 10
        # PowerShell 5.1 hands back a byte[] when the content type is not textual.
        $content = if ($response.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
        if ($response.StatusCode -eq 200 -and $content -match $marker) {
            Write-Pass "fallback answered 200 with the target body"
        }
        else {
            Write-Fail "unexpected fallback response: $($response.StatusCode) $content"
        }
    }
    catch {
        Write-Fail "fallback request failed: $_"
    }

    Write-Host "`n--- SOCKS5 greeting and HTTP proxy mode, byte exact over a raw socket"
    # .NET's WebProxy walks straight past a loopback proxy, so the client is probed with raw sockets.
    $greeting = Invoke-RawProbe -port $clientPort -request ([byte[]]@(0x05, 0x01, 0x00)) -timeoutMs 5000
    Write-Host ("    observed: SOCKS5 method reply {0}" -f (Format-HexBytes $greeting))
    # Current behaviour: the client answers the local SOCKS5 handshake.
    # Post-fix expectation: unchanged (this is plain SOCKS5 negotiation).
    if ($greeting.Length -eq 2 -and $greeting[0] -eq 0x05 -and $greeting[1] -eq 0x00) {
        Write-Pass "the client answered the SOCKS5 greeting with 05 00"
    }
    else {
        Write-Fail "unexpected SOCKS5 greeting reply"
    }

    $absolute = "GET http://127.0.0.1:$targetPort/ps-proxy-check HTTP/1.1`r`nHost: 127.0.0.1:$targetPort`r`nConnection: close`r`n`r`n"
    $direct = Invoke-RawProbe -port $srvPort -request ([System.Text.Encoding]::ASCII.GetBytes($absolute)) -timeoutMs 5000
    $directText = [System.Text.Encoding]::ASCII.GetString($direct)
    Write-Host ('    observed: the same request to the server answers "{0}"' -f ($directText.Split("`r")[0]))
    if ($directText -match $marker) {
        Write-Pass "the camouflage endpoint answers the absolute-form request"
    }
    else {
        Write-Fail "the camouflage endpoint did not answer: $directText"
    }

    $proxied = Invoke-RawProbe -port $clientPort -request ([System.Text.Encoding]::ASCII.GetBytes($absolute)) -timeoutMs 5000
    $proxiedText = [System.Text.Encoding]::ASCII.GetString($proxied)
    Write-Host ("    observed: through the client proxy: {0} byte(s) {1}" -f $proxied.Length, $proxiedText)
    # Current behaviour: the client builds the tunnel to the URI authority, the server refuses the
    # private destination, and the caller receives nothing at all.
    # Post-fix expectation: either a proper error response or a working tunnel.
    if ($proxiedText -match $marker) {
        Write-Fail "the loopback destination was reachable through the client proxy"
    }
    else {
        Write-Pass "the loopback destination is not reachable through the client proxy"
    }
}
finally {
    foreach ($process in @($server, $client)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Stop-Job $targetJob -ErrorAction SilentlyContinue
    Remove-Job $targetJob -Force -ErrorAction SilentlyContinue
}

Write-Host "`n========================= native scenario summary ========================="
Write-Host ("  passed: {0}   failed: {1}" -f $script:passed, $script:failed)
Write-Host "  logs:   $logDir"
Write-Host "=========================================================================="
if ($script:failed -gt 0) { exit 1 }
