# start-daemon.ps1 — bootstrap the CIDAS daemon on Windows.
#
# Creates daemon\.venv if absent, installs the daemon package in editable
# mode, then starts uvicorn as a background process and waits for
# /api/v1/health to respond.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$DaemonDir   = Join-Path $ProjectRoot "daemon"
$VenvDir     = Join-Path $DaemonDir ".venv"
$PidFile     = Join-Path $ProjectRoot ".cidas.pid"
$LogOut      = Join-Path $ProjectRoot "daemon-stdout.log"
$LogErr      = Join-Path $ProjectRoot "daemon-stderr.log"
$Port        = if ($env:DAEMON_PORT) { $env:DAEMON_PORT } else { "7355" }
$HostAddr    = if ($env:DAEMON_HOST) { $env:DAEMON_HOST } else { "127.0.0.1" }
$LogLevel    = if ($env:LOG_LEVEL)   { $env:LOG_LEVEL   } else { "info" }

# Load .env — sets env vars so child processes inherit them.
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path -LiteralPath $EnvFile) {
    Get-Content -LiteralPath $EnvFile |
        Where-Object { $_ -match "^\s*[A-Za-z_][A-Za-z0-9_]*\s*=" } |
        ForEach-Object {
            $parts = $_ -split "=", 2
            $key   = $parts[0].Trim()
            $val   = $parts[1].Trim().Trim('"').Trim("'")
            # Strip inline comments (e.g. "info  # debug | info | warning")
            $val   = ($val -split '\s+#')[0].TrimEnd()
            [Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    Write-Host "[CIDAS] Loaded $EnvFile"
}

# Port-occupancy check via .NET (no lsof/netstat dependency).
function Test-PortListening([string]$addr, [int]$port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($addr, $port, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne(200)
        if ($ok -and $client.Connected) { $client.Close(); return $true }
        $client.Close()
    } catch { }
    return $false
}

if (Test-PortListening $HostAddr ([int]$Port)) {
    Write-Host "[CIDAS] Daemon already running on port $Port."
    exit 0
}

# Create venv if absent.
if (-not (Test-Path -LiteralPath $VenvDir)) {
    Write-Host "[CIDAS] Creating Python virtual environment..."
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CIDAS] python -m venv failed. Is Python 3.10+ on PATH?"
        exit 1
    }
    $venvPip = Join-Path $VenvDir "Scripts\pip.exe"
    & $venvPip install --quiet --upgrade pip
    & $venvPip install --quiet -e "$DaemonDir[dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CIDAS] pip install failed."
        exit 1
    }
}

$VenvUvicorn = Join-Path $VenvDir "Scripts\uvicorn.exe"
if (-not (Test-Path -LiteralPath $VenvUvicorn)) {
    Write-Error "[CIDAS] uvicorn.exe not found at $VenvUvicorn -- venv may be corrupt. Delete daemon\.venv and rerun."
    exit 1
}

# Quick import smoke-test: catches Python errors before going to the background.
Write-Host "[CIDAS] Checking daemon imports..."
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
& $VenvPython -c "from daemon.main import app" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "[CIDAS] Daemon import check failed. Fix the error above before starting."
    exit 1
}

Write-Host "[CIDAS] Starting daemon on ${HostAddr}:${Port} ..."
Write-Host "[CIDAS] stdout -> $LogOut"
Write-Host "[CIDAS] stderr -> $LogErr"

$proc = Start-Process -FilePath $VenvUvicorn `
    -ArgumentList @(
        "daemon.main:app",
        "--host",      $HostAddr,
        "--port",      $Port,
        "--log-level", $LogLevel,
        "--app-dir",   $ProjectRoot
    ) `
    -WorkingDirectory      $ProjectRoot `
    -RedirectStandardOutput $LogOut `
    -RedirectStandardError  $LogErr `
    -WindowStyle Hidden `
    -PassThru

$proc.Id | Out-File -LiteralPath $PidFile -Encoding ASCII
Write-Host "[CIDAS] Daemon PID $($proc.Id) written to $PidFile"

# Poll health endpoint for up to 30 seconds.
Write-Host "[CIDAS] Waiting for daemon to be ready..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://${HostAddr}:${Port}/api/v1/health" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch { }

    if ($proc.HasExited) {
        Write-Host ""
        Write-Host "[CIDAS] --- stderr (last 40 lines) ---"
        if (Test-Path $LogErr) { Get-Content $LogErr | Select-Object -Last 40 }
        Write-Host "[CIDAS] --- stdout (last 20 lines) ---"
        if (Test-Path $LogOut) { Get-Content $LogOut | Select-Object -Last 20 }
        Write-Host "[CIDAS] ---"
        Write-Error "[CIDAS] Daemon exited unexpectedly (code $($proc.ExitCode))."
        exit 1
    }
    Start-Sleep -Seconds 1
}

if ($ready) {
    Write-Host "[CIDAS] Daemon is ready."
} else {
    Write-Warning "[CIDAS] Daemon did not respond within 30s -- check $LogErr"
}

Write-Host "[CIDAS] Swagger UI -> http://${HostAddr}:${Port}/docs"
