# install-shim.ps1 — installs the CIDAS npm shim on Windows.
#
# Mirrors install-shim.sh: creates %USERPROFILE%\.cidas, drops npm-shim.js
# and an npm.cmd wrapper there, records the real npm path, prepends the
# directory to the user-scope PATH, then signs the shim. Idempotent —
# rerunning replaces the on-disk shim and resigns without duplicating
# the PATH entry.
#
# Requires PowerShell 5.1+ or PowerShell Core 7+. Run from any directory.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ShimSrc     = Join-Path $ScriptDir "npm-shim.js"
$CidasDir    = Join-Path $env:USERPROFILE ".cidas"
$ShimDest    = Join-Path $CidasDir "npm-shim.js"
$Wrapper     = Join-Path $CidasDir "npm.cmd"
$RealNpmFile = Join-Path $CidasDir "real-npm"

Write-Host "[CIDAS] Installing npm shim..."

# Locate the real npm. Get-Command resolves the shim itself once installed,
# so we filter to executables NOT in our install dir. Prefer .cmd over .ps1
# because Node.js child_process.spawnSync can execute .cmd directly on Windows
# but cannot execute .ps1 files without a powershell.exe wrapper.
$realNpm = $null
$candidates = @()
foreach ($cmd in (Get-Command npm -All -ErrorAction SilentlyContinue)) {
    $src = $cmd.Source
    if ($src -and -not $src.StartsWith($CidasDir, [StringComparison]::OrdinalIgnoreCase)) {
        $candidates += $src
    }
}
# Pick the first .cmd candidate; fall back to the first non-.ps1; then any.
foreach ($src in $candidates) {
    if ($src -match '\.cmd$') { $realNpm = $src; break }
}
if (-not $realNpm) {
    foreach ($src in $candidates) {
        if ($src -notmatch '\.ps1$') { $realNpm = $src; break }
    }
}
if (-not $realNpm -and $candidates.Count -gt 0) {
    $realNpm = $candidates[0]
}
if (-not $realNpm) {
    Write-Error "[CIDAS] npm not found on PATH. Install Node.js first."
    exit 1
}
Write-Host "[CIDAS] Real npm -> $realNpm"

# Guard: refuse to wrap our own wrapper (catches a reinstall where the
# previous run left ~/.cidas first on PATH but real npm has since been
# uninstalled).
if ($realNpm -ieq $Wrapper) {
    Write-Error "[CIDAS] Shim is already active. Run uninstall-shim.ps1 first."
    exit 1
}

# Prepare the install directory.
New-Item -ItemType Directory -Force -Path $CidasDir | Out-Null
Set-Content -Path $RealNpmFile -Value $realNpm -NoNewline -Encoding ASCII
Copy-Item -Path $ShimSrc -Destination $ShimDest -Force

# The wrapper: a single-purpose .cmd that hands every argv straight to node.
# %* forwards everything including quoting; @echo off keeps the console clean.
@'
@echo off
node "%USERPROFILE%\.cidas\npm-shim.js" %*
'@ | Set-Content -Path $Wrapper -Encoding ASCII

Write-Host "[CIDAS] Shim installed: $Wrapper"
Write-Host "[CIDAS] Real npm saved: $realNpm"

# Prepend $CidasDir to the user-scope PATH so new terminals pick it up.
# We read+rewrite via [Environment] rather than $env:PATH so the change
# survives logoff (the latter would only affect the current session).
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ([string]::IsNullOrEmpty($userPath)) { $userPath = "" }

$pathEntries = $userPath.Split(";", [StringSplitOptions]::RemoveEmptyEntries)
$alreadyOnPath = $pathEntries | Where-Object { $_.TrimEnd('\') -ieq $CidasDir.TrimEnd('\') }

if (-not $alreadyOnPath) {
    $newUserPath = if ($userPath) { "$CidasDir;$userPath" } else { $CidasDir }
    [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
    Write-Host "[CIDAS] Added $CidasDir to user PATH"
} else {
    Write-Host "[CIDAS] $CidasDir already in user PATH"
}

# Sign via the shim itself (no external sha256 tool needed on Windows).
Write-Host "[CIDAS] Signing shim..."
& node $ShimDest --sign
if ($LASTEXITCODE -ne 0) {
    Write-Error "[CIDAS] sign-shim step failed (exit $LASTEXITCODE)."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "[CIDAS] Done. Open a new PowerShell window for the PATH change to take effect."
Write-Host "[CIDAS] Verify with: where.exe npm   (should list $Wrapper first)"
