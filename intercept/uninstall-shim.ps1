# uninstall-shim.ps1 — removes the CIDAS npm shim on Windows.
#
# Counterpart to uninstall-shim.sh. Removes %USERPROFILE%\.cidas\npm.cmd
# and npm-shim.js, then strips the install dir out of the user-scope PATH.
# Leaves the rest of ~/.cidas alone (config.json, daemon.token, audit.log,
# offline-cache.json) so reinstalling doesn't lose user state.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$CidasDir = Join-Path $env:USERPROFILE ".cidas"
$Wrapper  = Join-Path $CidasDir "npm.cmd"
$ShimDest = Join-Path $CidasDir "npm-shim.js"
$HashFile = Join-Path $CidasDir "shim.sha256"

Write-Host "[CIDAS] Uninstalling npm shim..."

foreach ($f in @($Wrapper, $ShimDest, $HashFile)) {
    if (Test-Path -LiteralPath $f) {
        Remove-Item -LiteralPath $f -Force
        Write-Host "[CIDAS] Removed: $f"
    }
}

# Strip $CidasDir out of the user-scope PATH if present. Case-insensitive
# match because the user might have typed a different-cased duplicate.
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if (-not [string]::IsNullOrEmpty($userPath)) {
    $entries = $userPath.Split(";", [StringSplitOptions]::RemoveEmptyEntries)
    $filtered = $entries | Where-Object {
        $_.TrimEnd('\') -ine $CidasDir.TrimEnd('\')
    }
    $newUserPath = ($filtered -join ";")

    if ($newUserPath -ne $userPath) {
        [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
        Write-Host "[CIDAS] Removed $CidasDir from user PATH"
    }
}

Write-Host ""
Write-Host "[CIDAS] Uninstall complete. Open a new PowerShell window for the PATH change to take effect."
