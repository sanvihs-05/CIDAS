# run-tests.ps1 — run daemon (pytest) and extension (vitest) test suites on Windows.
#
# Mirrors run-tests.sh. Creates daemon\.venv if absent, then runs pytest
# followed by vitest and prints a pass/fail summary.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root       = Resolve-Path (Join-Path $ScriptDir "..")
$DaemonDir  = Join-Path $Root "daemon"
$ExtDir     = Join-Path $Root "extension"
$InterceptDir = Join-Path $Root "intercept"
$VenvDir    = Join-Path $DaemonDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip    = Join-Path $VenvDir "Scripts\pip.exe"
$VenvPytest = Join-Path $VenvDir "Scripts\pytest.exe"

Write-Host "══════════════════════════════════════════"
Write-Host "  CIDAS Test Suite"
Write-Host "══════════════════════════════════════════"

# ── Daemon (pytest) ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Daemon tests (pytest + coverage)..."

if (-not (Test-Path -LiteralPath $VenvDir)) {
    Write-Host "[CIDAS] Creating venv and installing daemon dependencies..."
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CIDAS] python -m venv failed. Is Python 3.10+ on PATH?"
        exit 1
    }
    & $VenvPip install --quiet --upgrade pip
    & $VenvPip install --quiet -e "$DaemonDir[dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CIDAS] pip install failed."
        exit 1
    }
}

Push-Location $Root
try {
    & $VenvPytest daemon/tests/ `
        --cov=daemon `
        --cov-config=daemon/pyproject.toml `
        --cov-report=term-missing `
        -v
    $PytestExit = $LASTEXITCODE
} finally {
    Pop-Location
}

# ── npm shim (Jest) ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Shim tests (jest)..."

Push-Location $InterceptDir
try {
    if (-not (Test-Path -LiteralPath (Join-Path $InterceptDir "node_modules"))) {
        Write-Host "[CIDAS] Installing intercept node_modules..."
        & npm install
    }
    & npm test
    $JestExit = $LASTEXITCODE
} finally {
    Pop-Location
}

# ── Extension (vitest) ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Extension tests (vitest)..."

Push-Location $ExtDir
try {
    if (-not (Test-Path -LiteralPath (Join-Path $ExtDir "node_modules"))) {
        Write-Host "[CIDAS] Installing extension node_modules..."
        & npm install
    }
    & npx vitest run
    $VitestExit = $LASTEXITCODE
} finally {
    Pop-Location
}

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════"
if ($PytestExit -eq 0 -and $JestExit -eq 0 -and $VitestExit -eq 0) {
    Write-Host "  ALL TESTS PASSED"
    exit 0
} else {
    Write-Host "  FAILURES: pytest=$PytestExit  jest=$JestExit  vitest=$VitestExit"
    exit 1
}
