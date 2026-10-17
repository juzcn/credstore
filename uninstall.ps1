<#
.SYNOPSIS
    credstore uninstaller for Windows PowerShell.

.DESCRIPTION
    Uninstalls credstore from uv tool install.
    User data (~\.credstore\) is NOT removed — delete it manually if needed.

.EXAMPLE
    .\uninstall.ps1
#>

$ErrorActionPreference = "Continue"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "  $([char]0x2713) $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  $([char]0x2717) $msg" -ForegroundColor Red }
function Write-Dim($msg)  { Write-Host "  $msg" -ForegroundColor DarkGray }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow }

function Get-ToolBinDir {
    # uv knows where it puts tool shims — ask it rather than assuming
    # %USERPROFILE%\.local\bin, which UV_TOOL_BIN_DIR / XDG_BIN_HOME override.
    $dir = $null
    try {
        $dir = (& uv tool dir --bin 2>$null | Select-Object -First 1)
    } catch {
        $dir = $null
    }
    if (-not $dir) { $dir = "$env:USERPROFILE\.local\bin" }
    return "$dir".Trim()
}

Write-Host ""
Write-Host "credstore Uninstaller" -ForegroundColor Cyan
Write-Host ""

# Set when a step fails, so the script can exit non-zero — a wrapper doing
# `.\uninstall.ps1; if ($?) { ... }` must not be told the tool is gone when it
# is not.
$failed = $false

# 1. Uninstall from uv tool
$installed = uv tool list 2>$null | Select-String "credstore"
if ($installed) {
    Write-Step "Uninstalling credstore..."
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $uninstallOutput = uv tool uninstall credstore 2>&1
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevEAP
    if ($ok) {
        Write-Ok "credstore removed"
    } else {
        Write-Fail "uninstall failed"
        $failed = $true
        if ($uninstallOutput) {
            $uninstallOutput | Select-Object -Last 5 | ForEach-Object { Write-Dim "    $_" }
        }
    }
} else {
    Write-Dim "credstore is not installed."
}

# 2. Clean up wrapper binaries
$localBin = Get-ToolBinDir
foreach ($bin in @("$localBin\credstore.exe", "$localBin\credstore.cmd")) {
    if (Test-Path $bin) {
        Remove-Item $bin -Force -ErrorAction SilentlyContinue
        # Confirm rather than assume: a shim held open by a running process
        # survives the remove, and reporting "Removed:" for it hides that
        # `credstore` still resolves to a binary the uninstall did not touch.
        if (Test-Path $bin) {
            Write-Fail "Could not remove: $bin"
            $failed = $true
        } else {
            Write-Dim "  Removed: $bin"
        }
    }
}

# 3. Remaining data
Write-Host ""
$credstoreDir = "$env:USERPROFILE\.credstore"
if (Test-Path $credstoreDir) {
    Write-Warn "Data files NOT removed (delete manually if desired):"
    Write-Dim "  ~\.credstore\       — encrypted credential backup"
} else {
    Write-Ok "No remaining data files."
}

Write-Host ""
if ($failed) {
    Write-Fail "Uninstall did not complete — see the failed step(s) above."
    exit 1
}
Write-Host "Done." -ForegroundColor Cyan
