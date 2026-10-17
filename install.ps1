<#
.SYNOPSIS
    credstore one-click installer for Windows PowerShell.

.DESCRIPTION
    No prerequisites — the script installs uv if needed, then uses
    ``uv tool install --force`` in an isolated environment.  --force makes
    the script idempotent: first run installs, re-runs upgrade to the latest
    PyPI release.  Python is managed automatically by uv.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/juzcn/credstore/main/install.ps1 | iex"

    Or download first:
    irm https://raw.githubusercontent.com/juzcn/credstore/main/install.ps1 -OutFile install.ps1
    .\install.ps1
#>

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "  $([char]0x2713) $msg" -ForegroundColor Green }
function Write-Dim($msg)  { Write-Host "  $msg" -ForegroundColor DarkGray }
function Write-Err($msg)  { Write-Host $msg -ForegroundColor Red }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow }

function Get-ToolBinDir {
    # uv knows where it puts tool shims — ask it rather than assuming
    # %USERPROFILE%\.local\bin, which UV_TOOL_BIN_DIR / XDG_BIN_HOME override
    # (and which uv's own installer honours too).  The EAP dance is needed for
    # the same reason as the install step below: redirecting a native
    # command's stderr under $ErrorActionPreference = "Stop" is terminating.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $dir = $null
    try {
        $dir = (& uv tool dir --bin 2>$null | Select-Object -First 1)
    } catch {
        $dir = $null
    }
    $ErrorActionPreference = $prevEAP
    if (-not $dir) { $dir = "$env:USERPROFILE\.local\bin" }
    return "$dir".Trim()
}

function Add-ToUserPath($dir) {
    # Read the RAW value and write it back as REG_EXPAND_SZ.
    # [Environment]::SetEnvironmentVariable('Path', ..., 'User') stores a
    # REG_SZ of the *already expanded* text, permanently baking %USERPROFILE%
    # and friends into the user's PATH and dropping the expansion behaviour.
    $current = $null
    try {
        $envKey = Get-Item -Path "HKCU:\Environment" -ErrorAction Stop
        $current = $envKey.GetValue(
            "Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    } catch {
        $current = ""
    }
    # Anything but an ordinary string (a REG_MULTI_SZ, say) is not something to
    # rewrite blindly — leave it alone and let the user's shell pick uv up.
    if ($current -isnot [string]) { return }
    if ($current -split ';' -contains $dir) { return }

    $newValue = if ($current) { "$current;$dir" } else { $dir }
    try {
        Set-ItemProperty -Path "HKCU:\Environment" -Name Path -Value $newValue -Type ExpandString
    } catch {
        # Failing to edit PATH must not fail the install: the tool is in place,
        # this shell has the directory, and a warning says what is missing.
        Write-Warn "Could not update the User PATH — add this directory yourself:"
        Write-Dim "  $dir"
    }
}

$repo = "https://github.com/juzcn/credstore"

Write-Host "credstore Installer" -ForegroundColor Cyan
Write-Host ""
Write-Host "Install method : uv tool install --force (isolated environment; re-run = update)"
Write-Host "User data      : ~\.credstore\ (encrypted credential backup)"
Write-Host "Python         : 3.13+ (managed by uv)"
Write-Host ""

# [1/2] Ensure uv is available
Write-Step "[1/2] Ensuring uv is available..."
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Dim "Installing uv..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: could not install uv."
        Write-Warn "Help: https://docs.astral.sh/uv/"
        exit 1
    }
    # uv's installer puts its binary in %USERPROFILE%\.local\bin by default and
    # registers that directory for the *next* shell; this one needs it now.
    # (With UV_INSTALL_DIR set elsewhere, uv stays unresolvable here — the
    # check below then says so plainly instead of failing later with a trace.)
    $env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"
}
# Report a missing uv here rather than at the next line: under
# $ErrorActionPreference = "Stop" an unresolvable `uv` inside a subexpression
# is a *terminating* error, so the script died with a raw PowerShell trace
# (after printing the success-looking "✓ uv") instead of a message.
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Err "Error: uv is not available on PATH after installation."
    Write-Warn "  Install it manually: https://docs.astral.sh/uv/"
    exit 1
}
Write-Ok "uv $(& uv --version)"

# [2/2] Install/update credstore from PyPI.  --force: re-running this
# script upgrades an existing install (a plain ``uv tool install`` no-ops
# with "already installed").
#
# --python is required, not cosmetic: without it uv builds the tool env on
# whatever interpreter it prefers (often an older one it already manages)
# and then resolves to the newest release compatible with THAT Python.
# credstore 0.10+ needs >= 3.13, so a 3.12 tool env silently installs 0.9.0.
# With the constraint uv fetches a suitable interpreter, or fails loudly.
Write-Step "[2/2] Installing/updating credstore..."
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$uvOutput = & uv tool install --force --python ">=3.13" credstore 2>&1
$ok = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prevEAP
if (-not $ok) {
    Write-Err "Error: credstore installation failed."
    # uv's own message is the only thing that says WHY — no 3.13 interpreter,
    # DNS/proxy failure, dependency resolution — so show its tail instead of
    # discarding it (the sibling uninstall.ps1 already reports this way).
    $uvOutput | Select-Object -Last 10 | ForEach-Object { Write-Dim "    $_" }
    Write-Warn "Help: $repo"
    exit 1
}
Write-Ok "credstore ready"

$localBin = Get-ToolBinDir
$env:PATH = "$localBin;$env:PATH"

# Ensure the shim directory is on the persistent User PATH
Add-ToUserPath $localBin

Write-Host ""
Write-Host "credstore installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Get started:" -ForegroundColor Cyan
Write-Host "  credstore set-password    # set up encrypted backup (first time)"
Write-Host "  credstore set API_KEY     # store a secret (masked input)"
Write-Host ""
Write-Host "More info: $repo" -ForegroundColor Cyan
