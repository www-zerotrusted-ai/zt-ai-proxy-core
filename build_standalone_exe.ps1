<#!
.SYNOPSIS
  Build script for ZTProxy STANDALONE Edition (Open Source).
.DESCRIPTION
  Builds the standalone edition with:
  - No enterprise modules (excluded from build)
  - Local-only providers (file-based config, no-auth, local audit logs)
  - Static blocklists from JSON files
  - No API keys required
.PARAMETER OneFile
  Build a single-file executable (slower first start) instead of onedir.
.PARAMETER Clean
  Remove existing build & dist folders before building.
.EXAMPLE
  pwsh ./build_standalone.ps1                 # Onedir build (default)
  pwsh ./build_standalone.ps1 -OneFile        # Single file build
  pwsh ./build_standalone.ps1 -Clean -OneFile # Clean + single file
.NOTES
  Output: dist/ZTProxy-Standalone.exe (or dist/ZTProxy-Standalone/ folder)
!#>
param(
    [switch]$OneFile,
    [switch]$Clean,
    [string]$Venv = 'venv312'
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg){ Write-Host "[Standalone Build] $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg){ Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Resolve paths
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "========================================" -ForegroundColor Green
Write-Host "  ZTProxy STANDALONE Edition - Build" -ForegroundColor Green
Write-Host "  Open Source | No Auth | Local Only" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

$VenvPath = Join-Path $Root $Venv
$Python = if (Test-Path (Join-Path $VenvPath 'Scripts/python.exe')) { Join-Path $VenvPath 'Scripts/python.exe' } else { $null }

# 1. Create venv if missing
if (-not $Python) {
    Write-Step "Creating venv '$Venv' (Python 3.12 if available)"
    $pyLauncher = if ($env:PYTHON) { $env:PYTHON } else { 'py' }
    & $pyLauncher -3.12 -m venv $Venv | Out-Null
    $Python = Join-Path $VenvPath 'Scripts/python.exe'
}
if (-not (Test-Path $Python)) { Write-Err "Python executable not found in venv"; exit 1 }

# 2. Upgrade pip + install deps
Write-Step 'Upgrading pip'
& $Python -m pip install --upgrade pip >$null

Write-Step 'Installing project dependencies'
# Install dependencies directly from pyproject.toml
& $Python -m pip install openai mitmproxy bs4 beautifulsoup4 lxml httpx requests aiohttp zt-guardrails-lib redis

Write-Step 'Installing mitmproxy (pinned version)'
& $Python -m pip install "mitmproxy==12.1.1"

Write-Step 'Verifying mitmproxy import'
& $Python -c "import mitmproxy, mitmproxy.tools.main as _m; print('mitmproxy OK')" | Out-Null

# 3. Ensure PyInstaller present
$havePyInstaller = & $Python -c "import importlib,sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"; $rc=$LASTEXITCODE
if ($rc -ne 0) {
    Write-Step 'Installing PyInstaller'
    & $Python -m pip install pyinstaller
}

# 4. Set STANDALONE edition environment variable for build
$env:ZT_EDITION = 'standalone'
Write-Step "Edition: STANDALONE (ZT_EDITION=$env:ZT_EDITION)"

# 5. Optional clean
if ($Clean) {
    Write-Step 'Cleaning build, dist, __pycache__'
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build,dist
    Get-ChildItem -Recurse -Include '__pycache__' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

# 6. Build mode
$SpecFile = Join-Path $Root 'ZTProxy-Standalone.spec'
$mode = if ($OneFile) { 'onefile' } else { 'onedir' }
Write-Step "Building ($mode)"

# 7. Stop any running proxy
try {
  $procs = Get-Process -Name 'ZTProxy*' -ErrorAction SilentlyContinue
  if ($procs) {
    Write-Warn 'Stopping running ZTProxy to release file locks'
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }
} catch {}

# 8. Create default config files for standalone
Write-Step 'Creating default standalone config files'
$configDir = Join-Path $Root 'config'
if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Force -Path $configDir | Out-Null }

# Default blocklist
$blocklistPath = Join-Path $configDir 'blocklist.json'
if (-not (Test-Path $blocklistPath)) {
    $blocklist = @(
        "openai.com", "anthropic.com", "claude.ai", "chatgpt.com",
        "gemini.google.com", "bard.google.com", "copilot.microsoft.com",
        "perplexity.ai", "poe.com", "you.com", "character.ai"
    )
    $blocklist | ConvertTo-Json | Set-Content -Path $blocklistPath -Encoding UTF8
    Write-Step "Created default blocklist: $blocklistPath"
}

# Default whitelist (empty)
$whitelistPath = Join-Path $configDir 'whitelist.json'
if (-not (Test-Path $whitelistPath)) {
    @() | ConvertTo-Json | Set-Content -Path $whitelistPath -Encoding UTF8
    Write-Step "Created default whitelist: $whitelistPath"
}

# Default config
$configPath = Join-Path $Root 'ztproxy_config.json'
if (-not (Test-Path $configPath)) {
    $config = @{
        edition = "standalone"
        filter_mode = "post-chat-pii"
        enforcement_mode = "block"
        use_remote_blocklist = $false
        include_request_body = $false
        debug = $false
    }
    $config | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8
    Write-Step "Created default config: $configPath"
}

# 9. Run PyInstaller with standalone spec
if (Test-Path $SpecFile) {
    & $Python -m PyInstaller --clean $SpecFile
} else {
    Write-Err "Spec file not found: $SpecFile"
    Write-Step "Creating spec file..."
    
    # Create spec file dynamically
    $specContent = @"
# -*- mode: python ; coding: utf-8 -*-
# ZTProxy Standalone Edition Spec
import os
from PyInstaller.utils.hooks import collect_submodules

_mitm = collect_submodules('mitmproxy')
_aio = collect_submodules('aiohttp')
_req = collect_submodules('requests')
_extra = [
    'mitmproxy.tools.main',
    'mitmproxy.addonmanager',
    'aiohttp','yarl','multidict','frozenlist','aiosignal'
]
hidden_all = sorted(set(_mitm + _aio + _req + _extra))

# Include core and interceptor, EXCLUDE enterprise
datas_items = [
    ('core', 'core'),
    ('interceptor', 'interceptor'),
    ('browser_extension', 'browser_extension'),
    ('config', 'config'),
]

a = Analysis(
    ['zt-proxy 1.py'],
    pathex=[os.getcwd()],
    binaries=[],
    datas=datas_items,
    hiddenimports=hidden_all,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['enterprise'],  # Exclude enterprise modules
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ZTProxy-Standalone',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"@
    $specContent | Set-Content -Path $SpecFile -Encoding UTF8
    & $Python -m PyInstaller --clean $SpecFile
}

if ($LASTEXITCODE -ne 0) { Write-Err "Build failed."; exit $LASTEXITCODE }

# 10. Summary
if ($OneFile) {
    $exe = Join-Path $Root 'dist/ZTProxy-Standalone.exe'
    if (Test-Path $exe) { 
        Write-Host ""
        Write-Step "[OK] Standalone executable: $exe" 
        Write-Host "  Size: $([math]::Round((Get-Item $exe).Length / 1MB, 2)) MB" -ForegroundColor Gray
    } else { 
        Write-Warn 'Executable not found in dist/' 
    }
} else {
    $exe = Join-Path $Root 'dist/ZTProxy-Standalone/ZTProxy-Standalone.exe'
    if (Test-Path $exe) { 
        Write-Host ""
        Write-Step "[OK] Standalone executable: $exe" 
        $folderSize = (Get-ChildItem -Path (Join-Path $Root 'dist/ZTProxy-Standalone') -Recurse | Measure-Object -Property Length -Sum).Sum
        Write-Host "  Folder size: $([math]::Round($folderSize / 1MB, 2)) MB" -ForegroundColor Gray
    } else { 
        Write-Warn 'Executable not found in dist/ZTProxy-Standalone/' 
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "To run the standalone edition:" -ForegroundColor Yellow
if ($OneFile) { 
    Write-Host "  .\dist\ZTProxy-Standalone.exe" -ForegroundColor White
} else { 
    Write-Host "  .\dist\ZTProxy-Standalone\ZTProxy-Standalone.exe" -ForegroundColor White
}
Write-Host ""
Write-Host "Edition: STANDALONE - No auth, local files only" -ForegroundColor Cyan
Write-Host ""
