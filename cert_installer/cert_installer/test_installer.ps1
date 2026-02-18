# Test Certificate Installer
# Quick verification that cert and extension can be found

Write-Host "Testing Certificate Installer..." -ForegroundColor Cyan

# Check if Python is available
Write-Host "`nChecking Python..." -ForegroundColor Yellow
$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCheck) {
    Write-Host "  ✓ Python found: $(python --version)" -ForegroundColor Green
} else {
    Write-Host "  ✗ Python not found!" -ForegroundColor Red
    exit 1
}

# Check if mitmproxy-ca.pem exists
Write-Host "`nChecking certificate file..." -ForegroundColor Yellow
$certPath = "..\mitmproxy-ca.pem"
if (Test-Path $certPath) {
    Write-Host "  ✓ Found: $certPath" -ForegroundColor Green
    $certSize = (Get-Item $certPath).Length
    Write-Host "    Size: $certSize bytes" -ForegroundColor Gray
} else {
    Write-Host "  ✗ Not found: $certPath" -ForegroundColor Red
}

# Check if chrome_extension exists
Write-Host "`nChecking Chrome extension..." -ForegroundColor Yellow
$extPath = "..\chrome_extension"
if (Test-Path $extPath) {
    Write-Host "  ✓ Found: $extPath" -ForegroundColor Green
    $manifestPath = Join-Path $extPath "manifest.json"
    if (Test-Path $manifestPath) {
        Write-Host "    ✓ manifest.json exists" -ForegroundColor Green
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        Write-Host "    Name: $($manifest.name)" -ForegroundColor Gray
        Write-Host "    Version: $($manifest.version)" -ForegroundColor Gray
    } else {
        Write-Host "    ✗ manifest.json not found!" -ForegroundColor Red
    }
} else {
    Write-Host "  ✗ Not found: $extPath" -ForegroundColor Red
}

# Check if install_cert.py exists
Write-Host "`nChecking installer script..." -ForegroundColor Yellow
if (Test-Path "install_cert.py") {
    Write-Host "  ✓ Found: install_cert.py" -ForegroundColor Green
} else {
    Write-Host "  ✗ Not found: install_cert.py" -ForegroundColor Red
}

# Check if PyInstaller is available
Write-Host "`nChecking PyInstaller..." -ForegroundColor Yellow
try {
    $pyiCheck = python -m PyInstaller --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ PyInstaller found: $pyiCheck" -ForegroundColor Green
    } else {
        Write-Host "  ✗ PyInstaller not installed" -ForegroundColor Yellow
        Write-Host "    Install: pip install pyinstaller" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ✗ PyInstaller not installed" -ForegroundColor Yellow
    Write-Host "    Install: pip install pyinstaller" -ForegroundColor Gray
}

Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "Test Complete" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
