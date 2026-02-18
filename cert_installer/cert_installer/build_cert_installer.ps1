# Build Certificate Installer and Uninstaller
# This script builds standalone executables using PyInstaller

Write-Host "Building ZTProxy Certificate Installer..." -ForegroundColor Cyan

# Ensure we're in the cert_installer directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Clean previous builds
Write-Host "`nCleaning previous builds..." -ForegroundColor Yellow
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }

# Build installer
Write-Host "`nBuilding install_cert.exe..." -ForegroundColor Green
python -m PyInstaller `
    --clean `
    --onefile `
    --console `
    --name "ZTProxy_Install_Cert" `
    --icon=NONE `
    --add-data "../mitmproxy-ca-cert.cer;." `
    --add-data "../mitmproxy-ca.pem;." `
    --add-data "../browser_extension;browser_extension" `
    install_cert.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Installer build failed!" -ForegroundColor Red
    exit 1
}

# Build uninstaller
Write-Host "`nBuilding uninstall_cert.exe..." -ForegroundColor Green
python -m PyInstaller `
    --clean `
    --onefile `
    --console `
    --name "ZTProxy_Uninstall_Cert" `
    --icon=NONE `
    uninstall_cert.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Uninstaller build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n✅ Build completed successfully!" -ForegroundColor Green
Write-Host "`nExecutables created in: $scriptDir\dist\" -ForegroundColor Cyan
Write-Host "  - ZTProxy_Install_Cert.exe" -ForegroundColor White
Write-Host "  - ZTProxy_Uninstall_Cert.exe" -ForegroundColor White

# List files
Write-Host "`nDist contents:" -ForegroundColor Yellow
Get-ChildItem "dist" | Format-Table Name, Length, LastWriteTime -AutoSize
