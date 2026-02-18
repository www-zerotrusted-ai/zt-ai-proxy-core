# ZTProxy Certificate Installer

This folder contains tools to install and manage the mitmproxy CA certificate required for HTTPS interception.

## Files

- **install_cert.py** - Python script to install certificate and Chrome extension
- **uninstall_cert.py** - Python script to remove certificate
- **build_cert_installer.ps1** - PowerShell script to build standalone executables
- **dist/** - Built executables (after running build script)

## Quick Start

### Option 1: Run Python Scripts Directly

Requires Python 3.8+:

```powershell
# Install certificate and extension
python install_cert.py

# Uninstall certificate
python uninstall_cert.py
```

### Option 2: Build and Run Executables

```powershell
# Build executables (requires PyInstaller)
.\build_cert_installer.ps1

# Run installer
.\dist\ZTProxy_Install_Cert.exe

# Run uninstaller
.\dist\ZTProxy_Uninstall_Cert.exe
```

## What Gets Installed

### Certificate Installation
- Locates `mitmproxy-ca.pem` in the project root
- Installs it to Windows **Trusted Root Certification Authorities** (Current User)
- No administrator privileges required
- Enables HTTPS traffic interception

### Chrome Extension Setup
- Locates `chrome_extension` folder
- Provides instructions to manually load the unpacked extension
- Extension enables:
  - Session header injection (X-ZT-Session)
  - Authentication state management
  - Block notification toasts

## Certificate Locations

The installer looks for `mitmproxy-ca.pem` in:
1. Same directory as installer
2. Parent directory (project root)
3. User's home: `~/.mitmproxy/mitmproxy-ca-cert.pem`

## Chrome Extension Installation

After running the installer:

1. Open Chrome: `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `chrome_extension` folder path shown by installer
5. Extension will appear in toolbar

## Uninstallation

The uninstaller removes the certificate from Windows Trusted Root store:

```powershell
python uninstall_cert.py
# or
.\dist\ZTProxy_Uninstall_Cert.exe
```

**Note:** Chrome extension must be manually removed from `chrome://extensions/`

## Building Executables

Requirements:
- Python 3.8+
- PyInstaller: `pip install pyinstaller`

Build command:
```powershell
.\build_cert_installer.ps1
```

This creates:
- `dist/ZTProxy_Install_Cert.exe` (includes certificate + extension files)
- `dist/ZTProxy_Uninstall_Cert.exe`

## Troubleshooting

### "certutil not found"
- Only works on Windows
- `certutil.exe` should be available by default

### "Certificate not found"
- Ensure `mitmproxy-ca.pem` exists in project root
- Check file permissions

### "Extension manifest.json not found"
- Ensure `chrome_extension/manifest.json` exists
- Check folder structure

### Certificate already installed
- Uninstall first: `python uninstall_cert.py`
- Then reinstall: `python install_cert.py`

## Technical Details

### Certificate Installation Method
Uses Windows `certutil` command:
```cmd
certutil -user -addstore -f Root mitmproxy-ca.pem
```

### Certificate Removal Method
```cmd
certutil -user -delstore Root mitmproxy
```

### Registry Path (for reference)
Chrome extensions: `HKCU\Software\Google\Chrome\Extensions`

## Security Notes

- Certificate is installed to **Current User** store only
- Does NOT require administrator privileges
- Only enables interception for the current user
- Extension requires Developer Mode enabled
- Both can be removed at any time

## Integration with Main Installer

This cert installer can be called from the main ZTProxy installer:

```python
import subprocess
subprocess.run(["python", "cert_installer/install_cert.py"])
```

Or using the compiled executable:
```python
subprocess.run(["cert_installer/dist/ZTProxy_Install_Cert.exe"])
```

## Updates

When updating the certificate or extension:
1. Replace `mitmproxy-ca.pem` in project root
2. Update files in `chrome_extension/` folder
3. Rebuild executables: `.\build_cert_installer.ps1`
4. Distribute new `dist/` executables

## Support

For issues:
1. Check ZTProxy logs: `interceptor/intercepted_requests.log`
2. Check Chrome extension console: `chrome://extensions/` → Details → Inspect views → background page
3. Verify certificate: Windows Start → "Manage user certificates" → Trusted Root Certification Authorities → Certificates → mitmproxy
