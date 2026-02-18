# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files
from pathlib import Path
import os

# Get the directory containing this spec file
spec_dir = Path(SPECPATH)
project_root = spec_dir.parent

# Certificate files to embed
cert_files = []

# Add certificate from cert_installer directory
local_cert = spec_dir / "mitmproxy-ca 5.pem"
if local_cert.exists():
    cert_files.append((str(local_cert), 'certs'))
    print(f"[SPEC] Embedding certificate: {local_cert}")

# Add fallback certificates from parent config directory
config_dir = project_root / "config"
if config_dir.exists():
    for cert_name in ["mitmproxy-ca-cert.pem", "mitmproxy-ca.pem"]:
        cert_path = config_dir / cert_name
        if cert_path.exists():
            cert_files.append((str(cert_path), 'certs'))

print(f"[SPEC] Total certificates to embed: {len(cert_files)}")

# Chrome extension files to embed
extension_files = []
extension_dir = project_root / "chrome_extension"

if extension_dir.exists():
    print(f"[SPEC] Embedding Chrome extension from: {extension_dir}")
    
    # Add all files from chrome_extension directory
    for file_path in extension_dir.glob("*"):
        if file_path.is_file():
            # Exclude documentation files to keep size down
            if file_path.suffix.lower() not in ['.md']:
                extension_files.append((str(file_path), 'chrome_extension'))
                print(f"[SPEC]   + {file_path.name}")
    
    print(f"[SPEC] Total extension files to embed: {len(extension_files)}")
else:
    print(f"[SPEC] WARNING: Chrome extension directory not found: {extension_dir}")

# Combine all data files
all_data_files = cert_files + extension_files
print(f"[SPEC] Total files to embed: {len(all_data_files)}")

a = Analysis(
    ['install_unified.py'],
    pathex=[],
    binaries=[],
    datas=all_data_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='InstallZTProxy',
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
    uac_admin=True,  # Request admin privileges on startup
)
