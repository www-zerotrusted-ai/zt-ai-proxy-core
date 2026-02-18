# -*- mode: python ; coding: utf-8 -*-

"""
PyInstaller spec file for ZTProxy Certificate Installer
Creates a single-file executable with admin elevation.
"""

import sys
from pathlib import Path

block_cipher = None

# Get the project root directory (parent of cert_installer)
project_root = Path(SPECPATH).parent
cert_installer_dir = Path(SPECPATH)

# Data files to include (certificate and chrome extension) - EMBEDDED INTO EXE
datas = []

# Windows certificate format (.cer) - preferred
if (project_root / 'mitmproxy-ca-cert.cer').exists():
    datas.append((str(project_root / 'mitmproxy-ca-cert.cer'), '.'))
    print(f"[SPEC] Embedding certificate: {project_root / 'mitmproxy-ca-cert.cer'}")

# PEM format (fallback)
if (project_root / 'mitmproxy-ca.pem').exists():
    datas.append((str(project_root / 'mitmproxy-ca.pem'), '.'))
    print(f"[SPEC] Embedding certificate: {project_root / 'mitmproxy-ca.pem'}")

# Chrome extension folder
if (project_root / 'chrome_extension').exists():
    datas.append((str(project_root / 'chrome_extension'), 'chrome_extension'))
    print(f"[SPEC] Embedding chrome_extension folder")

# Fallback: other certificate locations
if (cert_installer_dir / 'mitmproxy-ca 5.pem').exists():
    datas.append((str(cert_installer_dir / 'mitmproxy-ca 5.pem'), 'certs'))
if (project_root / 'config' / 'mitmproxy-ca-cert.pem').exists():
    datas.append((str(project_root / 'config' / 'mitmproxy-ca-cert.pem'), 'certs'))

if not datas:
    print("[SPEC] WARNING: No certificate files found to embed!")
else:
    print(f"[SPEC] Total files to embed: {len(datas)}")

a = Analysis(
    ['install_cert.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='InstallZTProxyCert',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Show console for feedback
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path here if you have one
    uac_admin=True,  # Request admin privileges automatically
    uac_uiaccess=False,
)
