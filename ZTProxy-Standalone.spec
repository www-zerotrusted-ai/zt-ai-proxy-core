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
    'aiohttp','yarl','multidict','frozenlist','aiosignal',
    'redis','redis.asyncio','redis.connection',
    'openai','httpx','bs4','lxml','lxml.etree','lxml.html',
]
hidden_all = sorted(set(_mitm + _aio + _req + _extra))

# Include interceptor directory as data
datas_items = [
    ('interceptor', 'interceptor'),
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
    excludes=[
        'enterprise',  # Exclude enterprise modules
        'pandas', 'numpy', 'scipy', 'matplotlib',  # Heavy numerical packages
        'boto3', 'botocore', 's3transfer',  # AWS SDK
        'PIL', 'pillow',  # Image processing
        'tkinter', 'tk', 'tcl',  # GUI toolkit
        'pytz', 'tzdata',  # Timezone data
        'IPython', 'jupyter',  # Jupyter/IPython
        'pytest', 'unittest2',  # Testing frameworks
        'pydoc', 'doctest',  # Documentation tools
    ],
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
