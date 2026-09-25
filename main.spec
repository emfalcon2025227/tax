# -*- mode: python ; coding: utf-8 -*-
# ==============================================================================
# PyInstaller Build Specification for Windows 11
# Project: Accounting & Tax Analysis System - Data Entry Application
# Developer: م/ محمود محمد | mahmoud.m@sdi.ae
# ==============================================================================

import sys
import os

block_cipher = None

# OS path separator for datas: ';' on Windows, ':' on Unix
data_sep = ';' if sys.platform.startswith('win') else ':'

# Collected data files: index.html is mandatory for pywebview
datas = [
    ('index.html', '.'),
]

# If .env exists in the directory, bundle it as default fallback
if os.path.exists('.env'):
    datas.append(('.env', '.'))

# Hidden imports necessary for pywebview (Edge WebView2 / WinForms) and Supabase
hiddenimports = [
    'webview',
    'webview.platforms.winforms',
    'webview.platforms.edgechromium',
    'clr',
    'pythonnet',
    'dotenv',
    'supabase',
    'postgrest',
    'gotrue',
    'realtime',
    'storage3',
    'supafunc',
    'decimal',
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
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

# Standalone Single-File Executable Configuration for Windows 11
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='TaxDataEntry_App',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                  # STRICT: --noconsole prevents black terminal window from appearing
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
