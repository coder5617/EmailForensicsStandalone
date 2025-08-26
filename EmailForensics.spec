# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['email_forensics_main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['dns.resolver', 'dns.exception', 'email.parser', 'email.utils', 'reportlab.graphics.charts.barcharts', 'reportlab.graphics.charts.lineplots', 'reportlab.graphics.charts.piecharts', 'reportlab.graphics.charts.spider', 'reportlab.graphics.charts.doughnut'],
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
    name='EmailForensics',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version.txt',
)
