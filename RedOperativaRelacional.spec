# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['scripts/red_operativa_relacional_launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=['red_operativa_app', 'app.api', 'app.db', 'app.processing'],
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
    [],
    exclude_binaries=True,
    name='RedOperativaRelacional',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='RedOperativaRelacional',
)
