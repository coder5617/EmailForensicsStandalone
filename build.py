"""
build.py - Build script for Email Forensics Desktop App
Creates a standalone executable using PyInstaller
"""

import os
import sys
import shutil
import platform
from pathlib import Path

def clean_build():
    """Clean previous build artifacts"""
    dirs_to_remove = ['build', 'dist', '__pycache__']
    files_to_remove = ['*.spec']
    
    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"Removed {dir_name}/")
    
    for pattern in files_to_remove:
        import glob
        for file in glob.glob(pattern):
            os.remove(file)
            print(f"Removed {file}")

def build_app():
    """Build the application using PyInstaller"""
    
    # Determine platform-specific options
    system = platform.system()
    
    # Base PyInstaller command
    cmd = [
        'pyinstaller',
        '--name=EmailForensics',
        '--onefile',  # Single file executable
        '--windowed',  # No console window
        '--clean',  # Clean PyInstaller cache
    ]
    
    # Add icon if available
    icon_file = 'icon.ico' if system == 'Windows' else 'icon.icns'
    if os.path.exists(icon_file):
        cmd.append(f'--icon={icon_file}')
    
    # Add version file for Windows
    if system == 'Windows' and os.path.exists('version.txt'):
        cmd.append('--version-file=version.txt')
    
    # Hidden imports that PyInstaller might miss
    hidden_imports = [
        'dns.resolver',
        'dns.exception',
        'email.parser',
        'email.utils',
        'reportlab.graphics.charts.barcharts',
        'reportlab.graphics.charts.lineplots',
        'reportlab.graphics.charts.piecharts',
        'reportlab.graphics.charts.spider',
        'reportlab.graphics.charts.doughnut',
    ]
    
    for imp in hidden_imports:
        cmd.append(f'--hidden-import={imp}')
    
    # Add data files if needed
    # cmd.append('--add-data=resources;resources')
    
    # Main script
    cmd.append('email_forensics_main.py')
    
    # Convert to string and execute
    cmd_str = ' '.join(cmd)
    print(f"Building with command: {cmd_str}")
    
    return os.system(cmd_str)

def create_installer():
    """Create an installer for the built application"""
    system = platform.system()
    
    if system == 'Windows':
        create_windows_installer()
    elif system == 'Darwin':  # macOS
        create_macos_installer()
    else:  # Linux
        create_linux_package()

def create_windows_installer():
    """Create Windows installer using Inno Setup or NSIS"""
    
    # Inno Setup script
    inno_script = """
[Setup]
AppName=Email Forensics Analyzer
AppVersion=1.0.0
AppPublisher=EmailForensics
AppPublisherURL=https://github.com/emailforensics
DefaultDirName={autopf}\\EmailForensics
DefaultGroupName=Email Forensics
UninstallDisplayIcon={app}\\EmailForensics.exe
Compression=lzma2
SolidCompression=yes
OutputDir=dist
OutputBaseFilename=EmailForensics_Setup

[Files]
Source: "dist\\EmailForensics.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\\Email Forensics Analyzer"; Filename: "{app}\\EmailForensics.exe"
Name: "{group}\\Uninstall Email Forensics"; Filename: "{uninstallexe}"
Name: "{autodesktop}\\Email Forensics"; Filename: "{app}\\EmailForensics.exe"

[Run]
Filename: "{app}\\EmailForensics.exe"; Description: "Launch Email Forensics"; Flags: postinstall nowait skipifsilent
"""
    
    with open('setup.iss', 'w') as f:
        f.write(inno_script)
    
    print("Created Inno Setup script: setup.iss")
    print("To create installer, run: iscc setup.iss")

def create_macos_installer():
    """Create macOS .app bundle and DMG"""
    
    print("Creating macOS app bundle...")
    
    # Create .app structure
    app_path = Path('dist/EmailForensics.app')
    contents = app_path / 'Contents'
    macos = contents / 'MacOS'
    resources = contents / 'Resources'
    
    # Create directories
    macos.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)
    
    # Move executable to MacOS folder
    if Path('dist/EmailForensics').exists():
        shutil.move('dist/EmailForensics', macos / 'EmailForensics')
    
    # Create Info.plist
    info_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Email Forensics</string>
    <key>CFBundleDisplayName</key>
    <string>Email Forensics Analyzer</string>
    <key>CFBundleIdentifier</key>
    <string>com.emailforensics.analyzer</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleExecutable</key>
    <string>EmailForensics</string>
</dict>
</plist>"""
    
    with open(contents / 'Info.plist', 'w') as f:
        f.write(info_plist)
    
    print("macOS app bundle created")
    print("To create DMG, use: hdiutil create -volname EmailForensics -srcfolder dist/EmailForensics.app -ov -format UDZO EmailForensics.dmg")

def create_linux_package():
    """Create Linux AppImage or .deb package"""
    
    # Create .desktop file
    desktop_file = """[Desktop Entry]
Name=Email Forensics Analyzer
Comment=Analyze email headers for authentication and security
Exec=EmailForensics
Icon=email-forensics
Type=Application
Categories=Network;Security;
"""
    
    with open('emailforensics.desktop', 'w') as f:
        f.write(desktop_file)
    
    print("Created desktop file: emailforensics.desktop")
    print("To create AppImage, use appimagetool")
    print("To create .deb package, use dpkg-deb")

def create_version_file():
    """Create version file for Windows"""
    version_info = """
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'EmailForensics'),
        StringStruct(u'FileDescription', u'Email Forensics Analyzer'),
        StringStruct(u'FileVersion', u'1.0.0.0'),
        StringStruct(u'InternalName', u'EmailForensics'),
        StringStruct(u'LegalCopyright', u'Copyright 2024'),
        StringStruct(u'OriginalFilename', u'EmailForensics.exe'),
        StringStruct(u'ProductName', u'Email Forensics Analyzer'),
        StringStruct(u'ProductVersion', u'1.0.0.0')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""
    
    with open('version.txt', 'w') as f:
        f.write(version_info)
    
    print("Created version file: version.txt")

def main():
    """Main build process"""
    print("=" * 60)
    print("Email Forensics Desktop App - Build Script")
    print("=" * 60)
    
    # Clean previous builds
    print("\n1. Cleaning previous builds...")
    clean_build()
    
    # Create version file for Windows
    if platform.system() == 'Windows':
        print("\n2. Creating version file...")
        create_version_file()
    
    # Build the application
    print("\n3. Building application...")
    result = build_app()
    
    if result == 0:
        print("\n✅ Build successful!")
        
        # Create installer
        print("\n4. Creating installer...")
        create_installer()
        
        print("\n" + "=" * 60)
        print("Build complete! Check the 'dist' folder for the executable.")
        print("=" * 60)
    else:
        print("\n❌ Build failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()