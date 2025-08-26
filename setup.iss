
[Setup]
AppName=Email Forensics Analyzer
AppVersion=1.0.0
AppPublisher=EmailForensics
AppPublisherURL=https://github.com/emailforensics
DefaultDirName={autopf}\EmailForensics
DefaultGroupName=Email Forensics
UninstallDisplayIcon={app}\EmailForensics.exe
Compression=lzma2
SolidCompression=yes
OutputDir=dist
OutputBaseFilename=EmailForensics_Setup

[Files]
Source: "dist\EmailForensics.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Email Forensics Analyzer"; Filename: "{app}\EmailForensics.exe"
Name: "{group}\Uninstall Email Forensics"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Email Forensics"; Filename: "{app}\EmailForensics.exe"

[Run]
Filename: "{app}\EmailForensics.exe"; Description: "Launch Email Forensics"; Flags: postinstall nowait skipifsilent
