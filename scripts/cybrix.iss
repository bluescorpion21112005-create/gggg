; Inno Setup script — compiled by scripts/build_windows.ps1 (/DAppVersion=x.y.z)
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6C2B4E0A-7D1F-4C3B-9E57-3A1C8F5D2B90}
AppName=Cybrix
AppVersion={#AppVersion}
AppPublisher=Cybrix
DefaultDirName={autopf}\Cybrix
DefaultGroupName=Cybrix
DisableProgramGroupPage=yes
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=Cybrix-Setup-{#AppVersion}
SetupIconFile=..\presentation\assets\cybrix.ico
UninstallDisplayIcon={app}\cybrix-ai.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
; an update installer started by the app closes the running copy first
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "..\dist\cybrix-ai\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Cybrix"; Filename: "{app}\cybrix-ai.exe"
Name: "{autodesktop}\Cybrix"; Filename: "{app}\cybrix-ai.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\cybrix-ai.exe"; Description: "{cm:LaunchProgram,Cybrix}"; Flags: nowait postinstall skipifsilent
