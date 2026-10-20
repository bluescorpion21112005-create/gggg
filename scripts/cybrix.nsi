; NSIS installer — built on Linux by scripts/build_windows_wine.sh (makensis -DAppVersion=x.y.z).
; Same result as scripts/cybrix.iss (used on Windows): Start-menu entry, optional desktop icon,
; uninstaller, closes a running copy first. Installs per user (no UAC prompt) into
; %LOCALAPPDATA%\Programs\Cybrix.
Unicode true
!ifndef AppVersion
  !define AppVersion "0.0.0"
!endif
!ifndef AppDir
  !define AppDir "..\dist\cybrix-ai"
!endif
!ifndef OutDir
  !define OutDir "..\dist"
!endif
!define UninstKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cybrix"

!include "MUI2.nsh"

Name "Cybrix"
OutFile "${OutDir}\Cybrix-Setup-${AppVersion}.exe"
InstallDir "$LOCALAPPDATA\Programs\Cybrix"
InstallDirRegKey HKCU "Software\Cybrix" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ManifestDPIAware true
VIProductVersion "${AppVersion}.0"
VIAddVersionKey "ProductName" "Cybrix"
VIAddVersionKey "FileDescription" "Cybrix setup"
VIAddVersionKey "FileVersion" "${AppVersion}"
VIAddVersionKey "ProductVersion" "${AppVersion}"
VIAddVersionKey "CompanyName" "Cybrix"
VIAddVersionKey "LegalCopyright" "Cybrix"

!define MUI_ICON "..\presentation\assets\cybrix.ico"
!define MUI_UNICON "..\presentation\assets\cybrix.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\cybrix-ai.exe"
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Desktop shortcut"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION DesktopShortcut

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "Uzbek"

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Function DesktopShortcut
  CreateShortcut "$DESKTOP\Cybrix.lnk" "$INSTDIR\cybrix-ai.exe"
FunctionEnd

Section "Cybrix" SecMain
  SectionIn RO
  ; an update started from the app: close the running copy so its files can be replaced
  nsExec::Exec 'taskkill /F /IM cybrix-ai.exe'
  Sleep 500
  SetOutPath "$INSTDIR"
  RMDir /r "$INSTDIR\_internal"            ; drop libraries of the previous version
  File /r "${AppDir}\*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortcut "$SMPROGRAMS\Cybrix.lnk" "$INSTDIR\cybrix-ai.exe"
  WriteRegStr HKCU "Software\Cybrix" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UninstKey}" "DisplayName" "Cybrix"
  WriteRegStr HKCU "${UninstKey}" "DisplayVersion" "${AppVersion}"
  WriteRegStr HKCU "${UninstKey}" "Publisher" "Cybrix"
  WriteRegStr HKCU "${UninstKey}" "DisplayIcon" "$INSTDIR\cybrix-ai.exe"
  WriteRegStr HKCU "${UninstKey}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UninstKey}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UninstKey}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UninstKey}" "NoModify" 1
  WriteRegDWORD HKCU "${UninstKey}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /F /IM cybrix-ai.exe'
  Delete "$SMPROGRAMS\Cybrix.lnk"
  Delete "$DESKTOP\Cybrix.lnk"
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\cybrix-ai.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"                          ; only if empty: user data lives in %APPDATA%, not here
  DeleteRegKey HKCU "${UninstKey}"
  DeleteRegKey HKCU "Software\Cybrix"
SectionEnd
