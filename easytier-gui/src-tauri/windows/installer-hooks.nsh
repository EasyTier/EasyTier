!define EASYTIER_INSTALLER_SCRIPT "${__FILEDIR__}\installer-processes.ps1"

; Tauri uninstalls the old version on its reinstall page, before PREINSTALL.
; MUI consumes this callback on the first page (Welcome). Opening the installer
; alone does not stop anything; the user must first leave the welcome page.
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE EasyTierPrepareInstall
!define MUI_CUSTOMFUNCTION_GUIINIT EasyTierInstallerGuiInit

Var EasyTierHelper
Var EasyTierInstallerPid
Var EasyTierDone
Var EasyTierFailed

!macro EasyTierPrepare RESTORE
  ${If} $EasyTierHelper != ""
    Return
  ${EndIf}
  InitPluginsDir
  File "/oname=$PLUGINSDIR\installer-processes.ps1" "${EASYTIER_INSTALLER_SCRIPT}"
  System::Call 'kernel32::GetCurrentProcessId() i .r0'
  StrCpy $EasyTierInstallerPid $0
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\installer-processes.ps1" -InstallDir "$INSTDIR" -InstallerPid $EasyTierInstallerPid -RestoreService ${RESTORE}'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Could not close EasyTier:$\r$\n$1" /SD IDOK
    Abort
  ${EndIf}
  IntOp $1 $1 + 0
  ${If} $1 != 0
    System::Call 'kernel32::OpenEventW(i 0x100000, i 0, w "Local\EasyTierInstaller-$EasyTierInstallerPid-done") p .r0'
    StrCpy $EasyTierDone $0
    System::Call 'kernel32::OpenEventW(i 0x100000, i 0, w "Local\EasyTierInstaller-$EasyTierInstallerPid-failed") p .r0'
    StrCpy $EasyTierFailed $0
    ${If} $EasyTierDone == 0
    ${OrIf} $EasyTierFailed == 0
      MessageBox MB_OK|MB_ICONSTOP "Could not wait for EasyTier to finish updating." /SD IDOK
      Abort
    ${EndIf}
    StrCpy $EasyTierHelper 1
  ${EndIf}
!macroend

!macro EasyTierFinish
  ${If} $EasyTierHelper != ""
    System::Call 'kernel32::OpenEventW(i 2, i 0, w "Local\EasyTierInstaller-$EasyTierInstallerPid-finish") p .r0'
    ${If} $0 != 0
      System::Call 'kernel32::SetEvent(p r0)'
      System::Call 'kernel32::CloseHandle(p r0)'
    ${EndIf}
    System::Call 'kernel32::WaitForSingleObject(p $EasyTierDone, i 65000) i .r0'
    System::Call 'kernel32::WaitForSingleObject(p $EasyTierFailed, i 0) i .r1'
    System::Call 'kernel32::CloseHandle(p $EasyTierDone)'
    System::Call 'kernel32::CloseHandle(p $EasyTierFailed)'
    StrCpy $EasyTierHelper ""
    ${If} $0 != 0
    ${OrIf} $1 != 258
      MessageBox MB_OK|MB_ICONSTOP "Could not restore the EasyTier service. Please check its status in Windows Services." /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
!macroend

Function EasyTierPrepareInstall
  !insertmacro EasyTierPrepare 1
FunctionEnd

Function EasyTierInstallerGuiInit
  ; Passive installs skip Welcome, but still run the old uninstaller page.
  ${GetOptions} $CMDLINE "/P" $0
  ${IfNot} ${Errors}
    Call EasyTierPrepareInstall
  ${EndIf}
FunctionEnd

Function un.EasyTierPrepareUninstall
  !insertmacro EasyTierPrepare 0
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  ; Silent installs skip all pages. Also handle a fresh/custom install path.
  Call EasyTierPrepareInstall
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro EasyTierFinish
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Call un.EasyTierPrepareUninstall
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  !insertmacro EasyTierFinish
!macroend
