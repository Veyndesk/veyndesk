; Veyndesk installer hooks (per-machine install, see tauri.conf.json).
;
; * Windows Firewall rules for the app and the service worker (direct connections, LAN server).
; * The "Veyndesk" service (LocalSystem): runs the host as SYSTEM in the user's session so the
;   UAC prompt and the lock / login screen can be seen and used remotely. With the service
;   installed, the app is only the UI (see crates/service).

!macro VEYNDESK_STOP_SERVICE
  nsExec::Exec 'sc.exe stop Veyndesk'
  Sleep 2000
  ; the worker dies with the service; make sure nothing keeps the .exe locked
  nsExec::Exec 'taskkill /F /IM veyndesk-service.exe'
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; upgrade: the running service would lock veyndesk-service.exe
  !insertmacro VEYNDESK_STOP_SERVICE
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; remove the firewall rule created by installs from before the rename
  nsExec::Exec 'netsh advfirewall firewall delete rule name="VeloDesk"'
  nsExec::Exec 'netsh advfirewall firewall delete rule name="Veyndesk"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="Veyndesk" dir=in action=allow program="$INSTDIR\Veyndesk.exe" enable=yes profile=any'
  nsExec::Exec 'netsh advfirewall firewall add rule name="Veyndesk" dir=in action=allow program="$INSTDIR\veyndesk-service.exe" enable=yes profile=any'

  ; Keep this PC's ID and settings: the service keeps its config in %ProgramData%\Veyndesk
  ; (SYSTEM + Administrators only). Copy the installing user's config the first time.
  ReadEnvStr $0 APPDATA
  ReadEnvStr $1 ProgramData
  ${IfNot} ${FileExists} "$1\Veyndesk\host.json"
  ${AndIf} ${FileExists} "$0\Veyndesk\host.json"
    CreateDirectory "$1\Veyndesk\server"
    CopyFiles /SILENT "$0\Veyndesk\host.json" "$1\Veyndesk"
    CopyFiles /SILENT "$0\Veyndesk\server\*.*" "$1\Veyndesk\server"
  ${EndIf}

  ; Allow services to raise Ctrl+Alt+Del (SendSAS). 1 = services, 3 = services and Ease of Access.
  SetRegView 64
  ReadRegDWORD $2 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "SoftwareSASGeneration"
  ${If} $2 != 1
  ${AndIf} $2 != 3
    WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "SoftwareSASGeneration" 1
  ${EndIf}
  SetRegView lastused

  ; (Re)create the service; on upgrade "create" fails and "config" updates the path.
  nsExec::Exec 'sc.exe create Veyndesk binPath= "\"$INSTDIR\veyndesk-service.exe\" --service" start= auto DisplayName= "Veyndesk"'
  nsExec::Exec 'sc.exe config Veyndesk binPath= "\"$INSTDIR\veyndesk-service.exe\" --service" start= auto'
  nsExec::Exec 'sc.exe description Veyndesk "Veyndesk remote desktop: lets remote sessions see and use the UAC prompt and the login screen."'
  nsExec::Exec 'sc.exe failure Veyndesk reset= 86400 actions= restart/5000/restart/5000/restart/30000'
  nsExec::Exec 'sc.exe start Veyndesk'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VEYNDESK_STOP_SERVICE
  nsExec::Exec 'sc.exe delete Veyndesk'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  nsExec::Exec 'netsh advfirewall firewall delete rule name="Veyndesk"'
  ; %ProgramData%\Veyndesk (ID, settings, logs) is kept, like the per-user config.
!macroend
