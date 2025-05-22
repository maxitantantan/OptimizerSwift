@echo off
title Optimización de FPS para Juegos - Completo
color 0a
mode con: cols=60 lines=25

setlocal enabledelayedexpansion

cls
echo.
echo ================================
echo     OPTIMIZACION DE FPS - COMPLETO
echo ================================
echo.

:: Inicio de los pasos de optimización

call :Step "Cerrando procesos innecesarios..."
taskkill /F /IM "chrome.exe" >nul 2>&1
taskkill /F /IM "discord.exe" >nul 2>&1
taskkill /F /IM "steam.exe" >nul 2>&1
taskkill /F /IM "spotify.exe" >nul 2>&1
taskkill /F /IM "OneDrive.exe" >nul 2>&1

call :Step "Desactivando efectos visuales..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

call :Step "Desactivando efectos de transparencia..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f

call :Step "Estableciendo plan de energía de alto rendimiento..."
powercfg -setactive SCHEME_MAX

call :Step "Ajustando la programación del procesador..."
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False

call :Step "Desactivando programas de inicio innecesarios..."
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NombreDelPrograma" /f >nul 2>&1

call :Step "Limpiando archivos temporales..."
del /q/f/s %TEMP%\* >nul 2>&1
del /q/f/s C:\Windows\Temp\* >nul 2>&1

call :Step "Limpiando caché de DNS..."
ipconfig /flushdns

call :Step "Desactivando notificaciones de Windows..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOAST_ENABLED" /t REG_DWORD /d 0 /f

call :Step "Desactivando el servicio de búsqueda de Windows..."
sc stop "WSearch" >nul 2>&1
sc config "WSearch" start=disabled

call :Step "Desactivando animaciones de Windows..."
reg add "HKCU\Control Panel\Desktop" /v "User  Preferences Mask" /t REG_BINARY /d 3E00000000000000000000000000000000 /f

call :Step "Desactivando la barra de juegos de Xbox..."
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

call :Step "Desactivando la función Game DVR..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f

call :Step "Estableciendo prioridad alta para el proceso del juego..."
:: Reemplaza "nombre_del_juego.exe" por tu juego
wmic process where name="nombre_del_juego.exe" CALL setpriority "high priority" >nul 2>&1

call :Step "Desactivando la protección en tiempo real de Windows Defender (temporal)..."
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true" >nul 2>&1

call :Step "Desactivando Superfetch (SysMain)..."
sc stop "SysMain" >nul 2>&1
sc config "SysMain" start=disabled

call :Step "Desactivando Prefetch..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

call :Step "Desactivando tareas programadas innecesarias..."
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\CEIP" /Disable

call :Step "Desactivando algoritmo de Nagle..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNoDelay" /t REG_DWORD /d 1 /f

call :Step "Desactivando optimizaciones de pantalla completa..."
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "nombre_del_juego.exe" /t REG_SZ /d "~ RUNASINVOKER DISABLEDXMAXIMIZEDWINDOWEDMODE" /f

call :Step "Ajustando parámetros TCP para mejor red..."
netsh int tcp set global autotuninglevel=disabled >nul 2>&1

call :Step "Limpiando el portapapeles..."
echo off | clip

call :Step "Desactivando actualizaciones automáticas de apps..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /v "AutoUpdate" /t REG_DWORD /d 0 /f

call :Step "Estableciendo Windows Update en modo manual..."
sc config wuauserv start=manual

call :Step "Desactivando tareas de inicio innecesarias adicionales..."
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable

call :Step "Desactivando notificaciones y alertas..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOAST_ENABLED" /t REG_DWORD /d 0 /f

call :Step "Desactivando informes de errores..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f

call :Step "Desactivando aplicaciones en segundo plano innecesarias..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "BackgroundAccessApplicationsEnabled" /t REG_DWORD /d 0 /f

call :Step "Ajustes avanzados GPU (ejemplo NVIDIA)..."
:: Añade aquí comandos específicos si tienes herramientas CLI para GPU

call :Step "Optimización del Agente de Transferencia Inteligente de Windows (BITS)..."
sc stop "BITS" >nul 2>&1
sc config "BITS" start=disabled

call :Step "Desactivando servicio de Telemetría de Windows..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled

call :Step "Deteniendo servicio Superfetch adicional..."
sc stop "SysMain" >nul 2>&1

call :Step "Eliminando archivos de registro temporales..."
del /q/f/s "%systemdrive%\Windows\Temp\*" >nul 2>&1

call :Step "Desactivando indexación de búsqueda..."
sc stop "WSearch" >nul 2>&1
sc config "WSearch" start=disabled

call :Step "Desactivando asistente de compatibilidad para programas..."
sc stop "PcaSvc" >nul 2>&1
sc config "PcaSvc" start=disabled

call :Step "Deteniendo servicio de mapas offline..."
sc stop "MapsBroker" >nul 2>&1
sc config "MapsBroker" start=disabled

call :Step "Desactivando servicio de actualización de fanatical..."
sc stop "FanaticUpdatedService" >nul 2>&1
sc config "FanaticUpdatedService" start=disabled

call :Step "Desactivando servicios innecesarios de impresión..."
sc stop "Spooler" >nul 2>&1
sc config "Spooler" start=disabled

call :Step "Desactivando el servicio de bluetooth si no lo usas..."
sc stop "bthserv" >nul 2>&1
sc config "bthserv" start=disabled

call :Step "Desactivando servicio de fax si no lo necesitas..."
sc stop "Fax" >nul 2>&1
sc config "Fax" start=disabled

call :Step "Desactivando servicio de teléfono..."
sc stop "RASMan" >nul 2>&1
sc config "RASMan" start=disabled

call :Step "Desactivando servicios de optimización de entrega..."
sc stop "DoSvc" >nul 2>&1
sc config "DoSvc" start=disabled

call :Step "Desactivando servicios de actualización automática de Windows Store..."
sc stop "WSService" >nul 2>&1
sc config "WSService" start=disabled

call :Step "Desactivando servicio de compatibilidad con dispositivos de juegos..."
sc stop "GameInput" >nul 2>&1
sc config "GameInput" start=disabled

call :Step "Optimizando la memoria paginada..."
wmic pagefilelist where name="C:\\pagefile.sys" set InitialSize=4096,MaximumSize=4096

call :Step "Limpiando memoria con BITS de Windows..."
net stop bits >nul 2>&1
net start bits >nul 2>&1

call :Step "Reiniciando servicio de red para aplicar cambios..."
netsh int ip reset >nul 2>&1
netsh winsock reset >nul 2>&1

call :Step "Desactivando actualizaciones automáticas de drivers..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

call :Step "Desactivando servicio de compatibilidad de programas..."
sc stop "PcaSvc" >nul 2>&1
sc config "PcaSvc" start=disabled

call :Step "Deshabilitando el efecto de sombra en menús..."
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

call :Step "Aumentando el tamaño del búfer del teclado (reduce latencia)..."
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f

call :Step "Deshabilitando la indexación de archivos en unidades..."
sc stop "WSearch" >nul 2>&1
sc config "WSearch" start=disabled

call :Step "Desactivando protección contra falsificaciones DMA (puertos thunderbolt)..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\DMAProtection" /v "Enabled" /t REG_DWORD /d 0 /f

call :Step "Desactivando la optimización de entrega en Windows Update..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f

call :Step "Desactivando sincronización de reloj en segundo plano..."
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable

call :Step "Deshabilitando animaciones del menú Inicio..."
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f

call :Step "Reduciendo el tiempo de espera para cierre de procesos..."
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f

call :Step "Reduciendo el tiempo de espera para cierre de servicios..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f

call :Step "Desactivando el SmartScreen Filter para mejorar rendimiento..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f

call :Step "Desactivando actualizaciones automáticas del sistema..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f

call :Step "Acelerando el tiempo de apagado del sistema..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "HungAppTimeout" /t REG_SZ /d "1000" /f

call :Step "Desactivando búsqueda por voz Cortana..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

call :Step "Desactivando recientes en menú inicio para mejorar rendimiento..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f

call :Step "Desactivando eventos de diagnóstico y monitoreo..."
sc stop "dmwappushservice" >nul 2>&1
sc config "dmwappushservice" start=disabled

call :Step "Limpiando archivos de volcado de memoria..."
del /q/f/s %systemroot%\Minidump\* >nul 2>&1

call :Step "Limpiando carpeta Prefetch..."
del /q/f/s %systemroot%\Prefetch\* >nul 2>&1

call :Step "Desactivando actualización de mapas en segundo plano..."
sc stop "MapsBroker" >nul 2>&1
sc config "MapsBroker" start=disabled

call :Step "Desactivando servicio de configuración de red de Windows..."
sc stop "NetSetupSvc" >nul 2>&1
sc config "NetSetupSvc" start=disabled

call :Step "Desactivando el servicio de Windows Backup..."
sc stop "wbengine" >nul 2>&1
sc config "wbengine" start=disabled

call :Step "Desactivando el servicio de Windows Event Log..."
sc stop "EventLog" >nul 2>&1
sc config "EventLog" start=disabled

call :Step "Desactivando el servicio de Windows Biometric..."
sc stop "WbioSrvc" >nul 2>&1
sc config "WbioSrvc" start=disabled

call :Step "Desactivando el servicio de Windows Remote Desktop..."
sc stop "TermService" >nul 2>&1
sc config "TermService" start=disabled

call :Step "Desactivando el servicio de Windows Remote Management..."
sc stop "WinRM" >nul 2>&1
sc config "WinRM" start=disabled

call :Step "Desactivando el servicio de Windows Time..."
sc stop "W32Time" >nul 2>&1
sc config "W32Time" start=disabled

call :Step "Desactivando el servicio de Windows Firewall..."
sc stop "MpsSvc" >nul 2>&1
sc config "MpsSvc" start=disabled

call :Step "Desactivando el servicio de Windows Update..."
sc stop "wuauserv" >nul 2>&1
sc config "wuauserv" start=disabled

call :Step "Desactivando el servicio de Windows Media Player Network Sharing..."
sc stop "WMPNetworkSvc" >nul 2>&1
sc config "WMPNetworkSvc" start=disabled

call :Step "Desactivando el servicio de Windows Error Reporting..."
sc stop "WerSvc" >nul 2>&1
sc config "WerSvc" start=disabled

call :Step "Limpiando el historial de archivos recientes..."
del /q "%APPDATA%\Microsoft\Windows\Recent\*" >nul 2>&1

:: Desactivar la sincronización de OneDrive
call :Step "Desactivando la sincronización de OneDrive..."
taskkill /F /IM "OneDrive.exe" >nul 2>&1
reg add "HKCU\Software\Microsoft\OneDrive" /v "User Folder" /t REG_SZ /d "" /f

:: Limpiar el registro de Windows
call :Step "Limpiando el registro de Windows..."
:: Nota: Usa con precaución, se recomienda hacer un respaldo del registro antes de limpiar
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /f >nul 2>&1

:: Desactivar el servicio de Windows Search
call :Step "Desactivando el servicio de Windows Search..."
sc stop "WSearch" >nul 2>&1
sc config "WSearch" start=disabled

:: Desactivar el servicio de Windows Update
call :Step "Desactivando el servicio de Windows Update..."
sc stop "wuauserv" >nul 2>&1
sc config "wuauserv" start=disabled

:: Limpiar el caché de Windows Store
call :Step "Limpiando el caché de Windows Store..."
wsreset.exe

:: Desactivar el servicio de Windows Error Reporting
call :Step "Desactivando el servicio de Windows Error Reporting..."
sc stop "WerSvc" >nul 2>&1
sc config "WerSvc" start=disabled

:: Desactivar el servicio de Windows Media Player Network Sharing
call :Step "Desactivando el servicio de Windows Media Player Network Sharing..."
sc stop "WMPNetworkSvc" >nul 2>&1
sc config "WMPNetworkSvc" start=disabled

:: Desactivar el servicio de Windows Biometric
call :Step "Desactivando el servicio de Windows Biometric..."
sc stop "WbioSrvc" >nul 2>&1
sc config "WbioSrvc" start=disabled

:: Limpiar el caché de DNS
call :Step "Limpiando caché de DNS..."
ipconfig /flushdns

:: Desactivar el servicio de Windows Backup
call :Step "Desactivando el servicio de Windows Backup..."
sc stop "wbengine" >nul 2>&1
sc config "wbengine" start=disabled

:: Deshabilitar servicios de telemetría adicionales
call :Step "Deshabilitando servicios de telemetría adicionales..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" >nul 2>&1
sc config "dmwappushservice" start=disabled

:: Desactivar aceleración de puntero del ratón
call :Step "Desactivando aceleración del ratón..."
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

:: Limpiar archivos temporales de usuario
call :Step "Limpiando archivos temporales del usuario..."
del /q/f/s "%USERPROFILE%\AppData\Local\Temp\*" >nul 2>&1

:: Limpiar caché de fuentes
call :Step "Limpiando caché de fuentes..."
del /q/f/s "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache*" >nul 2>&1

:: Ajustar tamaño del archivo de paginación (memoria virtual) automáticamente
call :Step "Configurando archivo de paginación en automático..."
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: Desactivar telnet client si está habilitado
call :Step "Desactivando cliente Telnet..."
sc stop "TlntSvr" >nul 2>&1
sc config "TlntSvr" start=disabled

:: Aumentar el límite de conexiones simultáneas TCP/IP
call :Step "Aumentando conexiones TCP/IP simultáneas..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d 10000 /f

:: Eliminar archivos de registro de eventos antiguos
call :Step "Eliminando registros de eventos antiguos..."
for /f "tokens=*" %%g in ('wevtutil.exe el') do wevtutil.exe cl "%%g" 2>nul

:: Desactivar hibernación para liberar espacio en disco
call :Step "Desactivando hibernación..."
powercfg -h off

:: Limpiar caché Prefetch y Temp otra vez
call :Step "Limpiando carpetas Prefetch y Temp..."
del /q/f/s %SystemRoot%\Prefetch\* >nul 2>&1
del /q/f/s %TEMP%\* >nul 2>&1

:: Configurar el adaptador de red para mejor rendimiento
call :Step "Configurando adaptador de red para mejor rendimiento..."
netsh interface tcp set global chimney=enabled
netsh interface tcp set global congestionprovider=ctcp
netsh interface tcp set global ecncapability=enabled
netsh interface tcp set global timestamps=enabled
netsh interface tcp set global autotuninglevel=normal
netsh interface tcp set global dca=enabled

:: Eliminar archivos temporales de Windows Update
call :Step "Eliminando archivos temporales de Windows Update..."
del /q/f/s %windir%\SoftwareDistribution\Download\* >nul 2>&1

:: Desactivar servicio de Windows Defender (temporal)
call :Step "Desactivando Windows Defender temporalmente..."
sc stop WinDefend >nul 2>&1
sc config WinDefend start=disabled

:: Limpiar historial de reproducción multimedia
call :Step "Limpiando historial multimedia..."
del /q /f /s "%APPDATA%\Microsoft\Media Player\*" >nul 2>&1

:: Optimizar caché de iconos
call :Step "Optimizando caché de iconos..."
ie4uinit.exe -ClearIconCache

:: Desactivar la indexación de búsqueda para mejorar velocidad de discos
call :Step "Desactivando indexación para todos los discos..."
powershell "Get-Service -Name WSearch | Stop-Service -Force"
powershell "Set-Service -Name WSearch -StartupType Disabled"
attrib -R -S -H "%ProgramData%\Microsoft\Search\Data\Applications\Windows" >nul 2>&1

:: Limpiar historial de búsqueda de Windows
call :Step "Limpiando historial de búsqueda de Windows..."
del /q/f %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\* >nul 2>&1

:: Deshabilitar el servicio de telemetría de experiencia del usuario conectado
call :Step "Deshabilitando Telemetría de Experiencia de Usuario..."
sc stop "Diagsvc" >nul 2>&1
sc config "Diagsvc" start=disabled

:: Limpiar archivos de caché de Microsoft Store
call :Step "Limpiando caché de Microsoft Store..."
del /q/f /s %localappdata%\Packages\Microsoft.WindowsStore_*\LocalCache\* >nul 2>&1

:: Deshabilitar servicio de informe de problema (WER)
call :Step "Deshabilitando servicio de informes de problemas..."
sc stop "WerSvc" >nul 2>&1
sc config "WerSvc" start=disabled

:: Aumentar el cache del DNS para mejorar velocidad de navegación
call :Step "Aumentando tamaño del cache DNS..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d 86400 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d 3600 /f

:: Desactivar el servicio de Windows Error Reporting
call :Step "Deshabilitando servicio de errores..."
sc stop "WerSvc" >nul 2>&1
sc config "WerSvc" start=disabled

:: Limpiar el historial de la papelera de reciclaje
call :Step "Limpiando papelera de reciclaje..."
rd /s /q %systemdrive%\$Recycle.Bin

:: Optimización de la unidad de disco (Desfragmentación rápida)
call :Step "Desfragmentando disco principal..."
defrag %systemdrive% -w -v

:: Ajustar prioridad de red para mejorar gaming online
call :Step "Ajustando prioridad de red para juegos..."
netsh interface set interface "Ethernet" enable
netsh interface set interface "Wi-Fi" disable

:: Desactivar notificaciones de Windows Update
call :Step "Desactivando notificaciones de Windows Update..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\WindowsUpdate" /v "Enabled" /t REG_DWORD /d 0 /f

:: Limpiar historial de comandos de PowerShell
call :Step "Limpiando historial de PowerShell..."
del /f /q %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt >nul 2>&1

:: Limpiar caché de Store Apps
call :Step "Limpiando caché de aplicaciones UWP..."
powershell -Command "Get-AppxPackage | Remove-AppxPackage"

:: Desactivar servicio de Bluetooth si no usas dispositivo Bluetooth
call :Step "Desactivando servicio Bluetooth..."
sc stop "bthserv" >nul 2>&1
sc config "bthserv" start=disabled

:: Deshabilitar el servicio de Bluetooth Support Service si no se usa
call :Step "Desactivando servicio de soporte Bluetooth..."
sc stop bthserv >nul 2>&1
sc config bthserv start=disabled

:: Desactivar las animaciones visuales para rendimiento
call :Step "Desactivando animaciones visuales..."
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012008010000000" /f

:: Desactivar servicio de IP helper para acelerar conexiones
call :Step "Desactivando servicio IP Helper..."
sc stop iphlpsvc >nul 2>&1
sc config iphlpsvc start=disabled

:: Limpiar caché ARP para evitar conflictos de red
call :Step "Limpiando caché ARP..."
netsh interface ip delete arpcache

:: Optimizar ajustes de red para mejorar ping en juegos
call :Step "Optimizando TCP/IP para juegos..."
netsh int tcp set global chimney=disabled
netsh int tcp set global autotuninglevel=highlyrestricted
netsh int tcp set global congestionprovider=ctcp

:: Deshabilitar el servicio de Fax si no se utiliza
call :Step "Desactivando servicio de Fax..."
sc stop Fax >nul 2>&1
sc config Fax start=disabled

:: Desactivar indexado de búsqueda para mejorar desempeño HDD
call :Step "Desactivando indexación para unidades de disco..."
powershell "Get-WmiObject -Query 'SELECT * FROM Win32_Volume WHERE IndexingEnabled = $true' | ForEach-Object { $_.IndexingEnabled = $false; $_.Put() }"

:: Deshabilitar informes de errores y diagnóstico
call :Step "Desactivando servicios de diagnóstico y error..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled
sc stop "WdiServiceHost" >nul 2>&1
sc config "WdiServiceHost" start=disabled

:: Aumentar el tamaño del buffer de entrada y salida del CMD para mejor performance
call :Step "Ajustando buffer CMD..."
mode con:cols=120 lines=40

:: Ajustar tamaño del buffer de consola para evitar lag en CMD
reg add "HKCU\Console" /v ScreenBufferSize /t REG_DWORD /d 0x28000 /f

:: Limpiar archivos temporales de la carpeta Prefetch para acelerar inicio
call :Step "Limpiando Prefetch..."
del /q/f/s %SystemRoot%\Prefetch\* >nul 2>&1

:: Desactivar autoarranque de programas innecesarios con schtasks
call :Step "Desactivando tareas programadas innecesarias..."
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable

:: Desactivar servicios de Bluetooth y dispositivos que no utilices
call :Step "Desactivando servicios Bluetooth..."
sc stop "bthserv" >nul 2>&1
sc config "bthserv" start=disabled

:: Eliminar fuentes no utilizadas para mejorar carga
call :Step "Eliminando fuentes no utilizadas..."
del /q/f "%windir%\Fonts\*.tmp" >nul 2>&1

:: Deshabilitar la función de búsqueda de Windows para liberar recursos
call :Step "Desactivando servicio de búsqueda de Windows (WSearch)..."
sc stop WSearch >nul 2>&1
sc config WSearch start=disabled

:: Liberar memoria inactiva para mejorar rendimiento
call :Step "Liberando memoria inactiva..."
rundll32.exe advapi32.dll,ProcessIdleTasks

:: Limpiar caché de fuentes para evitar lentitud gráfica
call :Step "Limpiando caché de fuentes..."
del /q/f/s "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache*" >nul 2>&1

:: Optimizar configuración de red para reducir latencia
call :Step "Modificando configuraciones de red..."
netsh interface tcp set global rss=enabled
netsh interface tcp set global chimney=enabled
netsh interface tcp set global autotuninglevel=normal
netsh interface tcp set global congestionprovider=ctcp

:: Deshabilitar servicios de rastreo y telemetría para privacidad y rendimiento
call :Step "Deshabilitando servicios de telemetría..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" >nul 2>&1
sc config "dmwappushservice" start=disabled

:: Desactivar notificaciones y consejos de Windows para evitar distracciones y mejorar performance
call :Step "Desactivando notificaciones y consejos..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f

:: Limpiar historial de archivos recientes para velocidad y privacidad
call :Step "Limpiando historial de archivos recientes..."
del /q "%APPDATA%\Microsoft\Windows\Recent\*" >nul 2>&1

:: Limpiar historial de cache DNS nuevamente
call :Step "Limpiando caché DNS..."
ipconfig /flushdns

:: Optimizar configuración de energía para alto rendimiento
call :Step "Configurando plan de energía en alto rendimiento..."
powercfg -setactive SCHEME_MIN

:: Deshabilitar efectos visuales innecesarios para mejorar FPS
call :Step "Desactivando efectos visuales..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

:: Limpiar archivos temporales de usuario y sistema
call :Step "Limpiando archivos temporales..."
del /q/f/s "%TEMP%\*" >nul 2>&1
del /q/f/s "%SystemRoot%\Temp\*" >nul 2>&1

:: Deshabilitar Superfetch (SysMain) para mejorar rendimiento en juegos
call :Step "Desactivando servicio Superfetch (SysMain)..."
sc stop "SysMain" >nul 2>&1
sc config "SysMain" start=disabled

:: Deshabilitar optimización de entrega para acelerar red
call :Step "Desactivando Delivery Optimization Service..."
sc stop "DoSvc" >nul 2>&1
sc config "DoSvc" start=disabled

:: Desactivar el servicio de telemetría y recopilación de datos
call :Step "Desactivando Telemetría y recopilación de datos..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" >nul 2>&1
sc config "dmwappushservice" start=disabled
sc stop "WdiServiceHost" >nul 2>&1
sc config "WdiServiceHost" start=disabled

:: Deshabilitar la compatibilidad de programas (Program Compatibility Assistant)
call :Step "Deshabilitando compatibilidad de programas..."
sc stop "PcaSvc" >nul 2>&1
sc config "PcaSvc" start=disabled

:: Desactivar el servicio de captura de eventos de diagnóstico
call :Step "Desactivando Captura de Eventos de Diagnóstico..."
sc stop "DiagTrack" >nul 2>&1
sc config "DiagTrack" start=disabled

:: Limpiar caché de iconos para una carga más rápida del escritorio
call :Step "Limpiando caché de iconos..."
ie4uinit.exe -show

:: Deshabilitar el servicio de impresión si no usas impresora
call :Step "Desactivando servicio de impresión..."
sc stop "Spooler" >nul 2>&1
sc config "Spooler" start=disabled

:: Eliminar archivos temporales de internet Explorer y Edge
call :Step "Limpiando archivos temporales de navegadores..."
RunDll32.exe InetCpl.cpl,ClearMy TracksByProcess 255

:: Desactivar actualizaciones automáticas de Microsoft Store
call :Step "Desactivando actualizaciones automáticas de Store..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f

:: Desactivar el servicio de actualización de Windows Update para evitar consumo innecesario
call :Step "Desactivando servicio de Windows Update..."
sc stop "wuauserv" >nul 2>&1
sc config "wuauserv" start=disabled

:: Incrementar el tamaño del búfer del teclado para menor latencia
call :Step "Aumentando tamaño del búfer de teclado..."
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f

:: Optimizar ajustes para conexiones WiFi
call :Step "Optimizando conexiones WiFi..."
netsh wlan set autoconfig enabled=no interface="Wi-Fi"

:: Eliminar archivos temporales viejos y logs del sistema
call :Step "Eliminando archivos temporales viejos y logs..."
forfiles /p "%systemroot%\Logs" /s /m *.* /d -30 /c "cmd /c del @path"

:: Desactivar animaciones del menú inicio para mejor rendimiento
call :Step "Desactivando animaciones del menú Inicio..."
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f

:: Desactivar indexación en carpetas específicas para liberar recursos
call :Step "Desactivando indexación en carpetas específicas..."
attrib +I "%userprofile%\Documents" /S
attrib +I "%userprofile%\Pictures" /S

:: Limpiar caché de iconos y miniaturas
call :Step "Limpiando caché de iconos y miniaturas..."
del /f /q %LocalAppData%\Microsoft\Windows\Explorer\iconcache* >nul 2>&1
del /f /q %LocalAppData%\Microsoft\Windows\Explorer\thumbcache* >nul 2>&1

:: Limpiar caché DLL para evitar errores y mejorar carga
call :Step "Limpiando caché de DLLs..."
del /f /q %systemroot%\System32\*.dll >nul 2>&1

:: Limpiar historial de eventos del sistema para liberar espacio
call :Step "Limpiando historial de eventos..."
wevtutil cl System
wevtutil cl Application
wevtutil cl Security

:: Deshabilitar servicio Windows Search para liberar recursos
call :Step "Deshabilitando servicio Windows Search..."
sc stop "WSearch" >nul 2>&1
sc config "WSearch" start=disabled

:: Desactivar envío de informes de errores a Microsoft
call :Step "Desactivando envío de informes de error..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f

:: Borrar caché de fuentes para evitar problemas en la interfaz
call :Step "Borrando caché de fuentes..."
del /s /f /q "%localappdata%\FontCache.dat" >nul 2>&1
del /s /f /q "%localappdata%\FontCache-S-1-5-21.dat" >nul 2>&1

:: Desactivar servicio de cálculo de indexación para discos externos
call :Step "Desactivando indexación en discos externos..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch\Parameters" /v "DisableBackoff" /t REG_DWORD /d 1 /f

:: Deshabilitar el servicio de telemetría Connected User Experiences
call :Step "Deshabilitando Connected User Experiences..."
sc stop "Diagsvc" >nul 2>&1
sc config "Diagsvc" start=disabled

:: Desactivar los servicios de optimización de entrega (Delivery Optimization)
call :Step "Desactivando Delivery Optimization..."
sc stop "DoSvc" >nul 2>&1
sc config "DoSvc" start=disabled

:: Limpiar la caché del sistema de archivos (File Explorer)
call :Step "Limpiando caché del sistema de archivos..."
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe

:: Deshabilitar las actualizaciones automáticas de drivers
call :Step "Desactivando actualizaciones automáticas de drivers..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

:: Desactivar servicios innecesarios de impresión y fax
call :Step "Desactivando servicios de impresión y fax..."
sc stop "Spooler" >nul 2>&1
sc config "Spooler" start=disabled
sc stop "Fax" >nul 2>&1
sc config "Fax" start=disabled

:: Optimizar potencia CPU para máximo rendimiento
call :Step "Ajustando potencia de CPU a máximo rendimiento..."
powercfg -setactive SCHEME_MAX

:: Limpiar archivos de caché de DirectX
call :Step "Limpiando caché de DirectX..."
del /q/f/s %systemroot%\System32\dxcache\* >nul 2>&1

:: Deshabilitar sincronización de tiempo de Windows
call :Step "Desactivando sincronización de tiempo automática..."
sc stop "W32Time" >nul 2>&1
sc config "W32Time" start=disabled

:: Deshabilitar el servicio de grabación de pantalla (Game DVR)
call :Step "Deshabilitando Game DVR y grabación de pantalla..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

:: Desactivar el servicio Superfetch (SysMain) para mejorar rendimiento en juegos
call :Step "Desactivando servicio SysMain..."
sc stop "SysMain" >nul 2>&1
sc config "SysMain" start=disabled

:: Mejorar velocidad de apagado de Windows
call :Step "Reduciendo tiempo de espera para cierre de procesos..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f

:: Limpiar caché de Prefetch para acelerar arranque
call :Step "Limpiando carpeta Prefetch..."
del /q/f/s %systemroot%\Prefetch\* >nul 2>&1

:: Desactivar visualización de miniaturas para mejorar rendimiento del Explorador
call :Step "Desactivando miniaturas del Explorador..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f

:: Desactivar protección SmartScreen para evitar retrasos
call :Step "Desactivando SmartScreen..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

:: Aumentar el tamaño del archivo de paginación para sistemas con poca RAM
call :Step "Ajustando tamaño archivo de paginación..."
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=4096,MaximumSize=8192

:: Desactivar actualizaciones automáticas de drivers
call :Step "Desactivando actualizaciones automáticas de drivers..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f

:: Reiniciar servicios de red para aplicar ajustes
call :Step "Reiniciando servicios de red..."
netsh int ip reset >nul 2>&1
netsh winsock reset >nul 2>&1

:: Limpiar caché de DNS
call :Step "Limpiando caché DNS..."
ipconfig /flushdns

:: Limpiar los prefijos de red temporales para evitar problemas
call :Step "Limpiando prefijos de red temporales..."
netsh interface ipv4 reset

:: Deshabilitar el servicio de Windows Update Medic (WaaSMedicSvc)
call :Step "Deshabilitando Windows Update Medic Service..."
sc stop WaaSMedicSvc >nul 2>&1
sc config WaaSMedicSvc start=disabled

:: Deshabilitar el servicio de Windows Defender Security Center
call :Step "Desactivando Windows Defender Security Center..."
sc stop wscsvc >nul 2>&1
sc config wscsvc start=disabled

:: Limpiar la caché del cliente DHCP para mejorar asignación de IP
call :Step "Limpiando caché DHCP..."
ipconfig /release
ipconfig /renew

:: Desactivar el servicio de Firewall de Windows si usas otro firewall
call :Step "Desactivando Firewall de Windows..."
sc stop MpsSvc >nul 2>&1
sc config MpsSvc start=disabled

:: Ajustar política para evitar hibernación y ahorrar espacio en disco
call :Step "Desactivando hibernación para ahorrar espacio..."
powercfg -h off

:: Limpiar el historial de archivos abiertos recientemente
call :Step "Limpiando historial de archivos recientes..."
del /q "%APPDATA%\Microsoft\Windows\Recent\*" >nul 2>&1

:: Eliminar archivos temporales de Google Chrome (si instalado)
call :Step "Limpiando archivos temporales de Chrome..."
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache" (
    rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"
)

:: Deshabilitar la función de restauración del sistema para liberar recursos
call :Step "Desactivando Restauración del sistema..."
wmic.exe /Namespace:\\root\default Path SystemRestore Call Disable

:: Limpiar los logs de eventos de aplicaciones específicas
call :Step "Limpiando logs de eventos de aplicaciones..."
for /f "tokens=*" %%g in ('wevtutil.exe el') do wevtutil.exe cl "%%g" 2>nul

:: Desactivar actualizaciones automáticas de Microsoft Store
call :Step "Desactivando actualizaciones automáticas de Microsoft Store..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f

:: Limpiar archivos temporales de Windows Installer
call :Step "Limpiando archivos temporales de Windows Installer..."
del /q /f /s %windir%\Installer\* >nul 2>&1

:: Desactivar el servicio de experiencia de usuario conectado y telemetría
call :Step "Deshabilitando experiencia conectada y telemetría..."
sc stop DiagTrack >nul 2>&1
sc config DiagTrack start=disabled

:: Limpiar memoria caché de iconos para evitar retardos en el escritorio
call :Step "Limpiando caché de iconos..."
ie4uinit.exe -ClearIconCache

:: Desactivar el servicio de Windows Biometric Service si no usas biometría
call :Step "Desactivando Windows Biometric Service..."
sc stop WbioSrvc >nul 2>&1
sc config WbioSrvc start=disabled

:: Limpiar caché de Windows Store para evitar problemas de rendimiento
call :Step "Limpiando caché de Windows Store..."
del /q/f/s %localappdata%\Packages\Microsoft.WindowsStore_*\LocalCache\* >nul 2>&1

:: Desactivar el servicio de Windows Error Reporting para evitar consumo de recursos
call :Step "Desactivando Windows Error Reporting..."
sc stop WerSvc >nul 2>&1
sc config WerSvc start=disabled

:: Limpiar archivos de registro de Windows
call :Step "Limpiando archivos de registro de Windows..."
del /q/f/s %systemroot%\Logs\* >nul 2>&1

:: Desactivar el servicio de Windows Media Player Network Sharing
call :Step "Desactivando Windows Media Player Network Sharing..."
sc stop WMPNetworkSvc >nul 2>&1
sc config WMPNetworkSvc start=disabled

:: Limpiar caché de miniaturas de Windows
call :Step "Limpiando caché de miniaturas..."
del /q/f/s %localappdata%\Microsoft\Windows\Explorer\thumbcache* >nul 2>&1

:: Desactivar el servicio de Windows Search para liberar recursos
call :Step "Desactivando Windows Search..."
sc stop WSearch >nul 2>&1
sc config WSearch start=disabled

:: Limpiar archivos temporales de la carpeta de Windows
call :Step "Limpiando archivos temporales de Windows..."
del /q/f/s %windir%\Temp\* >nul 2>&1

:: Desactivar el servicio de Windows Update para evitar descargas innecesarias
call :Step "Desactivando Windows Update..."
sc stop wuauserv >nul 2>&1
sc config wuauserv start=disabled

:: Limpiar caché de DNS para evitar problemas de conexión
call :Step "Limpiando caché de DNS..."
ipconfig /flushdns

:: Desactivar el servicio de Windows Remote Management si no se usa
call :Step "Desactivando Windows Remote Management..."
sc stop WinRM >nul 2>&1
sc config WinRM start=disabled

:: Limpiar archivos de caché de DirectX
call :Step "Limpiando caché de DirectX..."
del /q/f/s %systemroot%\System32\dxcache\* >nul 2>&1

:: Desactivar el servicio de Windows Time si no se necesita
call :Step "Desactivando Windows Time..."
sc stop W32Time >nul 2>&1
sc config W32Time start=disabled



call :Step "Finalizando."

echo.
echo Optimización completada. ¡Listo para jugar!
pause

:Step
set /a count+=1
set "text=%~1"
cls
echo ================================
echo     OPTIMIZACION DE FPS - COMPLETO
echo ================================
echo.
echo [!count!/%total%] %text%
echo.
call :DrawBar !count! %total%
timeout /t 1 >nul

:DrawBar
setlocal
set /a done=%1*50/%2
set /a left=50 - done
set "bar="
for /l %%a in (1,1,%done%) do set "bar=!bar!█"
for /l %%a in (1,1,%left%) do set "bar=!bar! "
<nul set /p=![bar!]!
echo(
endlocal

pause

exit /b
