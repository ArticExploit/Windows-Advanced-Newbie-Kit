# --- Ensure script is running as administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "Restarting script as administrator..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "User cancelled elevation. Exiting." -ForegroundColor Red
    }
    exit
}

function Pause {
    Write-Host ""
    Write-Host "Press Enter to return..." -ForegroundColor Yellow
    $null = Read-Host
}

function Show-Header ($title, $width=50) {
    Clear-Host
    $line = ('=' * $width)
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    $centered = $title.PadLeft(($width + $title.Length) / 2).PadRight($width)
    Write-Host $centered -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Show-Header "Windows Advanced Newbie Kit"
    Write-Host "   [1] Network"
    Write-Host "   [2] System"
    Write-Host "   [3] Printer"
    Write-Host "   [4] Disk"
    Write-Host "   [0] Exit"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-4,0] : " -NoNewline
}

function Show-NetworkMenu {
    Show-Header "Network"
    Write-Host "   [1] Flush DNS"
    Write-Host "   [2] Show IP Config"
    Write-Host "   [3] Open Advanced Firewall"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-3,0] : " -NoNewline
}

function Show-SystemMenu {
    Show-Header "System"
    Write-Host "   [1] Show System Info"
    Write-Host "   [2] Restart File Explorer"
    Write-Host "   [3] Open Device Manager"
    Write-Host "   [4] Reset Windows Update"
    Write-Host "   [5] Force Time Sync"
    Write-Host "   [6] Create and Open Battery Report"
    Write-Host "   [7] Set Services to Recommended Startup"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-7,0] : " -NoNewline
}


function Show-PrinterMenu {
    Show-Header "Printer"
    Write-Host "   [1] Restart Spooler Service"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1,0] : " -NoNewline
}

function Show-DiskMenu {
    Show-Header "Disk"
    Write-Host "   [1] Open Disk Management"
    Write-Host "   [2] Show Disk Space"
    Write-Host "   [3] Run Disk Cleanup"
    Write-Host "   [4] Clean Temporary Files"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-4,0] : " -NoNewline
}

function Set-ServicesRecommended {
    Write-Host ""
    Write-Host "Setting services to recommended startup types..." -ForegroundColor Yellow

    $services = @(
        @{Name="AJRouter";StartupType="Disabled"}
        @{Name="ALG";StartupType="Manual"}
        @{Name="AppIDSvc";StartupType="Manual"}
        @{Name="AppMgmt";StartupType="Manual"}
        @{Name="AppReadiness";StartupType="Manual"}
        @{Name="AppVClient";StartupType="Disabled"}
        @{Name="AppXSvc";StartupType="Manual"}
        @{Name="Appinfo";StartupType="Manual"}
        @{Name="AssignedAccessManagerSvc";StartupType="Disabled"}
        @{Name="AudioEndpointBuilder";StartupType="Automatic"}
        @{Name="AudioSrv";StartupType="Automatic"}
        @{Name="Audiosrv";StartupType="Automatic"}
        @{Name="AxInstSV";StartupType="Manual"}
        @{Name="BDESVC";StartupType="Manual"}
        @{Name="BFE";StartupType="Automatic"}
        @{Name="BITS";StartupType="AutomaticDelayedStart"}
        @{Name="BTAGService";StartupType="Manual"}
        @{Name="BcastDVRUserService_*";StartupType="Manual"}
        @{Name="BluetoothUserService_*";StartupType="Manual"}
        @{Name="BrokerInfrastructure";StartupType="Automatic"}
        @{Name="Browser";StartupType="Manual"}
        @{Name="BthAvctpSvc";StartupType="Automatic"}
        @{Name="BthHFSrv";StartupType="Automatic"}
        @{Name="CDPSvc";StartupType="Manual"}
        @{Name="CDPUserSvc_*";StartupType="Automatic"}
        @{Name="COMSysApp";StartupType="Manual"}
        @{Name="CaptureService_*";StartupType="Manual"}
        @{Name="CertPropSvc";StartupType="Manual"}
        @{Name="ClipSVC";StartupType="Manual"}
        @{Name="ConsentUxUserSvc_*";StartupType="Manual"}
        @{Name="CoreMessagingRegistrar";StartupType="Automatic"}
        @{Name="CredentialEnrollmentManagerUserSvc_*";StartupType="Manual"}
        @{Name="CryptSvc";StartupType="Automatic"}
        @{Name="CscService";StartupType="Manual"}
        @{Name="DPS";StartupType="Automatic"}
        @{Name="DcomLaunch";StartupType="Automatic"}
        @{Name="DcpSvc";StartupType="Manual"}
        @{Name="DevQueryBroker";StartupType="Manual"}
        @{Name="DeviceAssociationBrokerSvc_*";StartupType="Manual"}
        @{Name="DeviceAssociationService";StartupType="Manual"}
        @{Name="DeviceInstall";StartupType="Manual"}
        @{Name="DevicePickerUserSvc_*";StartupType="Manual"}
        @{Name="DevicesFlowUserSvc_*";StartupType="Manual"}
        @{Name="Dhcp";StartupType="Automatic"}
        @{Name="DiagTrack";StartupType="Disabled"}
        @{Name="DialogBlockingService";StartupType="Disabled"}
        @{Name="DispBrokerDesktopSvc";StartupType="Automatic"}
        @{Name="DisplayEnhancementService";StartupType="Manual"}
        @{Name="DmEnrollmentSvc";StartupType="Manual"}
        @{Name="Dnscache";StartupType="Automatic"}
        @{Name="DoSvc";StartupType="AutomaticDelayedStart"}
        @{Name="DsSvc";StartupType="Manual"}
        @{Name="DsmSvc";StartupType="Manual"}
        @{Name="DusmSvc";StartupType="Automatic"}
        @{Name="EFS";StartupType="Manual"}
        @{Name="EapHost";StartupType="Manual"}
        @{Name="EntAppSvc";StartupType="Manual"}
        @{Name="EventLog";StartupType="Automatic"}
        @{Name="EventSystem";StartupType="Automatic"}
        @{Name="FDResPub";StartupType="Manual"}
        @{Name="Fax";StartupType="Manual"}
        @{Name="FontCache";StartupType="Automatic"}
        @{Name="FrameServer";StartupType="Manual"}
        @{Name="FrameServerMonitor";StartupType="Manual"}
        @{Name="GraphicsPerfSvc";StartupType="Manual"}
        @{Name="HomeGroupListener";StartupType="Manual"}
        @{Name="HomeGroupProvider";StartupType="Manual"}
        @{Name="HvHost";StartupType="Manual"}
        @{Name="IEEtwCollectorService";StartupType="Manual"}
        @{Name="IKEEXT";StartupType="Manual"}
        @{Name="InstallService";StartupType="Manual"}
        @{Name="InventorySvc";StartupType="Manual"}
        @{Name="IpxlatCfgSvc";StartupType="Manual"}
        @{Name="KeyIso";StartupType="Automatic"}
        @{Name="KtmRm";StartupType="Manual"}
        @{Name="LSM";StartupType="Automatic"}
        @{Name="LanmanServer";StartupType="Automatic"}
        @{Name="LanmanWorkstation";StartupType="Automatic"}
        @{Name="LicenseManager";StartupType="Manual"}
        @{Name="LxpSvc";StartupType="Manual"}
        @{Name="MSDTC";StartupType="Manual"}
        @{Name="MSiSCSI";StartupType="Manual"}
        @{Name="MapsBroker";StartupType="AutomaticDelayedStart"}
        @{Name="McpManagementService";StartupType="Manual"}
        @{Name="MessagingService_*";StartupType="Manual"}
        @{Name="MicrosoftEdgeElevationService";StartupType="Manual"}
        @{Name="MixedRealityOpenXRSvc";StartupType="Manual"}
        @{Name="MpsSvc";StartupType="Automatic"}
        @{Name="MsKeyboardFilter";StartupType="Manual"}
        @{Name="NPSMSvc_*";StartupType="Manual"}
        @{Name="NaturalAuthentication";StartupType="Manual"}
        @{Name="NcaSvc";StartupType="Manual"}
        @{Name="NcbService";StartupType="Manual"}
        @{Name="NcdAutoSetup";StartupType="Manual"}
        @{Name="NetSetupSvc";StartupType="Manual"}
        @{Name="NetTcpPortSharing";StartupType="Disabled"}
        @{Name="Netlogon";StartupType="Automatic"}
        @{Name="Netman";StartupType="Manual"}
        @{Name="NgcCtnrSvc";StartupType="Manual"}
        @{Name="NgcSvc";StartupType="Manual"}
        @{Name="NlaSvc";StartupType="Manual"}
        @{Name="OneSyncSvc_*";StartupType="Automatic"}
        @{Name="P9RdrService_*";StartupType="Manual"}
        @{Name="PNRPAutoReg";StartupType="Manual"}
        @{Name="PNRPsvc";StartupType="Manual"}
        @{Name="PcaSvc";StartupType="Manual"}
        @{Name="PeerDistSvc";StartupType="Manual"}
        @{Name="PenService_*";StartupType="Manual"}
        @{Name="PerfHost";StartupType="Manual"}
        @{Name="PhoneSvc";StartupType="Manual"}
        @{Name="PimIndexMaintenanceSvc_*";StartupType="Manual"}
        @{Name="PlugPlay";StartupType="Manual"}
        @{Name="PolicyAgent";StartupType="Manual"}
        @{Name="Power";StartupType="Automatic"}
        @{Name="PrintNotify";StartupType="Manual"}
        @{Name="PrintWorkflowUserSvc_*";StartupType="Manual"}
        @{Name="ProfSvc";StartupType="Automatic"}
        @{Name="PushToInstall";StartupType="Manual"}
        @{Name="QWAVE";StartupType="Manual"}
        @{Name="RasAuto";StartupType="Manual"}
        @{Name="RasMan";StartupType="Manual"}
        @{Name="RemoteAccess";StartupType="Disabled"}
        @{Name="RemoteRegistry";StartupType="Disabled"}
        @{Name="RetailDemo";StartupType="Manual"}
        @{Name="RmSvc";StartupType="Manual"}
        @{Name="RpcEptMapper";StartupType="Automatic"}
        @{Name="RpcLocator";StartupType="Manual"}
        @{Name="RpcSs";StartupType="Automatic"}
        @{Name="SCPolicySvc";StartupType="Manual"}
        @{Name="SCardSvr";StartupType="Manual"}
        @{Name="SDRSVC";StartupType="Manual"}
        @{Name="SEMgrSvc";StartupType="Manual"}
        @{Name="SENS";StartupType="Automatic"}
        @{Name="SNMPTRAP";StartupType="Manual"}
        @{Name="SNMPTrap";StartupType="Manual"}
        @{Name="SSDPSRV";StartupType="Manual"}
        @{Name="SamSs";StartupType="Automatic"}
        @{Name="ScDeviceEnum";StartupType="Manual"}
        @{Name="Schedule";StartupType="Automatic"}
        @{Name="SecurityHealthService";StartupType="Manual"}
        @{Name="Sense";StartupType="Manual"}
        @{Name="SensorDataService";StartupType="Manual"}
        @{Name="SensorService";StartupType="Manual"}
        @{Name="SensrSvc";StartupType="Manual"}
        @{Name="SessionEnv";StartupType="Manual"}
        @{Name="SgrmBroker";StartupType="Automatic"}
        @{Name="SharedAccess";StartupType="Manual"}
        @{Name="SharedRealitySvc";StartupType="Manual"}
        @{Name="ShellHWDetection";StartupType="Automatic"}
        @{Name="SmsRouter";StartupType="Manual"}
        @{Name="Spooler";StartupType="Automatic"}
        @{Name="SstpSvc";StartupType="Manual"}
        @{Name="StateRepository";StartupType="Manual"}
        @{Name="StiSvc";StartupType="Manual"}
        @{Name="StorSvc";StartupType="Manual"}
        @{Name="SysMain";StartupType="Automatic"}
        @{Name="SystemEventsBroker";StartupType="Automatic"}
        @{Name="TabletInputService";StartupType="Manual"}
        @{Name="TapiSrv";StartupType="Manual"}
        @{Name="TermService";StartupType="Automatic"}
        @{Name="TextInputManagementService";StartupType="Manual"}
        @{Name="Themes";StartupType="Automatic"}
        @{Name="TieringEngineService";StartupType="Manual"}
        @{Name="TimeBroker";StartupType="Manual"}
        @{Name="TimeBrokerSvc";StartupType="Manual"}
        @{Name="TokenBroker";StartupType="Manual"}
        @{Name="TrkWks";StartupType="Automatic"}
        @{Name="TroubleshootingSvc";StartupType="Manual"}
        @{Name="TrustedInstaller";StartupType="Manual"}
        @{Name="UI0Detect";StartupType="Manual"}
        @{Name="UdkUserSvc_*";StartupType="Manual"}
        @{Name="UevAgentService";StartupType="Disabled"}
        @{Name="UmRdpService";StartupType="Manual"}
        @{Name="UnistoreSvc_*";StartupType="Manual"}
        @{Name="UserDataSvc_*";StartupType="Manual"}
        @{Name="UserManager";StartupType="Automatic"}
        @{Name="UsoSvc";StartupType="Manual"}
        @{Name="VGAuthService";StartupType="Automatic"}
        @{Name="VMTools";StartupType="Automatic"}
        @{Name="VSS";StartupType="Manual"}
        @{Name="VacSvc";StartupType="Manual"}
        @{Name="VaultSvc";StartupType="Automatic"}
        @{Name="W32Time";StartupType="Manual"}
        @{Name="WEPHOSTSVC";StartupType="Manual"}
        @{Name="WFDSConMgrSvc";StartupType="Manual"}
        @{Name="WMPNetworkSvc";StartupType="Manual"}
        @{Name="WManSvc";StartupType="Manual"}
        @{Name="WPDBusEnum";StartupType="Manual"}
        @{Name="WSService";StartupType="Manual"}
        @{Name="WSearch";StartupType="AutomaticDelayedStart"}
        @{Name="WaaSMedicSvc";StartupType="Manual"}
        @{Name="WalletService";StartupType="Manual"}
        @{Name="WarpJITSvc";StartupType="Manual"}
        @{Name="WbioSrvc";StartupType="Manual"}
        @{Name="Wcmsvc";StartupType="Automatic"}
        @{Name="WcsPlugInService";StartupType="Manual"}
        @{Name="WdNisSvc";StartupType="Manual"}
        @{Name="WdiServiceHost";StartupType="Manual"}
        @{Name="WdiSystemHost";StartupType="Manual"}
        @{Name="WebClient";StartupType="Manual"}
        @{Name="Wecsvc";StartupType="Manual"}
        @{Name="WerSvc";StartupType="Manual"}
        @{Name="WiaRpc";StartupType="Manual"}
        @{Name="WinDefend";StartupType="Automatic"}
        @{Name="WinHttpAutoProxySvc";StartupType="Manual"}
        @{Name="WinRM";StartupType="Manual"}
        @{Name="Winmgmt";StartupType="Automatic"}
        @{Name="WlanSvc";StartupType="Automatic"}
        @{Name="WpcMonSvc";StartupType="Manual"}
        @{Name="WpnService";StartupType="Manual"}
        @{Name="WpnUserService_*";StartupType="Automatic"}
        @{Name="XblAuthManager";StartupType="Manual"}
        @{Name="XblGameSave";StartupType="Manual"}
        @{Name="XboxGipSvc";StartupType="Manual"}
        @{Name="XboxNetApiSvc";StartupType="Manual"}
        @{Name="autotimesvc";StartupType="Manual"}
        @{Name="bthserv";StartupType="Manual"}
        @{Name="camsvc";StartupType="Manual"}
        @{Name="cbdhsvc_*";StartupType="Manual"}
        @{Name="cloudidsvc";StartupType="Manual"}
        @{Name="dcsvc";StartupType="Manual"}
        @{Name="defragsvc";StartupType="Manual"}
        @{Name="diagnosticshub.standardcollector.service";StartupType="Manual"}
        @{Name="diagsvc";StartupType="Manual"}
        @{Name="dmwappushservice";StartupType="Manual"}
        @{Name="dot3svc";StartupType="Manual"}
        @{Name="edgeupdate";StartupType="Manual"}
        @{Name="edgeupdatem";StartupType="Manual"}
        @{Name="embeddedmode";StartupType="Manual"}
        @{Name="fdPHost";StartupType="Manual"}
        @{Name="fhsvc";StartupType="Manual"}
        @{Name="gpsvc";StartupType="Automatic"}
        @{Name="hidserv";StartupType="Manual"}
        @{Name="icssvc";StartupType="Manual"}
        @{Name="iphlpsvc";StartupType="Automatic"}
        @{Name="lfsvc";StartupType="Manual"}
        @{Name="lltdsvc";StartupType="Manual"}
        @{Name="lmhosts";StartupType="Manual"}
        @{Name="mpssvc";StartupType="Automatic"}
        @{Name="msiserver";StartupType="Manual"}
        @{Name="netprofm";StartupType="Manual"}
        @{Name="nsi";StartupType="Automatic"}
        @{Name="p2pimsvc";StartupType="Manual"}
        @{Name="p2psvc";StartupType="Manual"}
        @{Name="perceptionsimulation";StartupType="Manual"}
        @{Name="pla";StartupType="Manual"}
        @{Name="seclogon";StartupType="Manual"}
        @{Name="shpamsvc";StartupType="Disabled"}
        @{Name="smphost";StartupType="Manual"}
        @{Name="spectrum";StartupType="Manual"}
        @{Name="sppsvc";StartupType="AutomaticDelayedStart"}
        @{Name="ssh-agent";StartupType="Disabled"}
        @{Name="svsvc";StartupType="Manual"}
        @{Name="swprv";StartupType="Manual"}
        @{Name="tiledatamodelsvc";StartupType="Automatic"}
        @{Name="tzautoupdate";StartupType="Disabled"}
        @{Name="uhssvc";StartupType="Disabled"}
        @{Name="upnphost";StartupType="Manual"}
        @{Name="vds";StartupType="Manual"}
        @{Name="vm3dservice";StartupType="Manual"}
        @{Name="vmicguestinterface";StartupType="Manual"}
        @{Name="vmicheartbeat";StartupType="Manual"}
        @{Name="vmickvpexchange";StartupType="Manual"}
        @{Name="vmicrdv";StartupType="Manual"}
        @{Name="vmicshutdown";StartupType="Manual"}
        @{Name="vmictimesync";StartupType="Manual"}
        @{Name="vmicvmsession";StartupType="Manual"}
        @{Name="vmicvss";StartupType="Manual"}
        @{Name="vmvss";StartupType="Manual"}
        @{Name="wbengine";StartupType="Manual"}
        @{Name="wcncsvc";StartupType="Manual"}
        @{Name="webthreatdefsvc";StartupType="Manual"}
        @{Name="webthreatdefusersvc_*";StartupType="Automatic"}
        @{Name="wercplsupport";StartupType="Manual"}
        @{Name="wisvc";StartupType="Manual"}
        @{Name="wlidsvc";StartupType="Manual"}
        @{Name="wlpasvc";StartupType="Manual"}
        @{Name="wmiApSrv";StartupType="Manual"}
        @{Name="workfolderssvc";StartupType="Manual"}
        @{Name="wscsvc";StartupType="AutomaticDelayedStart"}
        @{Name="wuauserv";StartupType="Manual"}
        @{Name="wudfsvc";StartupType="Manual"}
    )

    foreach ($svc in $services) {
        $name = $svc.Name
        $type = $svc.StartupType
    
        # Handle wildcard services (like Service_*)
        if ($name -like "*_*") {
            $base = $name.Substring(0, $name.IndexOf("_*"))
            $matching = Get-Service | Where-Object { $_.Name -like "$base*" }
            foreach ($msvc in $matching) {
                try {
                    Set-Service -Name $msvc.Name -StartupType $type -ErrorAction Stop
                    Write-Host "$($msvc.Name): $type" -ForegroundColor Green
                } catch {
                    Write-Host "Could not set $($msvc.Name): $_" -ForegroundColor Yellow
                }
            }
        } else {
            try {
                Set-Service -Name $name -StartupType $type -ErrorAction Stop
                Write-Host "$($name): $type" -ForegroundColor Green
            } catch {
                Write-Host "Could not set $($name): $_" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "All applicable services set to recommended startup types." -ForegroundColor Cyan
    Pause
}

# --- Commands for each category ---

function Flush-DNS {
    Write-Host ""
    Write-Host "Flushing DNS..." -ForegroundColor Yellow
    ipconfig /flushdns | Out-Null
    Write-Host "DNS cache cleared." -ForegroundColor Green
    Pause
}

function Show-IPConfig {
    Write-Host ""
    ipconfig
    Pause
}

function Open-AdvancedFirewall {
    Write-Host ""
    Write-Host "Opening Advanced Firewall panel..." -ForegroundColor Yellow
    Start-Process "wf.msc"
    Pause
}

function Restart-Explorer {
    Write-Host ""
    Write-Host "Restarting File Explorer..." -ForegroundColor Yellow
    Stop-Process -Name explorer -Force
    Start-Process explorer.exe
    Write-Host "File Explorer restarted." -ForegroundColor Green
    Pause
}

function Open-DeviceManager {
    Write-Host ""
    Write-Host "Opening Device Manager..." -ForegroundColor Yellow
    Start-Process "devmgmt.msc"
    Pause
}

function Show-SystemInfo {
    Write-Host ""
    systeminfo
    Pause
}

function Reset-WindowsUpdate {
    Write-Host ""
    Write-Host "Resetting Windows Update components..." -ForegroundColor Yellow
    try {
        # Stop services
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
        Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

        # Remove cache folders
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue

        # Start services
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Start-Service -Name bits -ErrorAction SilentlyContinue
        Start-Service -Name cryptsvc -ErrorAction SilentlyContinue

        Write-Host "Windows Update cache reset completed." -ForegroundColor Green
    } catch {
        Write-Host "Error during Windows Update reset: $_" -ForegroundColor Red
    }
    Pause
}

function Force-TimeSync {
    Write-Host ""
    Write-Host "Forcing time sync with Internet time server..." -ForegroundColor Yellow
    try {
        Set-Service -Name w32time -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service w32time -ErrorAction SilentlyContinue
        w32tm /resync | Out-Null
        Write-Host "Time sync initiated." -ForegroundColor Green
    } catch {
        Write-Host "Failed to sync time: $_" -ForegroundColor Red
    }
    Pause
}

function Create-BatteryReport {
    Write-Host ""
    $desktop = [Environment]::GetFolderPath("Desktop")
    $reportPath = Join-Path $desktop "battery-report.html"
    Write-Host "Generating battery report..." -ForegroundColor Yellow
    powercfg /batteryreport /output "$reportPath" | Out-Null
    if (Test-Path $reportPath) {
        Write-Host "Report created: $reportPath" -ForegroundColor Green
        Start-Process "$reportPath"
    } else {
        Write-Host "Error: unable to create the report." -ForegroundColor Red
    }
    Pause
}

function Restart-Spooler {
    Write-Host ""
    Write-Host "Restarting Print Spooler Service..." -ForegroundColor Yellow
    try {
        Restart-Service -Name Spooler -Force
        Write-Host "Print Spooler Service restarted." -ForegroundColor Green
    } catch {
        Write-Host "Error restarting Print Spooler: $_" -ForegroundColor Red
    }
    Pause
}

function Open-DiskManager {
    Write-Host ""
    Write-Host "Opening Disk Management..." -ForegroundColor Yellow
    Start-Process "diskmgmt.msc"
    Pause
}

function Show-DiskSpace {
    Write-Host ""
    Get-PSDrive -PSProvider 'FileSystem' | Select-Object Name,Free,Used, @{Name="Total(GB)";Expression={"{0:N2}" -f ($_.Used + $_.Free)/1GB}}, @{Name="Free(GB)";Expression={"{0:N2}" -f ($_.Free/1GB)}}
    Pause
}

function Run-DiskCleanup {
    Write-Host ""
    Write-Host "Running Disk Cleanup (cleanmgr) and component cleanup (DISM)..." -ForegroundColor Yellow
    try {
        # Run Disk Cleanup in automated mode for C:
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/d C: /VERYLOWDISK" -Wait
        # Run DISM component cleanup
        Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait
        Write-Host "Disk Cleanup and component cleanup completed." -ForegroundColor Green
    } catch {
        Write-Host "Failed to complete disk cleanup: $_" -ForegroundColor Red
    }
    Pause
}

function Clean-TempFiles {
    Write-Host ""
    Write-Host "Cleaning temporary files..." -ForegroundColor Yellow
    try {
        Get-ChildItem -Path "C:\Windows\Temp" -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem -Path $env:TEMP -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "Cleanup completed." -ForegroundColor Green
    } catch {
        Write-Host "Error during temporary files cleanup: $_" -ForegroundColor Red
    }
    Pause
}

# --- Main Menu Loop ---

do {
    Show-MainMenu
    $mainChoice = $null
    while ($null -eq $mainChoice) {
        $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
        if ($input -match '^[0-4]$') {
            $mainChoice = $input
        }
    }
    switch ($mainChoice) {
        "1" { # Network
            $exitMenu = $false
            do {
                Show-NetworkMenu
                $choice = $null
                while ($null -eq $choice) {
                    $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
                    if ($input -match '^[0-3]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Flush-DNS }
                    "2" { Show-IPConfig }
                    "3" { Open-AdvancedFirewall }
                    "0" { $exitMenu = $true }
                }
            } while (-not $exitMenu)
        }
        "2" { # System
            $exitMenu = $false
            do {
                Show-SystemMenu
                $choice = $null
                while ($null -eq $choice) {
                    $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
                    if ($input -match '^[0-7]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Show-SystemInfo }
                    "2" { Restart-Explorer }
                    "3" { Open-DeviceManager }
                    "4" { Reset-WindowsUpdate }
                    "5" { Force-TimeSync }
                    "6" { Create-BatteryReport }
                    "7" { Set-ServicesRecommended }
                    "0" { $exitMenu = $true }
                }
            } while (-not $exitMenu)
        }
        "3" { # Printer
            $exitMenu = $false
            do {
                Show-PrinterMenu
                $choice = $null
                while ($null -eq $choice) {
                    $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
                    if ($input -match '^[0-1]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Restart-Spooler }
                    "0" { $exitMenu = $true }
                }
            } while (-not $exitMenu)
        }
        "4" { # Disk
            $exitMenu = $false
            do {
                Show-DiskMenu
                $choice = $null
                while ($null -eq $choice) {
                    $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
                    if ($input -match '^[0-4]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Open-DiskManager }
                    "2" { Show-DiskSpace }
                    "3" { Run-DiskCleanup }
                    "4" { Clean-TempFiles }
                    "0" { $exitMenu = $true }
                }
            } while (-not $exitMenu)
        }
        "0" {
            Start-Sleep -Seconds 0
            exit
        }
    }
} while ($true)
