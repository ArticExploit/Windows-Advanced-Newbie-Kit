if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Windows-Advanced-Newbie-Kit needs to be run as Administrator. Attempting to relaunch."
    $argList = @()

    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        $argList += if ($_.Value -is [switch] -and $_.Value) {
            "-$($_.Key)"
        } elseif ($_.Value -is [array]) {
            "-$($_.Key) $($_.Value -join ',')"
        } elseif ($_.Value) {
            "-$($_.Key) '$($_.Value)'"
        }
    }

    $script = if ($PSCommandPath) {
        "& { & `'$($PSCommandPath)`' $($argList -join ' ') }"
    } else {
        "&([ScriptBlock]::Create((irm https://github.com/ArticExploit/Windows-Advanced-Newbie-Kit/releases/latest/download/wank.ps1))) $($argList -join ' ')"
    }

    $powershellCmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    $processCmd = if (Get-Command wt.exe -ErrorAction SilentlyContinue) { "wt.exe" } else { "$powershellCmd" }

    if ($processCmd -eq "wt.exe") {
        Start-Process $processCmd -ArgumentList "$powershellCmd -ExecutionPolicy Bypass -NoProfile -Command `"$script`"" -Verb RunAs
    } else {
        Start-Process $processCmd -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$script`"" -Verb RunAs
    }

    break
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
    Write-Host "   [4] Export Wi-Fi Profiles"
    Write-Host "   [5] Import Wi-Fi Profiles"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-5,0] : " -NoNewline
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

# --- Network: Wi-Fi profile export/import helpers ---

function Get-DefaultExportFolder {
    <#
    .SYNOPSIS
      Constructs a default export folder on the user's Desktop with a timestamp.
    #>
    try {
        $desktop = [Environment]::GetFolderPath("Desktop")
        $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        return (Join-Path $desktop "WiFi-Profiles-$stamp")
    } catch {
        # Fallback to C:\Temp if Desktop is not resolvable
        $fallback = "C:\Temp\WiFi-Profiles-" + (Get-Date).ToString("yyyyMMdd-HHmmss")
        return $fallback
    }
}

function Confirm-YesNo($Prompt, [bool]$DefaultYes=$true) {
    <#
    .SYNOPSIS
      Simple Y/N prompt that returns $true for Yes, $false for No.
    .PARAMETER Prompt
      Message shown to user.
    .PARAMETER DefaultYes
      If the user presses Enter, default is Yes when true, No when false.
    #>
    $suffix = if ($DefaultYes) { " [Y/n]" } else { " [y/N]" }
    while ($true) {
        Write-Host "$Prompt$suffix " -NoNewline -ForegroundColor Yellow
        $resp = Read-Host
        if ([string]::IsNullOrWhiteSpace($resp)) { return $DefaultYes }
        switch ($resp.Trim().ToLowerInvariant()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { Write-Host "Please answer 'y' or 'n'." -ForegroundColor DarkYellow }
        }
    }
}

function Ensure-Folder($Path) {
    <#
    .SYNOPSIS
      Ensures a folder exists, creating it if necessary.
    .RETURNS
      The full, resolved path string if successful; $null otherwise.
    #>
    try {
        if (-not (Test-Path -Path $Path -PathType Container)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        $resolved = (Resolve-Path -Path $Path).Path
        return $resolved
    } catch {
        Write-Host "Failed to create or access folder: $Path`n$_" -ForegroundColor Red
        return $null
    }
}

function Export-WiFiProfiles {
    <#
    .SYNOPSIS
      Exports all Wi-Fi profiles to a chosen folder using 'netsh wlan export profile'.
    .DESCRIPTION
      - Optionally includes key material (passwords) if the user confirms.
      - Exports all profiles at once (avoids locale-dependent parsing).
      - Writes one XML file per profile into the destination folder.
    .SECURITY
      Including keys writes readable credentials into XML files. Handle securely.
    #>
    Write-Host ""
    Write-Host "Exporting Wi-Fi profiles..." -ForegroundColor Cyan

    $includeKeys = Confirm-YesNo -Prompt "Include Wi-Fi passwords in exported XML (key=clear)? This writes readable credentials to disk." -DefaultYes:$false

    # Ask for destination folder with default suggestion
    $defaultFolder = Get-DefaultExportFolder
    Write-Host "Enter destination folder for exported profiles (Press Enter to use default):" -ForegroundColor Yellow
    Write-Host "Default: $defaultFolder" -ForegroundColor DarkGray
    Write-Host "> " -NoNewline
    $dest = Read-Host
    if ([string]::IsNullOrWhiteSpace($dest)) {
        $dest = $defaultFolder
    }

    $dest = Ensure-Folder -Path $dest
    if (-not $dest) { Pause; return }

    # Track existing XML files to count newly exported files reliably
    $preExisting = @()
    try {
        if (Test-Path -Path $dest) {
            $preExisting = Get-ChildItem -Path $dest -Filter *.xml -File -ErrorAction SilentlyContinue
        }
    } catch { }

    # Build netsh command
    $args = @('wlan','export','profile',"folder=""$dest""")
    if ($includeKeys) {
        $args += 'key=clear'
    }

    try {
        # Call netsh directly to export all profiles
        & netsh @args | Out-Null
        $exit = $LASTEXITCODE
        if ($exit -ne 0) {
            Write-Host "netsh returned a non-zero exit code: $exit" -ForegroundColor Red
        }
    } catch {
        Write-Host "Failed to run netsh: $_" -ForegroundColor Red
        Pause
        return
    }

    # Count new files
    $postFiles = @()
    try {
        $postFiles = Get-ChildItem -Path $dest -Filter *.xml -File -ErrorAction SilentlyContinue
    } catch { }

    # Compute newly created
    $newFiles = $postFiles | Where-Object { $preExisting -notcontains $_ }
    $newCount = if ($newFiles) { $newFiles.Count } else { 0 }

    if ($newCount -gt 0) {
        Write-Host "Export completed. $newCount profile XML file(s) saved to:" -ForegroundColor Green
        Write-Host "  $dest" -ForegroundColor Green
        if ($includeKeys) {
            Write-Host "WARNING: Export includes passwords. Store the files securely and delete when done." -ForegroundColor Yellow
        }
    } else {
        Write-Host "No new Wi-Fi profile XML files were created. Profiles may not exist or an error occurred." -ForegroundColor Yellow
        Write-Host "Check the destination folder: $dest" -ForegroundColor Yellow
    }

    Pause
}

function Import-WiFiProfiles {
    <#
    .SYNOPSIS
      Imports Wi-Fi profiles from XML files in a specified folder using 'netsh wlan add profile'.
    .DESCRIPTION
      - Imports all *.xml files in the folder.
      - User can choose to import for 'All users' (requires admin) or 'Current user'.
    .NOTES
      - Conflicting or duplicate profiles may be overwritten by netsh as appropriate.
    #>
    Write-Host ""
    Write-Host "Importing Wi-Fi profiles from XML..." -ForegroundColor Cyan

    # Ask for source folder
    Write-Host "Enter folder path containing exported Wi-Fi profile XML files (*.xml):" -ForegroundColor Yellow
    Write-Host "> " -NoNewline
    $src = Read-Host

    if ([string]::IsNullOrWhiteSpace($src)) {
        Write-Host "No folder specified. Import cancelled." -ForegroundColor Yellow
        Pause
        return
    }

    try {
        $srcResolved = (Resolve-Path -Path $src -ErrorAction Stop).Path
    } catch {
        Write-Host "Folder not found: $src" -ForegroundColor Red
        Pause
        return
    }

    try {
        $xmlFiles = Get-ChildItem -Path $srcResolved -Filter *.xml -File -ErrorAction Stop
    } catch {
        Write-Host "Failed to enumerate XML files in: $srcResolved`n$_" -ForegroundColor Red
        Pause
        return
    }

    if (-not $xmlFiles -or $xmlFiles.Count -eq 0) {
        Write-Host "No XML files found in: $srcResolved" -ForegroundColor Yellow
        Pause
        return
    }

    $allUsers = Confirm-YesNo -Prompt "Import profiles for ALL users (recommended, requires admin)? Choose 'No' for current user only." -DefaultYes:$true
    $userScope = if ($allUsers) { 'all' } else { 'current' }

    $success = 0
    $failed = 0
    $failures = @()

    foreach ($file in $xmlFiles) {
        try {
            & netsh wlan add profile filename="$($file.FullName)" "user=$userScope" | Out-Null
            $exit = $LASTEXITCODE
            if ($exit -eq 0) {
                $success++
                Write-Host "Imported: $($file.Name)" -ForegroundColor Green
            } else {
                $failed++
                $failures += "[$exit] $($file.FullName)"
                Write-Host "Failed (code $exit): $($file.Name)" -ForegroundColor Yellow
            }
        } catch {
            $failed++
            $failures += "[EXCEPTION] $($file.FullName) :: $_"
            Write-Host "Exception importing $($file.Name): $_" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Import summary:" -ForegroundColor Cyan
    Write-Host "  Success: $success" -ForegroundColor Green
    Write-Host "  Failed : $failed" -ForegroundColor Yellow
    if ($failed -gt 0) {
        Write-Host "  Failed items:" -ForegroundColor Yellow
        foreach ($f in $failures) {
            Write-Host "    - $f" -ForegroundColor Yellow
        }
    }

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
                    if ($input -match '^[0-5]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Flush-DNS }
                    "2" { Show-IPConfig }
                    "3" { Open-AdvancedFirewall }
                    "4" { Export-WiFiProfiles }
                    "5" { Import-WiFiProfiles }
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
