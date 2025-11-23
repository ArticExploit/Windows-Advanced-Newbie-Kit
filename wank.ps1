if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Winutil needs to be run as Administrator. Attempting to relaunch."
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
    Write-Host "   [5] Debloat"
    Write-Host "   [0] Exit"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-5,0] : " -NoNewline
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
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-6,0] : " -NoNewline
}

function Show-PrinterMenu {
    Show-Header "Printer"
    Write-Host "   [1] Restart Spooler Service"
    Write-Host "   [2] Setup Scanner SMB Share"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-2,0] : " -NoNewline
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

function Show-DebloatMenu {
    Show-Header "Debloat"
    Write-Host "   [1] Set Services to Recommended Startup"
    Write-Host "   [2] Disable Telemetry"
    Write-Host "   [3] Debloat Edge"
    Write-Host "   [0] Back"
    Write-Host ""
    Write-Host "Choose a menu option using your keyboard [1-3,0] : " -NoNewline
}

function Set-ServicesRecommended {
    [CmdletBinding()]
    param()

    Write-Host ""
    # Use existing Confirm-YesNo if available; otherwise define a local fallback
    if (-not (Get-Command Confirm-YesNo -ErrorAction SilentlyContinue)) {
        function Confirm-YesNo([string]$Prompt, [bool]$DefaultYes=$true) {
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
    }

    $doRevert = Confirm-YesNo -Prompt "Revert service startup types to their OriginalType values?" -DefaultYes:$false

    if ($doRevert) {
        Write-Host "Reverting Windows service startup types to OriginalType where provided..." -ForegroundColor Cyan
    } else {
        Write-Host "Applying Windows service startup types..." -ForegroundColor Cyan
    }

    # Helper: set startup type including support for AutomaticDelayedStart
    function Set-StartupType {
        param(
            [Parameter(Mandatory)] [string]$ServiceName,
            [Parameter(Mandatory)] [ValidateSet('Automatic','Manual','Disabled','AutomaticDelayedStart')] [string]$StartupType
        )

        try {
            $svc = Get-Service -Name $ServiceName -ErrorAction Stop

            switch ($StartupType) {
                'Automatic' {
                    Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                    if (Test-Path $regPath) {
                        try { Set-ItemProperty -Path $regPath -Name DelayedAutoStart -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
                    }
                }
                'Manual' {
                    Set-Service -Name $ServiceName -StartupType Manual -ErrorAction Stop
                }
                'Disabled' {
                    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                }
                'AutomaticDelayedStart' {
                    Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
                    $sc = cmd /c "sc.exe config `"$ServiceName`" start= delayed-auto" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                        if (Test-Path $regPath) {
                            Set-ItemProperty -Path $regPath -Name DelayedAutoStart -Type DWord -Value 1 -Force -ErrorAction Stop | Out-Null
                        } else {
                            throw "Could not set DelayedAutoStart registry. sc.exe output: $sc"
                        }
                    }
                }
            }
            return $true
        } catch {
            Write-Host "Failed to set $ServiceName -> $StartupType :: $_" -ForegroundColor Yellow
            return $false
        }
    }

    # Data: services with desired StartupType and OriginalType for revert
    # Supports wildcards like ServiceName_* by expanding to all matching services
    $services = @(
        @{Name="AJRouter";StartupType="Disabled";OriginalType="Manual"}
        @{Name="ALG";StartupType="Manual";OriginalType="Manual"}
        @{Name="AppIDSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="AppMgmt";StartupType="Manual";OriginalType="Manual"}
        @{Name="AppReadiness";StartupType="Manual";OriginalType="Manual"}
        @{Name="AppVClient";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="AppXSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="Appinfo";StartupType="Manual";OriginalType="Manual"}
        @{Name="AssignedAccessManagerSvc";StartupType="Disabled";OriginalType="Manual"}
        @{Name="AudioEndpointBuilder";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="AudioSrv";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="Audiosrv";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="AxInstSV";StartupType="Manual";OriginalType="Manual"}
        @{Name="BDESVC";StartupType="Manual";OriginalType="Manual"}
        @{Name="BFE";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="BITS";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="BTAGService";StartupType="Manual";OriginalType="Manual"}
        @{Name="BcastDVRUserService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="BluetoothUserService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="BrokerInfrastructure";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="Browser";StartupType="Manual";OriginalType="Manual"}
        @{Name="BthAvctpSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="BthHFSrv";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="CDPSvc";StartupType="Manual";OriginalType="Automatic"}
        @{Name="CDPUserSvc_*";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="COMSysApp";StartupType="Manual";OriginalType="Manual"}
        @{Name="CaptureService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="CertPropSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="ClipSVC";StartupType="Manual";OriginalType="Manual"}
        @{Name="ConsentUxUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="CoreMessagingRegistrar";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="CredentialEnrollmentManagerUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="CryptSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="CscService";StartupType="Manual";OriginalType="Manual"}
        @{Name="DPS";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="DcomLaunch";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="DcpSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="DevQueryBroker";StartupType="Manual";OriginalType="Manual"}
        @{Name="DeviceAssociationBrokerSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="DeviceAssociationService";StartupType="Manual";OriginalType="Manual"}
        @{Name="DeviceInstall";StartupType="Manual";OriginalType="Manual"}
        @{Name="DevicePickerUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="DevicesFlowUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="Dhcp";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="DiagTrack";StartupType="Disabled";OriginalType="Automatic"}
        @{Name="DialogBlockingService";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="DispBrokerDesktopSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="DisplayEnhancementService";StartupType="Manual";OriginalType="Manual"}
        @{Name="DmEnrollmentSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="Dnscache";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="DoSvc";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="DsSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="DsmSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="DusmSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="EFS";StartupType="Manual";OriginalType="Manual"}
        @{Name="EapHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="EntAppSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="EventLog";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="EventSystem";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="FDResPub";StartupType="Manual";OriginalType="Manual"}
        @{Name="Fax";StartupType="Manual";OriginalType="Manual"}
        @{Name="FontCache";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="FrameServer";StartupType="Manual";OriginalType="Manual"}
        @{Name="FrameServerMonitor";StartupType="Manual";OriginalType="Manual"}
        @{Name="GraphicsPerfSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="HomeGroupListener";StartupType="Manual";OriginalType="Manual"}
        @{Name="HomeGroupProvider";StartupType="Manual";OriginalType="Manual"}
        @{Name="HvHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="IEEtwCollectorService";StartupType="Manual";OriginalType="Manual"}
        @{Name="IKEEXT";StartupType="Manual";OriginalType="Manual"}
        @{Name="InstallService";StartupType="Manual";OriginalType="Manual"}
        @{Name="InventorySvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="IpxlatCfgSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="KeyIso";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="KtmRm";StartupType="Manual";OriginalType="Manual"}
        @{Name="LSM";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="LanmanServer";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="LanmanWorkstation";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="LicenseManager";StartupType="Manual";OriginalType="Manual"}
        @{Name="LxpSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="MSDTC";StartupType="Manual";OriginalType="Manual"}
        @{Name="MSiSCSI";StartupType="Manual";OriginalType="Manual"}
        @{Name="MapsBroker";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="McpManagementService";StartupType="Manual";OriginalType="Manual"}
        @{Name="MessagingService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="MicrosoftEdgeElevationService";StartupType="Manual";OriginalType="Manual"}
        @{Name="MixedRealityOpenXRSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="MpsSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="MsKeyboardFilter";StartupType="Manual";OriginalType="Disabled"}
        @{Name="NPSMSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="NaturalAuthentication";StartupType="Manual";OriginalType="Manual"}
        @{Name="NcaSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="NcbService";StartupType="Manual";OriginalType="Manual"}
        @{Name="NcdAutoSetup";StartupType="Manual";OriginalType="Manual"}
        @{Name="NetSetupSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="NetTcpPortSharing";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="Netlogon";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="Netman";StartupType="Manual";OriginalType="Manual"}
        @{Name="NgcCtnrSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="NgcSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="NlaSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="OneSyncSvc_*";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="P9RdrService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="PNRPAutoReg";StartupType="Manual";OriginalType="Manual"}
        @{Name="PNRPsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="PcaSvc";StartupType="Manual";OriginalType="Automatic"}
        @{Name="PeerDistSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="PenService_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="PerfHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="PhoneSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="PimIndexMaintenanceSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="PlugPlay";StartupType="Manual";OriginalType="Manual"}
        @{Name="PolicyAgent";StartupType="Manual";OriginalType="Manual"}
        @{Name="Power";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="PrintNotify";StartupType="Manual";OriginalType="Manual"}
        @{Name="PrintWorkflowUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="ProfSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="PushToInstall";StartupType="Manual";OriginalType="Manual"}
        @{Name="QWAVE";StartupType="Manual";OriginalType="Manual"}
        @{Name="RasAuto";StartupType="Manual";OriginalType="Manual"}
        @{Name="RasMan";StartupType="Manual";OriginalType="Manual"}
        @{Name="RemoteAccess";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="RemoteRegistry";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="RetailDemo";StartupType="Manual";OriginalType="Manual"}
        @{Name="RmSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="RpcEptMapper";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="RpcLocator";StartupType="Manual";OriginalType="Manual"}
        @{Name="RpcSs";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SCPolicySvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="SCardSvr";StartupType="Manual";OriginalType="Manual"}
        @{Name="SDRSVC";StartupType="Manual";OriginalType="Manual"}
        @{Name="SEMgrSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="SENS";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SNMPTRAP";StartupType="Manual";OriginalType="Manual"}
        @{Name="SNMPTrap";StartupType="Manual";OriginalType="Manual"}
        @{Name="SSDPSRV";StartupType="Manual";OriginalType="Manual"}
        @{Name="SamSs";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="ScDeviceEnum";StartupType="Manual";OriginalType="Manual"}
        @{Name="Schedule";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SecurityHealthService";StartupType="Manual";OriginalType="Manual"}
        @{Name="Sense";StartupType="Manual";OriginalType="Manual"}
        @{Name="SensorDataService";StartupType="Manual";OriginalType="Manual"}
        @{Name="SensorService";StartupType="Manual";OriginalType="Manual"}
        @{Name="SensrSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="SessionEnv";StartupType="Manual";OriginalType="Manual"}
        @{Name="SgrmBroker";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SharedAccess";StartupType="Manual";OriginalType="Manual"}
        @{Name="SharedRealitySvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="ShellHWDetection";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SmsRouter";StartupType="Manual";OriginalType="Manual"}
        @{Name="Spooler";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SstpSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="StateRepository";StartupType="Manual";OriginalType="Automatic"}
        @{Name="StiSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="StorSvc";StartupType="Manual";OriginalType="Automatic"}
        @{Name="SysMain";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="SystemEventsBroker";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="TabletInputService";StartupType="Manual";OriginalType="Manual"}
        @{Name="TapiSrv";StartupType="Manual";OriginalType="Manual"}
        @{Name="TermService";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="TextInputManagementService";StartupType="Manual";OriginalType="Automatic"}
        @{Name="Themes";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="TieringEngineService";StartupType="Manual";OriginalType="Manual"}
        @{Name="TimeBroker";StartupType="Manual";OriginalType="Manual"}
        @{Name="TimeBrokerSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="TokenBroker";StartupType="Manual";OriginalType="Manual"}
        @{Name="TrkWks";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="TroubleshootingSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="TrustedInstaller";StartupType="Manual";OriginalType="Manual"}
        @{Name="UI0Detect";StartupType="Manual";OriginalType="Manual"}
        @{Name="UdkUserSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="UevAgentService";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="UmRdpService";StartupType="Manual";OriginalType="Manual"}
        @{Name="UnistoreSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="UserDataSvc_*";StartupType="Manual";OriginalType="Manual"}
        @{Name="UserManager";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="UsoSvc";StartupType="Manual";OriginalType="Automatic"}
        @{Name="VGAuthService";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="VMTools";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="VSS";StartupType="Manual";OriginalType="Manual"}
        @{Name="VacSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="VaultSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="W32Time";StartupType="Manual";OriginalType="Manual"}
        @{Name="WEPHOSTSVC";StartupType="Manual";OriginalType="Manual"}
        @{Name="WFDSConMgrSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WMPNetworkSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WManSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WPDBusEnum";StartupType="Manual";OriginalType="Manual"}
        @{Name="WSService";StartupType="Manual";OriginalType="Manual"}
        @{Name="WSearch";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="WaaSMedicSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WalletService";StartupType="Manual";OriginalType="Manual"}
        @{Name="WarpJITSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WbioSrvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="Wcmsvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="WcsPlugInService";StartupType="Manual";OriginalType="Manual"}
        @{Name="WdNisSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WdiServiceHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="WdiSystemHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="WebClient";StartupType="Manual";OriginalType="Manual"}
        @{Name="Wecsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WerSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WiaRpc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WinDefend";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="WinHttpAutoProxySvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WinRM";StartupType="Manual";OriginalType="Manual"}
        @{Name="Winmgmt";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="WlanSvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="WpcMonSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="WpnService";StartupType="Manual";OriginalType="Automatic"}
        @{Name="WpnUserService_*";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="XblAuthManager";StartupType="Manual";OriginalType="Manual"}
        @{Name="XblGameSave";StartupType="Manual";OriginalType="Manual"}
        @{Name="XboxGipSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="XboxNetApiSvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="autotimesvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="bthserv";StartupType="Manual";OriginalType="Manual"}
        @{Name="camsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="cbdhsvc_*";StartupType="Manual";OriginalType="Automatic"}
        @{Name="cloudidsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="dcsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="defragsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="diagnosticshub.standardcollector.service";StartupType="Manual";OriginalType="Manual"}
        @{Name="diagsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="dmwappushservice";StartupType="Manual";OriginalType="Manual"}
        @{Name="dot3svc";StartupType="Manual";OriginalType="Manual"}
        @{Name="edgeupdate";StartupType="Manual";OriginalType="Automatic"}
        @{Name="edgeupdatem";StartupType="Manual";OriginalType="Manual"}
        @{Name="embeddedmode";StartupType="Manual";OriginalType="Manual"}
        @{Name="fdPHost";StartupType="Manual";OriginalType="Manual"}
        @{Name="fhsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="gpsvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="hidserv";StartupType="Manual";OriginalType="Manual"}
        @{Name="icssvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="iphlpsvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="lfsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="lltdsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="lmhosts";StartupType="Manual";OriginalType="Manual"}
        @{Name="mpssvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="msiserver";StartupType="Manual";OriginalType="Manual"}
        @{Name="netprofm";StartupType="Manual";OriginalType="Manual"}
        @{Name="nsi";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="p2pimsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="p2psvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="perceptionsimulation";StartupType="Manual";OriginalType="Manual"}
        @{Name="pla";StartupType="Manual";OriginalType="Manual"}
        @{Name="seclogon";StartupType="Manual";OriginalType="Manual"}
        @{Name="shpamsvc";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="smphost";StartupType="Manual";OriginalType="Manual"}
        @{Name="spectrum";StartupType="Manual";OriginalType="Manual"}
        @{Name="sppsvc";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="ssh-agent";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="svsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="swprv";StartupType="Manual";OriginalType="Manual"}
        @{Name="tiledatamodelsvc";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="tzautoupdate";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="uhssvc";StartupType="Disabled";OriginalType="Disabled"}
        @{Name="upnphost";StartupType="Manual";OriginalType="Manual"}
        @{Name="vds";StartupType="Manual";OriginalType="Manual"}
        @{Name="vm3dservice";StartupType="Manual";OriginalType="Automatic"}
        @{Name="vmicguestinterface";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmicheartbeat";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmickvpexchange";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmicrdv";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmicshutdown";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmictimesync";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmicvmsession";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmicvss";StartupType="Manual";OriginalType="Manual"}
        @{Name="vmvss";StartupType="Manual";OriginalType="Manual"}
        @{Name="wbengine";StartupType="Manual";OriginalType="Manual"}
        @{Name="wcncsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="webthreatdefsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="webthreatdefusersvc_*";StartupType="Automatic";OriginalType="Automatic"}
        @{Name="wercplsupport";StartupType="Manual";OriginalType="Manual"}
        @{Name="wisvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="wlidsvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="wlpasvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="wmiApSrv";StartupType="Manual";OriginalType="Manual"}
        @{Name="workfolderssvc";StartupType="Manual";OriginalType="Manual"}
        @{Name="wscsvc";StartupType="AutomaticDelayedStart";OriginalType="Automatic"}
        @{Name="wuauserv";StartupType="Manual";OriginalType="Manual"}
        @{Name="wudfsvc";StartupType="Manual";OriginalType="Manual"}
    )

    $updated = 0
    $skipped = 0
    $failed = 0

    foreach ($svcDef in $services) {
        $name = [string]$svcDef.Name
        $target = if ($doRevert) { [string]$svcDef.OriginalType } else { [string]$svcDef.StartupType }

        # Expand wildcards (e.g., Service_*), otherwise handle directly
        $matchedServices = @()
        if ($name -match '[\*\?]') {
            try {
                $matchedServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $name }
            } catch { $matchedServices = @() }
            if (-not $matchedServices -or $matchedServices.Count -eq 0) {
                Write-Host "Wildcard pattern matched no services: $name" -ForegroundColor DarkYellow
                $skipped++
                continue
            }
        } else {
            $svcObj = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $svcObj) { $matchedServices = @($svcObj) } else {
                Write-Host "Service not found (skipped): $name" -ForegroundColor DarkYellow
                $skipped++
                continue
            }
        }

        foreach ($ms in $matchedServices) {
            if (Set-StartupType -ServiceName $ms.Name -StartupType $target) {
                Write-Host "$($ms.Name): $target" -ForegroundColor Green
                $updated++
            } else {
                $failed++
            }
        }
    }

    Write-Host ""
    Write-Host "Service startup update complete. Updated: $updated, Skipped: $skipped, Failed: $failed" -ForegroundColor Cyan

    if (Get-Command Pause -ErrorAction SilentlyContinue) { Pause }
}

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

function Get-ActiveUserDesktopPath {
    <#
    .SYNOPSIS
      Tries to resolve the Desktop path of the currently signed-in interactive user,
      even when running elevated as Administrator.
    #>
    try {
        $sessionUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ([string]::IsNullOrWhiteSpace($sessionUser)) {
            return [Environment]::GetFolderPath("Desktop")
        }
        $userNameOnly = $sessionUser.Split('\')[-1]
        $candidate = Join-Path "C:\Users\$userNameOnly" "Desktop"
        if (Test-Path -Path $candidate -PathType Container) {
            return $candidate
        } else {
            return [Environment]::GetFolderPath("Desktop")
        }
    } catch {
        return [Environment]::GetFolderPath("Desktop")
    }
}

function Setup-ScannerShare {
    Write-Host ""
    Write-Host "Setup Scanner SMB share (default user/password: scanner/scanner)" -ForegroundColor Cyan

    # Prompt for username (default: scanner)
    $inputUser = Read-Host -Prompt "Enter username for scanner account (Press Enter for default 'scanner')"
    if ([string]::IsNullOrWhiteSpace($inputUser)) {
        $userName = "scanner"
    } else {
        $userName = $inputUser.Trim()
    }

    # Prompt for password (hidden). Use default 'scanner' if the user presses Enter.
    Write-Host "Enter password for user '$userName' (Press Enter for default 'scanner'):" -ForegroundColor Yellow
    $pwdSecure = Read-Host -AsSecureString -Prompt "(input hidden)"
    # Convert SecureString to plain to detect emptiness; free BSTR afterwards
    $pwdPlain = ""
    if ($pwdSecure -ne $null) {
        try {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwdSecure)
            $pwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } catch {
            $pwdPlain = ""
        } finally {
            if ($bstr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
    }
    if ([string]::IsNullOrWhiteSpace($pwdPlain)) {
        $passwordPlain = "scanner"
        $pwdSecure = ConvertTo-SecureString $passwordPlain -AsPlainText -Force
    } else {
        $passwordPlain = $pwdPlain
        # $pwdSecure is already set
    }

    $localQualified = "$env:COMPUTERNAME\$userName"

    # 1) Ensure local user exists; create or optionally reset password
    try {
        $existing = $null
        try { $existing = Get-LocalUser -Name $userName -ErrorAction Stop } catch { $existing = $null }

        if (-not $existing) {
            Write-Host "Creating local user '$userName'..." -ForegroundColor Yellow
            if (Get-Command New-LocalUser -ErrorAction SilentlyContinue) {
                New-LocalUser -Name $userName -Password $pwdSecure -PasswordNeverExpires:$true -UserMayNotChangePassword:$true -AccountNeverExpires:$true | Out-Null
                try { Add-LocalGroupMember -Group "Users" -Member $userName -ErrorAction SilentlyContinue } catch {}
            } else {
                # Fallback to net user
                $escapedPwd = $passwordPlain.Replace('"','\"')
                cmd /c "net user `"$userName`" `"$escapedPwd`" /add" | Out-Null
                cmd /c "net localgroup Users `"$userName`" /add" | Out-Null
            }
            Write-Host "User '$userName' created." -ForegroundColor Green
        } else {
            Write-Host "User '$userName' already exists." -ForegroundColor DarkYellow
            $reset = Confirm-YesNo -Prompt "Reset the password for '$userName' to the value you entered?" -DefaultYes:$false
            if ($reset) {
                try {
                    if (Get-Command Set-LocalUser -ErrorAction SilentlyContinue) {
                        Set-LocalUser -Name $userName -Password $pwdSecure -ErrorAction Stop
                    } else {
                        $escapedPwd = $passwordPlain.Replace('"','\"')
                        cmd /c "net user `"$userName`" `"$escapedPwd`"" | Out-Null
                    }
                    Write-Host "Password for '$userName' updated." -ForegroundColor Green
                } catch {
                    Write-Host "Failed to update password: $_" -ForegroundColor Red
                    Pause
                    return
                }
            } else {
                Write-Host "Left existing password unchanged." -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Host "Failed to ensure user '$userName': $_" -ForegroundColor Red
        Pause
        return
    }

    # 2) Create scan folder on active user's Desktop
    try {
        $desktop = Get-ActiveUserDesktopPath
        $scanPath = Join-Path $desktop "scan"
        if (-not (Test-Path -Path $scanPath -PathType Container)) {
            New-Item -ItemType Directory -Path $scanPath -Force | Out-Null
            Write-Host "Created folder: $scanPath" -ForegroundColor Green
        } else {
            Write-Host "Folder already exists: $scanPath" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "Failed to create/access scan folder: $_" -ForegroundColor Red
        Pause
        return
    }

    # 3) Enable Server service and open firewall rules; try enabling SMB1 for legacy devices
    try {
        Set-Service -Name LanmanServer -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name LanmanServer -ErrorAction SilentlyContinue

        if (Get-Command Enable-NetFirewallRule -ErrorAction SilentlyContinue) {
            Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Out-Null
        }

        Write-Host "Attempting to enable SMB 1.0/CIFS feature (no restart forced)..." -ForegroundColor Yellow
        $dism = Start-Process -FilePath dism.exe -ArgumentList "/online","/enable-feature","/featurename:SMB1Protocol","/All","/NoRestart" -PassThru -Wait -WindowStyle Hidden
        if ($dism.ExitCode -eq 0 -or $dism.ExitCode -eq 3010) {
            Write-Host "SMB1 feature enable attempt returned exit code $($dism.ExitCode)." -ForegroundColor Green
        } else {
            Write-Host "DISM returned code $($dism.ExitCode) while enabling SMB1. Proceeding." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "Warning: enabling SMB components failed or partially failed: $_" -ForegroundColor Yellow
    }

    # 4) NTFS permissions: grant Modify to the specified user (so Windows shows Read/Write)
    try {
        $targetAccount = $localQualified
        # Use grant:r to replace existing explicit ACE for that account; use $() to avoid parsing issues
        $icaclsCmd = "icacls"
        $grantArg = "$($targetAccount):(OI)(CI)M"
        $icaclsResult = & $icaclsCmd "$scanPath" /grant:r $grantArg /T /C 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Fallback to unqualified name
            $grantArg2 = "$($userName):(OI)(CI)M"
            $icaclsResult = & $icaclsCmd "$scanPath" /grant:r $grantArg2 /T /C 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "icacls returned non-zero, output:`n$icaclsResult" -ForegroundColor Yellow
            }
        }
        Write-Host "Granted NTFS Modify (Read/Write) to '$userName' on $scanPath." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set NTFS permissions: $_" -ForegroundColor Red
        Pause
        return
    }

    # 5) Create/update SMB share with Full access (share-level Full Control) for the user and Full for Administrators
    try {
        $shareName = "scan"
        $smbModuleLoaded = $false
        try {
            Import-Module SmbShare -ErrorAction Stop
            $smbModuleLoaded = $true
        } catch {
            $smbModuleLoaded = $false
        }

        if ($smbModuleLoaded) {
            $existingShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            if ($existingShare) {
                if ($existingShare.Path -ne $scanPath) {
                    Write-Host "Existing share '$shareName' points to a different path. Recreating..." -ForegroundColor Yellow
                    Remove-SmbShare -Name $shareName -Force -ErrorAction SilentlyContinue
                    $existingShare = $null
                }
            }

            if (-not $existingShare) {
                # Create share granting Full access to the specified user
                New-SmbShare -Name $shareName -Path $scanPath -FullAccess $localQualified -ErrorAction Stop | Out-Null

                # Clean broad groups to keep UI simple
                Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
                Revoke-SmbShareAccess -Name $shareName -AccountName "Users" -Force -ErrorAction SilentlyContinue
                Revoke-SmbShareAccess -Name $shareName -AccountName "Authenticated Users" -Force -ErrorAction SilentlyContinue

                # Ensure Administrators retain Full
                Grant-SmbShareAccess -Name $shareName -AccountName "Administrators" -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null

                Write-Host "Created SMB share '$shareName' for $scanPath granting Full Control (share-level) to $userName." -ForegroundColor Green
            } else {
                # Normalize permissions: remove broad groups and grant Full to user & admins
                Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
                Revoke-SmbShareAccess -Name $shareName -AccountName "Users" -Force -ErrorAction SilentlyContinue
                Revoke-SmbShareAccess -Name $shareName -AccountName "Authenticated Users" -Force -ErrorAction SilentlyContinue

                Grant-SmbShareAccess -Name $shareName -AccountName $localQualified -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null
                Grant-SmbShareAccess -Name $shareName -AccountName "Administrators" -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null

                Write-Host "Updated SMB share '$shareName' permissions to grant Full Control (share-level) to $userName." -ForegroundColor Green
            }
        } else {
            # net share fallback: delete existing and recreate with FULL for user and FULL for Administrators
            $existing = (& net share $shareName) 2>$null
            if ($LASTEXITCODE -eq 0 -and $existing) {
                cmd /c "net share $shareName /delete /y" | Out-Null
            }
            $escapedPath = $scanPath.Replace('"','\"')
            $escapedUser = $userName.Replace('"','\"')
            # net share syntax: /GRANT:user,PERM
            cmd /c "net share `"$shareName`"=`"$escapedPath`" /GRANT:$escapedUser,FULL /GRANT:Administrators,FULL /REMARK:`"Scanner share`"" | Out-Null
            Write-Host "Created SMB share '$shareName' (via net share) for $scanPath granting Full Control (share-level) to $userName." -ForegroundColor Green
        }
    } catch {
        Write-Host "Failed to create/update SMB share: $_" -ForegroundColor Red
        Pause
        return
    }

    Write-Host ""
    Write-Host "Scanner SMB share setup completed." -ForegroundColor Cyan
    Write-Host "Details:" -ForegroundColor Cyan
    Write-Host "  User      : $userName (password: $passwordPlain)" -ForegroundColor Green
    Write-Host "  Folder    : $scanPath" -ForegroundColor Green
    Write-Host "  Share name: scan  (\\$env:COMPUTERNAME\scan)" -ForegroundColor Green
    Write-Host "  Permissions: Share=Full Control (share-level); NTFS=Modify (Read/Write)" -ForegroundColor Green
    Pause
}

function Disable-Telemetry {
    Write-Host ""
    Write-Host "Applying telemetry/privacy tweaks (conservative mode)..." -ForegroundColor Cyan
    # Conservative: avoids aggressive actions (no ACL deny tricks, no wholesale policy deletions, no WER service disable, no svchost threshold tweaks)

    # Helpers (self-contained)
    function Set-RegValue([string]$Path, [string]$Name, [string]$Type, [object]$Value) {
        try {
            if (-not (Test-Path -Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
            return $true
        } catch {
            Write-Host "Registry set failed: $Path [$Name] => $Value :: $_" -ForegroundColor Yellow
            return $false
        }
    }

    function Disable-TaskPath([string]$FullTaskName) {
        try {
            $matches = [regex]::Match($FullTaskName, '^(\\.+\\)([^\\]+)$')
            if ($matches.Success) {
                $taskPath = $matches.Groups[1].Value
                $taskName = $matches.Groups[2].Value
                try {
                    $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
                    Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "Disabled task: $FullTaskName" -ForegroundColor Green
                    return
                } catch {
                    $null = cmd /c "schtasks /Change /TN `"$FullTaskName`" /Disable" 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Disabled task (schtasks): $FullTaskName" -ForegroundColor Green
                    } else {
                        Write-Host "Task not found or could not be disabled: $FullTaskName" -ForegroundColor DarkYellow
                    }
                }
            } else {
                $null = cmd /c "schtasks /Change /TN `"$FullTaskName`" /Disable" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Disabled task (schtasks): $FullTaskName" -ForegroundColor Green
                } else {
                    Write-Host "Task not found or could not be disabled: $FullTaskName" -ForegroundColor DarkYellow
                }
            }
        } catch {
            Write-Host "Failed to disable task: $FullTaskName :: $_" -ForegroundColor Yellow
        }
    }

    # 1) Set legacy boot menu policy (helps show F8 menu). Harmless if unsupported.
    try {
        & bcdedit /set "{current}" bootmenupolicy Legacy | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Boot menu policy set to Legacy." -ForegroundColor Green
        } else {
            Write-Host "bcdedit returned code $LASTEXITCODE (continuing)." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "Failed to set bootmenupolicy Legacy: $_" -ForegroundColor Yellow
    }

    # 2) On builds < 22557, touch Task Manager Preferences to apply tweak (index 28 byte -> 0)
    try {
        $build = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild -ErrorAction Stop).CurrentBuild
        if ([int]$build -lt 22557) {
            Write-Host "Adjusting Task Manager preferences for legacy builds (<22557)..." -ForegroundColor Yellow
            $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
            $preferences = $null

            for ($i = 0; $i -lt 80 -and -not $preferences; $i++) {
                Start-Sleep -Milliseconds 100
                $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
            }

            if ($preferences -and $preferences.Preferences -is [byte[]]) {
                if ($preferences.Preferences.Length -ge 29) {
                    $prefs = $preferences.Preferences
                    $prefs[28] = 0
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $prefs -Force
                    Write-Host "Task Manager preference byte[28] set to 0." -ForegroundColor Green
                } else {
                    Write-Host "Task Manager Preferences length unexpected; skipped tweak." -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "Task Manager Preferences not found; skipped tweak." -ForegroundColor DarkYellow
            }

            try { if ($taskmgr -and -not $taskmgr.HasExited) { Stop-Process -Id $taskmgr.Id -Force -ErrorAction SilentlyContinue } } catch {}
        }
    } catch {
        Write-Host "Failed adjusting Task Manager preferences: $_" -ForegroundColor Yellow
    }

    # 3) Remove Explorer namespace entry (cosmetic)
    try {
        $nsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        if (Test-Path $nsKey) {
            Remove-Item -Path $nsKey -Recurse -Force -ErrorAction Stop
            Write-Host "Removed Explorer namespace entry {0DB7E03F-FC29-4DC6-9020-FF41B59E513A}." -ForegroundColor Green
        } else {
            Write-Host "Explorer namespace key not present; nothing to remove." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "Failed removing Explorer namespace entry: $_" -ForegroundColor Yellow
    }

    # 4) Disable Defender Auto Sample Submission (2 = never send)
    try {
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop | Out-Null
        Write-Host "Disabled Defender automatic sample submission." -ForegroundColor Green
    } catch {
        Write-Host "Set-MpPreference not available or failed (Defender not present?): $_" -ForegroundColor DarkYellow
    }

    # --- Conservative telemetry reductions ---

    # A) Stop and disable core telemetry services (keep WER service intact)
    $telemetryServices = @(
        'DiagTrack',                                         # Connected User Experiences and Telemetry
        'dmwappushservice',                                  # WAP Push Message Routing
        'diagnosticshub.standardcollector.service'           # Diagnostics Hub
    )
    foreach ($svc in $telemetryServices) {
        try {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($null -ne $s) {
                if ($s.Status -ne 'Stopped') { try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {} }
                try { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
                Write-Host "Service disabled: $svc" -ForegroundColor Green
            } else {
                Write-Host "Service not found (skipped): $svc" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "Error handling service $svc :: $_" -ForegroundColor Yellow
        }
    }

    # B) Disable CEIP/telemetry/feedback tasks (WER queue task is safe to disable)
    $telemetryTasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Autochk\Proxy',
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\DiskFootprint\Diagnostics',
        '\Microsoft\Windows\Feedback\Siuf\DmClient',
        '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
    )
    foreach ($t in $telemetryTasks) { Disable-TaskPath -FullTaskName $t }

    # C) Apply machine-wide policy/registry changes
    $ok = $true
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowDiagnosticData' -Type DWord -Value 0)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowDeviceNameInTelemetry' -Type DWord -Value 0)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0)
    $ok = $ok -band (Set-RegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0)

    if ($ok) {
        Write-Host "Applied machine-wide policies to minimize diagnostic data and feedback prompts." -ForegroundColor Green
    } else {
        Write-Host "One or more machine policy changes failed. See warnings above." -ForegroundColor Yellow
    }

    # D) Apply per-user privacy/telemetry reductions for all existing user profiles
    try {
        $userRoots = Get-ChildItem Registry::HKEY_USERS -ErrorAction Stop | Where-Object {
            $_.Name -match 'HKEY_USERS\\S-1-5-21-\d+-\d+-\d+-\d+$'
        }

        foreach ($ur in $userRoots) {
            $sid = ($ur.Name -split '\\')[-1]
            $base = "Registry::HKEY_USERS\$sid"

            Set-RegValue -Path "$base\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name 'Enabled' -Type DWord -Value 0 | Out-Null
            Set-RegValue -Path "$base\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Type DWord -Value 0 | Out-Null
            Set-RegValue -Path "$base\Software\Microsoft\Siuf\Rules" -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0 | Out-Null
            Set-RegValue -Path "$base\Software\Microsoft\Siuf\Rules" -Name 'PeriodInNanoSeconds' -Type DWord -Value 0 | Out-Null
            Set-RegValue -Path "$base\Software\Policies\Microsoft\Windows\Explorer" -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 1 | Out-Null
            Set-RegValue -Path "$base\Software\Microsoft\Windows\CurrentVersion\Search" -Name 'BingSearchEnabled' -Type DWord -Value 0 | Out-Null
            Set-RegValue -Path "$base\Software\Microsoft\Windows\CurrentVersion\Search" -Name 'CortanaConsent' -Type DWord -Value 0 | Out-Null

            Write-Host "Applied per-user privacy settings for SID: $sid" -ForegroundColor DarkCyan
        }
    } catch {
        Write-Host "Failed applying per-user settings: $_" -ForegroundColor Yellow
    }

    # E) Disable Windows Recall feature (if present)
    try {
        Write-Host "Disabling Windows Recall feature (if available)..." -ForegroundColor Yellow
        $dism = Start-Process -FilePath dism.exe -ArgumentList "/Online","/Disable-Feature","/FeatureName:Recall","/NoRestart" -PassThru -Wait -WindowStyle Hidden
        switch ($dism.ExitCode) {
            0     { Write-Host "Recall feature disabled (no restart required)." -ForegroundColor Green }
            3010  { Write-Host "Recall feature disabled. Restart required to complete." -ForegroundColor Green }
            default {
                Write-Host "DISM returned exit code $($dism.ExitCode). Recall may not exist on this system or disable failed." -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Host "Failed to disable Recall feature: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Telemetry tweaks complete. A restart is recommended to fully apply changes." -ForegroundColor Cyan
    Pause
}

function Set-EdgePolicies {
    [CmdletBinding()]
    param(
        [switch]$Revert
    )

    Write-Host ""
    if ($Revert) {
        Write-Host "Reverting Microsoft Edge policy values to OriginalValue where provided..." -ForegroundColor Cyan
    } else {
        Write-Host "Applying Microsoft Edge policy values..." -ForegroundColor Cyan
    }

    # Define policy entries (deduplicated)
    $entries = @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"; Name="CreateDesktopShortcutDefault"; Type="DWord"; Value=0; OriginalValue=1 }

        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeEnhanceImagesEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PersonalizationReportingEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowRecommendationsEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="HideFirstRunExperience"; Type="DWord"; Value=1; OriginalValue=0 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="UserFeedbackAllowed"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ConfigureDoNotTrack"; Type="DWord"; Value=1; OriginalValue=0 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AlternateErrorPagesEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeCollectionsEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeFollowEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeShoppingAssistantEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="MicrosoftEdgeInsiderPromotionEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowMicrosoftRewards"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WebWidgetAllowed"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DiagnosticData"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeAssetDeliveryServiceEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="CryptoWalletEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WalletDonationEnabled"; Type="DWord"; Value=0; OriginalValue=1 }
    )

    $setCount = 0
    $failCount = 0
    foreach ($e in $entries) {
        $path = [string]$e.Path
        $name = [string]$e.Name
        $type = [string]$e.Type
        $targetValue = if ($Revert -and $e.ContainsKey('OriginalValue')) { [int]$e.OriginalValue } else { [int]$e.Value }

        try {
            if (-not (Test-Path -Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            # New-ItemProperty -Force updates if exists, creates if missing
            New-ItemProperty -Path $path -Name $name -PropertyType $type -Value $targetValue -Force | Out-Null
            Write-Host ("{0} -> {1} = {2} ({3})" -f $path, $name, $targetValue, $type) -ForegroundColor Green
            $setCount++
        } catch {
            Write-Host ("Failed: {0} -> {1} :: {2}" -f $path, $name, $_) -ForegroundColor Yellow
            $failCount++
        }
    }

    Write-Host ""
    Write-Host "Edge policy update complete. Set: $setCount, Failed: $failCount" -ForegroundColor Cyan
    Write-Host "Note: Restart Microsoft Edge for changes to take effect." -ForegroundColor DarkGray

    if (Get-Command Pause -ErrorAction SilentlyContinue) { Pause }
}


# --- Main Menu Loop ---

do {
    Show-MainMenu
    $mainChoice = $null
    while ($null -eq $mainChoice) {
        $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
        if ($input -match '^[0-5]$') {
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
                    if ($input -match '^[0-2]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Restart-Spooler }
                    "2" { Setup-ScannerShare }
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
        "5" { # Debloat
            $exitMenu = $false
            do {
                Show-DebloatMenu
                $choice = $null
                while ($null -eq $choice) {
                    $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
                    if ($input -match '^[0-3]$') {
                        $choice = $input
                    }
                }
                switch ($choice) {
                    "1" { Set-ServicesRecommended }
                    "2" { Disable-Telemetry }
                    "3" { Set-EdgePolicies }
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
