# Requires -RunAsAdministrator
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# Disable .NET telemetry
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

# Logging function to show registry changes
function Log-RegistryChange {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$OldValue = "Not Checked"
    )
    
    Write-Host "Registry Change:" -ForegroundColor Cyan
    Write-Host "  Path:  " -NoNewline
    Write-Host "$Path" -ForegroundColor Green
    Write-Host "  Name:  " -NoNewline
    Write-Host "$Name" -ForegroundColor Green
    Write-Host "  Old Value: " -NoNewline
    Write-Host "$OldValue" -ForegroundColor Yellow
    Write-Host "  New Value: " -NoNewline
    Write-Host "$Value" -ForegroundColor Yellow
    Write-Host ""
}

# Verify Administrator Rights with Enhanced Error Handling
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script requires Administrator rights." -ForegroundColor Red
    Write-Host "Please run the script as an Administrator." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

# Tweaks
$tweaks = @(
    @{ 
        Name = "Disable Windows Update"
        Category = "System"
        Description = "Prevents automatic downloading and installation of Windows updates, reducing background network activity and potential system interruptions."
        Action = {
            Write-Host "Disabling Windows Update..." -ForegroundColor Yellow
            $updatePaths = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
                "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
            )

            $updatePaths | ForEach-Object {
                if (!(Test-Path $_)) {
                    New-Item -Path $_ -Force | Out-Null
                }
            }

            # Windows Update Disable
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue).DoNotConnectToWindowsUpdateInternetLocations
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -OldValue $oldValue

            # Tray Icon Visibility
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "TrayIconVisibility" -ErrorAction SilentlyContinue).TrayIconVisibility
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "TrayIconVisibility" -Value 0 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "TrayIconVisibility" -Value 0 -OldValue $oldValue

            # Auto Update Options
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1 -OldValue $oldValue

            # Driver Searching
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue).SearchOrderConfig
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -OldValue $oldValue

            # Windows Store Auto Download
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue).AutoDownload
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -OldValue $oldValue
        }
    },
    @{
        Name = "Disable Windows Defender"
        Description = "Turns off Microsoft's built-in antivirus and security monitoring. Caution: This reduces system protection and is recommended only for advanced users with alternative security measures."
        Category = "Security"
        Action = {
            $registryChanges = @(
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet"
                    Values = @{
                        "SpyNetReporting" = 0
                        "SubmitSamplesConsent" = 0
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                    Values = @{
                        "SmartScreenEnabled" = "Off"
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
                    Values = @{
                        "DisableScanOnRealtimeEnable" = 1
                        "DisableBehaviorMonitoring" = 1
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
                    Values = @{
                        "EnableWebContentEvaluation" = 0
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\MsSecCore"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                    Values = @{
                        "SecurityHealth" = $null
                        "WindowsDefender" = $null
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisDrv"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService"
                    Values = @{
                        "Start" = 4
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
                    Values = @{
                        "Enabled" = 0
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection"
                    Values = @{
                        "DisableScanOnRealtimeEnable" = 1
                        "DisableOnAccessProtection" = 1
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
                    Values = @{
                        "VerifiedAndReputablePolicyState" = 0
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
                    Values = @{
                        "DisableAntiSpyware" = 1
                    }
                },
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"
                    Values = @{
                        "ServiceEnabled" = 0
                    }
                },
                @{
                    Path = "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled"
                    Values = @{
                        "(Default)" = 0
                    }
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdFilter"
                    Values = @{
                        "Start" = 4
                    }
                }
            )
            
            # Additional Disablement Lists
            $backgroundAppsChanges = @(
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
                    Values = @{
                        "LetAppsRunInBackground" = 2
                    }
                }
            )
            
            $gameBarChanges = @(
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter"
                    Values = @{
                        "ActivationType" = 0
                    }
                },
                @{
                    Path = "HKCR:\ms-gamebar"
                    Values = @{
                        "(Default)" = "Disabled"
                    }
                },
                @{
                    Path = "HKCR:\ms-gamebarservices"
                    Values = @{
                        "(Default)" = "Disabled"
                    }
                }
            )
            
            # List of Windows Defender and Security-related Services to Disable
            $defenderServices = @(
                "Sense", "wscsvc", "WdNisSvc", "WinDefend", 
                "MsSecCore", "SecurityHealthService", "WdBoot", 
                "WdNisDrv", "WdFilter"
            )
            
            # Function to Modify Registry Settings
            function Modify-RegistrySettings {
                param($registryChanges)
            
                Write-Host "Modifying Registry Settings..." -ForegroundColor Yellow
            
                foreach ($change in $registryChanges) {
                    $path = $change.Path
                    foreach ($entry in $change.Values.GetEnumerator()) {
                        try {
                            # Create registry path if it doesn't exist
                            if (!(Test-Path $path)) {
                                New-Item -Path $path -Force | Out-Null
                            }
                            
                            # Handle null value (deletion) or setting value
                            if ($entry.Value -eq $null) {
                                Remove-ItemProperty -Path $path -Name $entry.Key -ErrorAction SilentlyContinue
                            }
                            else {
                                Set-ItemProperty -Path $path -Name $entry.Key -Value $entry.Value -Force
                            }
                            
                            Write-Host "Modified: $path - $($entry.Key)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to modify: $path - $($entry.Key)" -ForegroundColor Red
                            Write-Host $_.Exception.Message -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Main Execution Block
            function Disable-WindowsDefender {
                # Verify Run as Administrator
                $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    Write-Host "Please run this script as Administrator" -ForegroundColor Red
                    return
                }
            
                # Confirm Action
                $confirmation = Read-Host "WARNING: This will significantly reduce system security. Are you sure? (Y/N)"
                if ($confirmation -ne 'Y') {
                    Write-Host "Operation cancelled." -ForegroundColor Yellow
                    return
                }
            
                # Execute Disablement
                Modify-RegistrySettings -registryChanges $registryChanges
                Modify-RegistrySettings -registryChanges $backgroundAppsChanges
                Modify-RegistrySettings -registryChanges $gameBarChanges
                
                # Disable Defender Services
                foreach ($service in $defenderServices) {
                    try {
                        Stop-Service -Name $service -Force
                        Set-Service -Name $service -StartupType Disabled
                        Write-Host "Disabled Service: $service" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Failed to disable service: $service" -ForegroundColor Red
                    }
                }
            
                Write-Host "System Features Disablement Complete" -ForegroundColor Green
                Write-Host "CAUTION: Your system is now less protected and may have reduced functionality." -ForegroundColor Red
            }
            
            # Run the Disablement Process
            Disable-WindowsDefender
            }
        },
    @{ 
        Name = "Disable Game Bar"
        Description = "Disables Windows Game Bar and related gaming overlay features, potentially improving system performance and reducing background processes."
        Category = "Gaming"
        Action = {
            Write-Host "Disabling Game Bar..." -ForegroundColor Yellow
            
            # Game Bar Presence Server
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -ErrorAction SilentlyContinue).ActivationType
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Value 0 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Value 0 -OldValue $oldValue
            
            # Game Bar URL Protocols
            $gamebarRegPaths = @(
                "HKCR:\ms-gamebar",
                "HKCR:\ms-gamebarservices"
            )
            
            $gamebarRegPaths | ForEach-Object {
                if (!(Test-Path $_)) {
                    New-Item -Path $_ -Force | Out-Null
                }
                $oldValue = (Get-ItemProperty -Path $_ -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
                Set-ItemProperty -Path $_ -Name "(Default)" -Value "Disabled" -Force
                Log-RegistryChange -Path $_ -Name "(Default)" -Value "Disabled" -OldValue $oldValue
            }
        }
    },
    @{ 
        Name = "Disable Background Apps"
        Category = "Privacy"
        Description = "Stops universal apps from running in the background, reducing resource consumption and limiting data collection and network usage."
        Action = {
            Write-Host "Disabling Background Apps..." -ForegroundColor Yellow
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -ErrorAction SilentlyContinue).LetAppsRunInBackground
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -OldValue $oldValue
        }
    },
    @{ 
        Name = "Disable Telemetry"
        Description = "Stops Windows from collecting and sending diagnostic and usage data to Microsoft, enhancing privacy and reducing background network communication."
        Category = "Privacy"
        Action = {
            Write-Host "Disabling Telemetry..." -ForegroundColor Yellow
            $telemetryPaths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack",
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            )

            $telemetryPaths | ForEach-Object {
                if (!(Test-Path $_)) {
                    New-Item -Path $_ -Force | Out-Null
                }
            }

            # Disable DiagTrack Service
            $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -ErrorAction SilentlyContinue).Start
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4 -Force
            Log-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4 -OldValue $oldValue

            # Disable Telemetry Collection
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -OldValue $oldValue

            # Limit Diagnostic Log Collection
            $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -ErrorAction SilentlyContinue).LimitDiagnosticLogCollection
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Force
            Log-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -OldValue $oldValue
        }
    },
    @{ 
        Name = "Disable UAC"
        Description = "Turns off User Account Control (UAC) prompts, which can improve system responsiveness but significantly reduces security by removing permission checks."
        Category = "Security"
        Action = {
            Write-Host "Disabling UAC..." -ForegroundColor Yellow
            $uacPaths = @{
                "EnableVirtualization" = 0
                "EnableInstallerDetection" = 0
                "PromptOnSecureDesktop" = 0
                "EnableLUA" = 0
                "EnableSecureUIAPaths" = 0
                "ConsentPromptBehaviorAdmin" = 0
                "ValidateAdminCodeSignatures" = 0
                "EnableUIADesktopToggle" = 0
                "ConsentPromptBehaviorUser" = 0
                "FilterAdministratorToken" = 0
            }

            $uacPaths.GetEnumerator() | ForEach-Object {
                $oldValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name $_.Key -ErrorAction SilentlyContinue).$($_.Key)
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name $_.Key -Value $_.Value -Force
                Log-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name $_.Key -Value $_.Value -OldValue $oldValue
            }
        }
    },
    @{ 
        Name = "Disable Superfetch and Prefetch"
        Description = "Disables system services that preload application data, which can reduce SSD wear and potentially improve system responsiveness for some configurations."
        Category = "Performance"
        Action = {
            Write-Host "Disabling Superfetch and Prefetch..." -ForegroundColor Yellow
            $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -ErrorAction SilentlyContinue).Start
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value 4 -Force
            Log-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value 4 -OldValue $oldValue
            
            # Stop the service
            try {
                Stop-Service "SysMain" -ErrorAction Stop
            }
            catch {
                Write-Host "Could not stop SysMain service" -ForegroundColor Red
            }
        }
    },
    @{ 
        Name = "Disable Hibernation"
        Description = "Turns off hibernation mode, freeing up disk space used by hiberfil.sys and potentially improving system startup and shutdown times."
        Category = "Power"
        Action = {
            Write-Host "Disabling Hibernation..." -ForegroundColor Yellow
            Start-Process "powercfg" -ArgumentList "/h off" -NoNewWindow -Wait
            Write-Host "Hibernation has been disabled" -ForegroundColor Green
        }
    },
    @{ 
        Name = "Disable Event Trace Sessions"
        Description = "Stops Windows diagnostic and performance logging services, reducing background data collection and potentially improving system performance."
        Category = "Logging"
        Action = {
            Write-Host "Disabling Event Trace Sessions..." -ForegroundColor Yellow
    
            # Disable specific event trace sessions
            $eventTraceSessions = @("SleepStudy", "Kernel-Processor-Power", "UserModePowerService")
            
            foreach ($session in $eventTraceSessions) {
                try {
                    Start-Process "wevtutil" -ArgumentList "sl", "Microsoft-Windows-$session/Diagnostic", "/e:false" -NoNewWindow -Wait
                    Write-Host "Disabled event trace session: $session" -ForegroundColor Green
                }
                catch {
                    Write-Host "Could not disable event trace session: $session" -ForegroundColor Red
                }
            }
        
            # Remove Autologger key with elevated permissions
            try {
                $key = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
                
                # Take ownership of the key
                $acl = Get-Acl $key
                $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $user, 
                    "FullControl", 
                    "ContainerInherit,ObjectInherit", 
                    "None", 
                    "Allow"
                )
                $acl.SetAccessRule($rule)
                $acl | Set-Acl $key
        
                # Remove the Autologger key
                Remove-Item -Path $key -Recurse -Force
                Write-Host "Autologger key successfully removed" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not remove Autologger key: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    },
    @{ 
        Name = "Disable Customer Experience Improvement Program"
        Description = "Disables the telemetry and feedback collection mechanisms to improve privacy and reduce background processes."
        Category = "Privacy & Telemetry"
        Action = {
            Write-Host "Disabling CEIP..." -ForegroundColor Yellow
            $disableCEIPScript = @"
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f
"@
            # Save and run the script
            $tempScriptPath = [System.IO.Path]::Combine($env:TEMP, "DisableCEIP.bat")
            Set-Content -Path $tempScriptPath -Value $disableCEIPScript
            Start-Process -FilePath $tempScriptPath -NoNewWindow -Wait
            Remove-Item -Path $tempScriptPath
        }
    },
    @{ 
        Name = "Remove OneDrive"
        Description = "Completely uninstalls Microsoft OneDrive from the system, removing associated startup entries and file explorer integrations."
        Category = "System"
        Action = {
        # Stop OneDrive processes
        Stop-Process -Name "OneDrive*" -Force -ErrorAction SilentlyContinue

        Write-Host "Removing OneDrive..." -ForegroundColor Yellow
        $uninstallPaths = @("$env:SystemRoot\SysWOW64\OneDriveSetup.exe", "$env:SystemRoot\System32\OneDriveSetup.exe")
        
        foreach ($path in $uninstallPaths) {
            if (Test-Path $path) {
                try {
                    Start-Process $path -ArgumentList "/uninstall" -Wait
                    Write-Host "OneDrive uninstaller executed: $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "Could not uninstall OneDrive from $path" -ForegroundColor Red
                }
            }
        }

        # Remove registry entries
        $registryPaths = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
            "HKLM:\SOFTWARE\Microsoft\OneDrive",
            "HKCU:\Software\Microsoft\OneDrive"
        )

        foreach ($regPath in $registryPaths) {
            try {
                if (Test-Path $regPath) {
                    Remove-Item -Path $regPath -Recurse -Force
                    Write-Host "Removed registry path: $regPath" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "Could not remove registry path: $regPath" -ForegroundColor Red
            }
        }

        # Remove OneDrive folders
        $oneDriveFolders = @(
            "$env:LOCALAPPDATA\Microsoft\OneDrive",
            "$env:PROGRAMDATA\Microsoft OneDrive",
            "C:\OneDriveTemp"
        )

        foreach ($folder in $oneDriveFolders) {
            if (Test-Path $folder) {
                try {
                    Remove-Item $folder -Recurse -Force
                    Write-Host "Removed folder: $folder" -ForegroundColor Green
                }
                catch {
                    Write-Host "Could not remove folder: $folder" -ForegroundColor Red
                }
            }
        }

        # Remove OneDrive from File Explorer
        $explorerKeys = @(
            "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
            "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        )

        foreach ($key in $explorerKeys) {
            try {
                if (Test-Path $key) {
                    Remove-Item -Path $key -Recurse -Force
                    Write-Host "Removed Explorer registry key: $key" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "Could not remove Explorer registry key: $key" -ForegroundColor Red
            }
        }

        Write-Host "OneDrive removal process completed." -ForegroundColor Cyan
    }
},
    @{ 
        Name = "Remove Explorer Quick Access Home and Gallery"
        Description = "Removes default Windows Explorer views like Home and Gallery, changing the default file browsing experience to 'This PC'."
        Category = "System"
        Action = {
            Write-Host "Removing Explorer Home and Gallery..." -ForegroundColor Yellow
            
            # Remove Home Namespace
            try {
                Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Recurse -Force -ErrorAction Stop
                Write-Host "Removed Explorer Home Namespace" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not remove Explorer Home Namespace" -ForegroundColor Red
            }
            
            # Remove Gallery Namespace
            try {
                Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Recurse -Force -ErrorAction Stop
                Write-Host "Removed Explorer Gallery Namespace" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not remove Explorer Gallery Namespace" -ForegroundColor Red
            }
            
            # Set Launch To "This PC" instead of Quick Access
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Force
            Write-Host "Set Explorer launch to 'This PC'" -ForegroundColor Green
        }
    },
    @{ 
        Name = "Optimize File System"
        Description = "Applies file system optimizations like disabling 8.3 filename creation and last access timestamp updates to improve disk performance."
        Category = "Performance"
        Action = {
            Write-Host "Optimizing File System..." -ForegroundColor Yellow
            
            try {
                # Disable 8.3 filename creation
                Start-Process "fsutil" -ArgumentList "behavior", "set", "disable8dot3", "1" -NoNewWindow -Wait
                
                # Disable last access timestamp update
                Start-Process "fsutil" -ArgumentList "behavior", "set", "disablelastaccess", "1" -NoNewWindow -Wait
                
                Write-Host "File system optimizations applied" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not apply file system optimizations" -ForegroundColor Red
            }
        }
    },
    @{ 
        Name = "Perform Disk Cleanup"
        Description = "Runs system disk cleanup utilities to remove temporary files, system logs, and other unnecessary data to free up disk space."
        Category = "Maintenance"
        Action = {
            Write-Host "Performing Disk Cleanup..." -ForegroundColor Yellow
            
            try {
                # Run Disk Cleanup utility
                Start-Process "cleanmgr.exe" -ArgumentList "/d C: /VERYLOWDISK" -NoNewWindow -Wait
                
                # Run DISM cleanup
                Start-Process "Dism.exe" -ArgumentList "/online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase" -NoNewWindow -Wait
                
                Write-Host "Disk cleanup completed" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not complete disk cleanup" -ForegroundColor Red
            }
        }
    }
    @{ 
        Name = "Disable HDCP (NVIDIA)"
        Description = "Disables High-bandwidth Digital Content Protection (HDCP), which can potentially improve graphics performance and reduce system overhead."
        Category = "Graphics"
        Action = {
            Write-Host "Disabling HDCP..." -ForegroundColor Yellow
            $hdcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000"
            
            $oldValue = (Get-ItemProperty -Path $hdcpPath -Name "RMHdcpKeyglobZero" -ErrorAction SilentlyContinue).RMHdcpKeyglobZero
            Set-ItemProperty -Path $hdcpPath -Name "RMHdcpKeyglobZero" -Value 1 -Force
            Log-RegistryChange -Path $hdcpPath -Name "RMHdcpKeyglobZero" -Value 1 -OldValue $oldValue
        }
    },
    @{ 
        Name = "Disable Services"
        Description = "Disables multiple Windows services deemed unnecessary, reducing background processes and potential system resource consumption."
        Category = "System"
        Action = {
            Write-Host "Disabling Additional Services..." -ForegroundColor Yellow
            $servicesToDisable = @(
                "AxInstSV", "tzautoupdate", "bthserv", "dmwappushservice", 
                "MapsBroker", "lfsvc", "SharedAccess", "lltdsvc", 
                "AppVClient", "NetTcpPortSharing", "CscService", "PhoneSvc", 
                "Spooler", "PrintNotify", "QWAVE", "RmSvc", 
                "RemoteAccess", "SensorDataService", "SensrSvc", "SensorService", 
                "ShellHWDetection", "SCardSvr", "ScDeviceEnum", "SSDPSRV", 
                "WiaRpc", "TabletInputService", "upnphost", "UserDataSvc", 
                "UevAgentService", "WalletService", "FrameServer", "stisvc", 
                "wisvc", "icssvc", "WSearch", "XblAuthManager", "XblGameSave",
                "WerSvc", # Windows Error Reporting Service
                "DiagTrack", # Connected User Experiences and Telemetry
                "dps", # Diagnostic Policy Service
                "Audiosrv" # Windows Audio Service
            )

            foreach ($service in $servicesToDisable) {
                try {
                    $currentService = Get-Service -Name $service -ErrorAction Stop
                    Write-Host "Disabling service: $service (Current Status: $($currentService.Status))" -ForegroundColor Yellow
                    Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                    Stop-Service -Name $service -Force -ErrorAction Stop
                    Write-Host "Service $service disabled successfully" -ForegroundColor Green
                }
                catch {
                    Write-Host "Could not disable service $service" -ForegroundColor Red
                }
            }
        }
    },
    @{ 
        Name = "Force P0-State"
        Description = "Forces the system to maintain the P0 state for CPU performance, improving responsiveness and reducing throttling."
        Category = "CPU Power Management"
        Action = {
            Write-Host "Applying Force P0-State tweak..." -ForegroundColor Yellow
            $forceP0StateScript = @"
@echo off
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
    for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\ControlSet001\Enum\%%i" /v "Driver"') do (
        for /f %%i in ('echo %%a ^| findstr "{"') do (
             Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f > nul 2>&1
        )
    )
)
"@
            # Save the script to a temp file and run it
            $tempScriptPath = [System.IO.Path]::Combine($env:TEMP, "ForceP0State.bat")
            Set-Content -Path $tempScriptPath -Value $forceP0StateScript
            Start-Process -FilePath $tempScriptPath -NoNewWindow -Wait
            Remove-Item -Path $tempScriptPath
        }
    },
    @{ 
        Name = "Disable DPS and Threaded DPC"
        Description = "Disables Diagnostic Policy Service and adjusts thread and DPC (Deferred Procedure Call) settings to potentially improve system responsiveness."
        Category = "Performance"
        Action = {
            Write-Host "Disabling Diagnostic Policy Service and Threaded DPC..." -ForegroundColor Yellow
            
            # Disable Threaded DPC
            try {
                $oldValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadDpcEnable" -ErrorAction SilentlyContinue).ThreadDpcEnable
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadDpcEnable" -Value 0 -Force
                Log-RegistryChange -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadDpcEnable" -Value 0 -OldValue $oldValue
                Write-Host "Threaded DPC disabled" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not disable Threaded DPC" -ForegroundColor Red
            }

            # Ensure Windows Update Service is disabled
            try {
                $updateService = Get-Service -Name "wuauserv" -ErrorAction Stop
                Write-Host "Disabling Windows Update Service..." -ForegroundColor Yellow
                Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction Stop
                Stop-Service -Name "wuauserv" -Force -ErrorAction Stop
                Write-Host "Windows Update Service disabled" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not disable Windows Update Service" -ForegroundColor Red
            }
        }
    },
    @{ 
        Name = "Optimize Memory Management"
        Description = "Disables paging features and adjusts memory settings to prioritize non-paged memory usage and system performance over caching."
        Category = "Performance"
        Action = {
            Write-Host "Optimizing Memory Management..." -ForegroundColor Yellow
            $memoryParams = @{
                "ClearPageFileAtShutdown" = 0
                "DisablePagingExecutive" = 1
                "FeatureSettings" = 1
                "LargeSystemCache" = 0
                "NonPagedPoolQuota" = 0
                "NonPagedPoolSize" = 0
                "PagedPoolQuota" = 0
                "PagedPoolSize" = 0
                "SecondLevelDataCache" = 0
                "SessionPoolSize" = 4
                "SessionViewSize" = 0x30
                "SystemPages" = 0
                "PhysicalAddressExtension" = 1
                "FeatureSettingsOverrideMask" = 3
                "FeatureSettingsOverride" = 3
                "EnableCfg" = 0
                "CoalescingTimerInterval" = 0
                "DisablePageCombining" = 1
            }

            $memoryParams.GetEnumerator() | ForEach-Object {
                $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name $_.Key -ErrorAction SilentlyContinue).$($_.Key)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name $_.Key -Value $_.Value -Force
                Log-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name $_.Key -Value $_.Value -OldValue $oldValue
            }
        }
    },
    @{ 
        Name = "Optimize Executive Worker Threads"
        Description = "Adjusts worker thread limits and timer settings to modify how background tasks and system processes are managed, potentially improving responsiveness for specific workloads."
        Category = "Performance"
        Action = {
            Write-Host "Optimizing Executive Worker Threads..." -ForegroundColor Yellow
            
            $executiveParams = @{
                "AdditionalCriticalWorkerThreads" = 6
                "AdditionalDelayedWorkerThreads" = 6
                "UuidSequenceNumber" = 0x002eaebf
                "CoalescingTimerInterval" = 0
            }
    
            $executiveParams.GetEnumerator() | ForEach-Object {
                $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" -Name $_.Key -ErrorAction SilentlyContinue).$($_.Key)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" -Name $_.Key -Value $_.Value -Force
                Log-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" -Name $_.Key -Value $_.Value -OldValue $oldValue
            }
        }
    },
    @{
        Name = "Optimize Power Management Settings"
        Description = "Disables hibernation and other low-power features, prioritizing consistent performance over power savings."
        Category = "Power"
        Action = {
            Write-Host "Applying Advanced Power Management Optimizations..." -ForegroundColor Yellow
            
            $powerSettingsPaths = @{
                "HibernateEnabledDefault" = 0
                "HibernateEnabled" = 0
                "CoalescingTimerInterval" = 0
                "DisableSensorWatchdog" = 1
                "FxVSyncEnabled" = 0
                "SleepStudyDisabled" = 1
                "ExitLatencyCheckEnabled" = 0
                "DisableVsyncLatencyUpdate" = 1
            }
    
            $powerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
    
            $powerSettingsPaths.GetEnumerator() | ForEach-Object {
                $oldValue = (Get-ItemProperty -Path $powerPath -Name $_.Key -ErrorAction SilentlyContinue).$($_.Key)
                Set-ItemProperty -Path $powerPath -Name $_.Key -Value $_.Value -Force
                Log-RegistryChange -Path $powerPath -Name $_.Key -Value $_.Value -OldValue $oldValue
            }
    
            Write-Host "Power management optimizations applied successfully" -ForegroundColor Green
        }
    },
    @{
        Name = "Optimize Kernel Performance"
        Description = "Tweaks kernel-level settings to adjust scheduling, interrupt handling, and DPC behavior, prioritizing stability and controlled system performance over default optimizations."
        Category = "Performance"
        Action = {
            Write-Host "Optimizing Kernel Performance..." -ForegroundColor Yellow
    
            # Regular kernel parameters
            $kernelParams = @{
                "DpcWatchdogProfileOffset" = 0
                "SeTokenSingletonAttributesConfig" = 3
                "obcaseinsensitive" = 1
                "GlobalTimerResolutionRequests" = 1
                "KernelSEHOPEnabled" = 0
                "DisableExceptionChainValidation" = 1
                "ThreadDpcEnable" = 0
                "TimerCheckFlags" = 0
                "SerializeTimerExpiration" = 2
                "AdjustDpcThreshold" = 0
                "DPCTimeout" = 0
                "DpcQueueDepth" = 1
                "MaximumSharedReadyQueueSize" = 1
                "MinimumDpcRate" = 0
                "DisableTsx" = 1
                "DpcWatchdogPeriod" = 0
                "InterruptSteeringDisabled" = 0
                "InterruptSteeringFlags" = 1
                "UnlimitDpcQueue" = 1
                "ForceForegroundBoostDecay" = 0
                "EnablePerCpuClockTickScheduling" = 0
                "DistributeTimers" = 1
                "CacheAwareScheduling" = 5
                "DisableAutoBoost" = 1
            }
    
            $kernelParams.GetEnumerator() | ForEach-Object {
                try {
                    $key = $_.Key
                    $value = $_.Value
    
                    # Retrieve the old value
                    $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name $key -ErrorAction SilentlyContinue).$key
    
                    # Set the new value
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name $key -Value $value -Force
    
                    # Log the change
                    Write-Host "Successfully updated $key to $value (Old Value: $oldValue)" -ForegroundColor Green
                }
                catch {
                    Write-Host "Error setting value for ${key}: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
    
# Special handling for hexadecimal values
$hexParams = @{
    "MitigationOptions" = "22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22"
    "MitigationOptionsAudit" = "22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22"
}

$hexParams.GetEnumerator() | ForEach-Object {
    try {
        $key = $_.Key
        $value = $_.Value

        # Force conversion of string to Byte[] with proper type casting
        $hexValue = $value -split ',' | Where-Object { $_ -ne "" } | ForEach-Object { [byte][Convert]::ToInt32($_, 16) }
        $byteArray = [System.Byte[]]$hexValue  # Ensure it's explicitly a Byte[] type

        # Retrieve the old value
        $oldValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name $key -ErrorAction SilentlyContinue).$key

        # Set the new value
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name $key -Value $byteArray -Force

        # Log the change
        Write-Host "Successfully updated $key to $($byteArray -join ',') (Old Value: $oldValue)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting hexadecimal value for ${key}: $($_.Exception.Message)" -ForegroundColor Red
    }
            }
        }
    }
)

function Toggle-ProcessorIdleStates {
    param(
        [bool]$Disable
    )

    $status = if ($Disable) { 1 } else { 0 }
    $currentScheme = (powercfg -getactivescheme).Split()[3]
    
    try {
        # Set AC and DC values
        Start-Process "powercfg" -ArgumentList @(
            "-setacvalueindex", 
            $currentScheme, 
            "sub_processor", 
            "5d76a2ca-e8c0-402f-a133-2158492d58ad", 
            $status
        ) -NoNewWindow -Wait
        
        Start-Process "powercfg" -ArgumentList @(
            "-setdcvalueindex", 
            $currentScheme, 
            "sub_processor", 
            "5d76a2ca-e8c0-402f-a133-2158492d58ad", 
            $status
        ) -NoNewWindow -Wait
        
        Start-Process "powercfg" -ArgumentList "-setactive", $currentScheme -NoNewWindow -Wait
        
        return $true
    }
    catch {
        return $false
    }
}



function Invoke-MASActivation {
    try {
        # Check Language Mode   
        if ($ExecutionContext.SessionState.LanguageMode.value__ -ne 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Windows PowerShell is not running in Full Language Mode. Please check https://massgrave.dev/fix_powershell", 
                "Activation Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # Check 3rd Party Antivirus
        $avList = Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct | 
            Where-Object { $_.displayName -notlike '*windows*' } | 
            Select-Object -ExpandProperty displayName

        if ($avList) {
            $avWarning = "3rd party Antivirus detected: $($avList -join ', ')`nThis might block the activation script."
            $result = [System.Windows.Forms.MessageBox]::Show(
                $avWarning, 
                "Antivirus Warning", 
                [System.Windows.Forms.MessageBoxButtons]::OKCancel, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            
            if ($result -eq 'Cancel') {
                return
            }
        }

        # Set TLS Security Protocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Activation Script URLs
        $URLs = @(
            'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/37ec96504a2983a5801c43e975ab78c8f9315d2a/MAS/All-In-One-Version-KL/MAS_AIO.cmd',
            'https://dev.azure.com/massgrave/Microsoft-Activation-Scripts/_apis/git/repositories/Microsoft-Activation-Scripts/items?path=/MAS/All-In-One-Version-KL/MAS_AIO.cmd&versionType=Commit&version=37ec96504a2983a5801c43e975ab78c8f9315d2a',
            'https://git.activated.win/massgrave/Microsoft-Activation-Scripts/raw/commit/37ec96504a2983a5801c43e975ab78c8f9315d2a/MAS/All-In-One-Version-KL/MAS_AIO.cmd'
        )

        $response = $null
        foreach ($URL in ($URLs | Sort-Object { Get-Random })) {
            try { 
                $response = Invoke-WebRequest -Uri $URL -UseBasicParsing 
                break 
            } catch {}
        }

        if (-not $response) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to retrieve MAS from available repositories.", 
                "Activation Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        # Verify script integrity
        $releaseHash = '49CE81C583C69AC739890D2DFBB908BDD67B862702DAAEBCD2D38F1DDCEE863D'
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.StreamWriter $stream
        $writer.Write($response)
        $writer.Flush()
        $stream.Position = 0
        $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace '-'
        
        if ($hash -ne $releaseHash) {
            [System.Windows.Forms.MessageBox]::Show(
                "Hash mismatch detected. Script integrity compromised.", 
                "Activation Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # Prepare activation script
        $rand = [Guid]::NewGuid().Guid
        $isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')
        $FilePath = if ($isAdmin) { 
            "$env:SystemRoot\Temp\MAS_$rand.cmd" 
        } else { 
            "$env:USERPROFILE\AppData\Local\Temp\MAS_$rand.cmd" 
        }

        Set-Content -Path $FilePath -Value "@::: $rand `r`n$response"

        # Check file creation
        if (-not (Test-Path $FilePath)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to create activation script file.", 
                "Activation Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        # Run activation
        $env:ComSpec = "$env:SystemRoot\system32\cmd.exe"
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c """"$FilePath"" $args""" -Wait

        # Cleanup
        $FilePaths = @("$env:SystemRoot\Temp\MAS*.cmd", "$env:USERPROFILE\AppData\Local\Temp\MAS*.cmd")
        foreach ($CleanupPath in $FilePaths) { 
            Get-Item $CleanupPath | Remove-Item 
        }

        [System.Windows.Forms.MessageBox]::Show(
            "Windows activation process completed!", 
            "Activation", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Activation failed: $($_.Exception.Message)", 
            "Activation Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# Logging function to show registry changes
function Log-RegistryChange {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$OldValue = "Not Checked"
    )
    
    Write-Host "Registry Change:" -ForegroundColor Cyan
    Write-Host "  Path:  " -NoNewline
    Write-Host "$Path" -ForegroundColor Green
    Write-Host "  Name:  " -NoNewline
    Write-Host "$Name" -ForegroundColor Green
    Write-Host "  Old Value: " -NoNewline
    Write-Host "$OldValue" -ForegroundColor Yellow
    Write-Host "  New Value: " -NoNewline
    Write-Host "$Value" -ForegroundColor Yellow
    Write-Host ""
}


# New function to import Catnip power plan
function Import-CatnipPowerPlan {
    $catnipPlanPath = "$PSScriptRoot\shakabo.pow"
    
    if (Test-Path $catnipPlanPath) {
        try {
            Write-Host "Importing Catnip Lowest Latency Power Plan..." -ForegroundColor Yellow
            # Correct way to pass parameters
            Start-Process "powercfg" -ArgumentList "/import", "`"$catnipPlanPath`"" -NoNewWindow -Wait
            [System.Windows.Forms.MessageBox]::Show("Catnip Power Plan imported successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error importing Catnip Power Plan: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Catnip Power Plan file not found!", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}

# New function to delete standard power plans
function Remove-StandardPowerPlans {
    try {
        Write-Host "Deleting Standard Power Plans..." -ForegroundColor Yellow
        
        $standardPlanIds = @(
            "381b4222-f694-41f0-9685-ff5bb260df2e",
            "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "a1841308-3541-4fab-bc81-f71556f20b4a"
        )

        foreach ($planId in $standardPlanIds) {
            Start-Process "powercfg" -ArgumentList "/delete", $planId -NoNewWindow -Wait
        }

        [System.Windows.Forms.MessageBox]::Show("Standard Power Plans deleted successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error deleting power plans: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# New function to restore default power plans
function Restore-DefaultPowerPlans {
    try {
        Write-Host "Restoring Default Power Plans..." -ForegroundColor Yellow
        
        # Reset to default power schemes
        Start-Process "powercfg" -ArgumentList "/restoredefaultschemes" -NoNewWindow -Wait

        [System.Windows.Forms.MessageBox]::Show("Default Power Plans restored successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error restoring default power plans: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Create-OptimizationGUI {
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'ruru-opt'
    $form.Size = New-Object System.Drawing.Size(1100, 920)
    $form.StartPosition = 'CenterScreen'
    
    # Deep dark mode with pastel accent
    $backgroundColor = [System.Drawing.Color]::FromArgb(255, 18, 18, 20)
    $secondaryBackColor = [System.Drawing.Color]::FromArgb(255, 26, 26, 30)
    $accentColor = [System.Drawing.Color]::FromArgb(255, 144, 176, 216)  # Pastel Blue
    $lightTextColor = [System.Drawing.Color]::FromArgb(255, 220, 220, 230)
    
    $form.BackColor = $backgroundColor
    $form.ForeColor = $lightTextColor

    # Title Font - More Distinct
    $titleFont = New-Object System.Drawing.Font("Consolas", 32, [System.Drawing.FontStyle]::Bold)
    
    # Header
    $headerFont = New-Object System.Drawing.Font("Consolas", 14, [System.Drawing.FontStyle]::Regular)
    $buttonFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)

    # Main Panel
    $mainPanel = New-Object System.Windows.Forms.Panel
    $mainPanel.Dock = 'Fill'
    $mainPanel.BackColor = $backgroundColor
    $form.Controls.Add($mainPanel)

    $titleFont = New-Object System.Drawing.Font([System.Drawing.FontFamily]::GenericMonospace, 32, [System.Drawing.FontStyle]::Bold)

    $primaryColor = [System.Drawing.Color]::White 

    # Title
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "ruru - opt"
    $titleLabel.Font = $titleFont
    $titleLabel.ForeColor = $accentColor
    $titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $titleLabel.Dock = 'Top'
    $titleLabel.Height = 80
    $mainPanel.Controls.Add($titleLabel)

# Subtitle Label
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "ruru windows meowkit"
$subtitleLabel.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)  
$subtitleLabel.ForeColor = $primaryColor 
$subtitleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$subtitleLabel.Width = $mainPanel.Width  
$subtitleLabel.Height = 12  
$subtitleLabel.Top = $titleLabel.Bottom + 2 
$mainPanel.Controls.Add($subtitleLabel)

    # Left Panel for Tweaks
    $tweaksPanel = New-Object System.Windows.Forms.Panel
    $tweaksPanel.Location = New-Object System.Drawing.Point(40, 120)
    $tweaksPanel.Size = New-Object System.Drawing.Size(600, 700) 
    $tweaksPanel.BackColor = $secondaryBackColor
    $mainPanel.Controls.Add($tweaksPanel)

    # Right Panel for Power Plan
    $powerPlanPanel = New-Object System.Windows.Forms.Panel
    $powerPlanPanel.Location = New-Object System.Drawing.Point(660, 120)
    $powerPlanPanel.Size = New-Object System.Drawing.Size(400, 450)
    $powerPlanPanel.BackColor = $secondaryBackColor
    $mainPanel.Controls.Add($powerPlanPanel)

    # Custom Button Style Function
    function New-StyledButton {
        param($Text, $Location, $Size)
        
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $Text
        $button.Location = $Location
        $button.Size = $Size
        $button.Font = $buttonFont
        $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $button.FlatAppearance.BorderColor = $accentColor
        $button.BackColor = $secondaryBackColor
        $button.ForeColor = $lightTextColor
        
        $button.Add_MouseEnter({
            $this.BackColor = $accentColor
            $this.ForeColor = [System.Drawing.Color]::Black
        })
        
        $button.Add_MouseLeave({
            $this.BackColor = $secondaryBackColor
            $this.ForeColor = $lightTextColor
        })
        
        return $button
    }

# Activator Label
$activatorLabel = New-Object System.Windows.Forms.Label
$activatorLabel.Text = "Activator"
$activatorLabel.Location = New-Object System.Drawing.Point(20, 340)
$activatorLabel.Font = $headerFont
$activatorLabel.ForeColor = $accentColor
$activatorLabel.AutoSize = $true
$powerPlanPanel.Controls.Add($activatorLabel)

# MAS-AIO Button
$masAIOButton = New-StyledButton -Text 'Run MAS-AIO' -Location (New-Object System.Drawing.Point(20, 378)) -Size (New-Object System.Drawing.Size(360, 40))
$powerPlanPanel.Controls.Add($masAIOButton)
$masAIOButton.Add_Click({ Invoke-MASActivation }) 


    # Tweak Control Buttons
    $selectAllButton = New-StyledButton -Text 'Select All Tweaks' -Location (New-Object System.Drawing.Point(40, 830)) -Size (New-Object System.Drawing.Size(280, 40))
    $mainPanel.Controls.Add($selectAllButton)
    
    $unselectAllButton = New-StyledButton -Text 'Unselect All Tweaks' -Location (New-Object System.Drawing.Point(360, 830)) -Size (New-Object System.Drawing.Size(280, 40))
    $mainPanel.Controls.Add($unselectAllButton)
    
    $applyButton = New-StyledButton -Text 'Apply Selected Optimizations' -Location (New-Object System.Drawing.Point(660, 830)) -Size (New-Object System.Drawing.Size(400, 40))
    $mainPanel.Controls.Add($applyButton)

    # Power Plan Label
    $powerPlanLabel = New-Object System.Windows.Forms.Label
    $powerPlanLabel.Text = "Power Plan Management"
    $powerPlanLabel.Location = New-Object System.Drawing.Point(20, 20)
    $powerPlanLabel.Font = $headerFont
    $powerPlanLabel.ForeColor = $accentColor
    $powerPlanLabel.AutoSize = $true
    $powerPlanPanel.Controls.Add($powerPlanLabel)

    # Power Plan Buttons
    $importPowerPlanButton = New-StyledButton -Text 'Import Catnip Lowest Latency Power Plan' -Location (New-Object System.Drawing.Point(20, 80)) -Size (New-Object System.Drawing.Size(360, 40))
    $powerPlanPanel.Controls.Add($importPowerPlanButton)
    $importPowerPlanButton.Add_Click({ Import-CatnipPowerPlan })

    $deletePowerPlansButton = New-StyledButton -Text 'Delete Standard Power Plans' -Location (New-Object System.Drawing.Point(20, 140)) -Size (New-Object System.Drawing.Size(360, 40))
    $powerPlanPanel.Controls.Add($deletePowerPlansButton)
    $deletePowerPlansButton.Add_Click({ Remove-StandardPowerPlans })

    # Restore Default Power Plans
    $restoreDefaultPowerPlansButton = New-StyledButton -Text 'Restore Default Power Plans' -Location (New-Object System.Drawing.Point(20, 200)) -Size (New-Object System.Drawing.Size(360, 40))
    $powerPlanPanel.Controls.Add($restoreDefaultPowerPlansButton)
    $restoreDefaultPowerPlansButton.Add_Click({ Restore-DefaultPowerPlans })

# Populate Tweaks
$y = 0
$categories = $tweaks | Group-Object Category

foreach ($category in $categories) {
    $categoryLabel = New-Object System.Windows.Forms.Label
    $categoryLabel.Text = "$($category.Name) Tweaks"
    $categoryLabel.Location = New-Object System.Drawing.Point(30, 12)
    $categoryLabel.Font = $headerFont
    $categoryLabel.ForeColor = $accentColor
    $categoryLabel.AutoSize = $true
    $tweaksPanel.Controls.Add($categoryLabel)
    $y += 40

    foreach ($tweak in $category.Group) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $tweak.Name
        $checkbox.Location = New-Object System.Drawing.Point(40, $y)
        $checkbox.Width = 560
        $checkbox.Font = $buttonFont
        $checkbox.ForeColor = $lightTextColor
        $checkbox.Tag = $tweak

        # desc
        $toolTip = New-Object System.Windows.Forms.ToolTip
        $toolTip.SetToolTip($checkbox, $tweak.Description)

        $tweaksPanel.Controls.Add($checkbox)
        $y += 30
    }
    $y += 20
}


    #Description
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $tweak.Name
    $checkbox.Location = New-Object System.Drawing.Point(40, $y)
    $checkbox.Width = 560
    $checkbox.Font = $buttonFont
    $checkbox.ForeColor = $lightTextColor
    $checkbox.Tag = $tweak
    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.SetToolTip($checkbox, $tweak.Description)
    
    $tweaksPanel.Controls.Add($checkbox)
    $y += 30

# GUI
$toggleIdleStatesButton = New-StyledButton -Text 'Toggle Processor Idle States' -Location (New-Object System.Drawing.Point(20, 260)) -Size (New-Object System.Drawing.Size(360, 40))
$powerPlanPanel.Controls.Add($toggleIdleStatesButton)

$toggleIdleStatesButton.Add_Click({

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Choose Processor Idle State'
    $form.Size = New-Object System.Drawing.Size(460, 250) 
    $form.StartPosition = 'CenterScreen' 
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.ForeColor = [System.Drawing.Color]::White
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Choose how you want to manage Processor Idle States:' + "`n`n" + 
                 '1. Disable Idle States: More responsive, higher temperature and power usage.' + "`n`n" +
                 '2. Enable Idle States: Less responsive, lower temperature and power usage (Windows default).'
    $label.Size = New-Object System.Drawing.Size(420, 100) 
    $label.Location = New-Object System.Drawing.Point(20, 20)
    $label.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)  
    $label.TextAlign = 'MiddleLeft'
    $form.Controls.Add($label)

    # radio buttons
    $buttonWidth = 180

    # (Enable Idle States)
    $enableRadioButton = New-Object System.Windows.Forms.RadioButton
    $enableRadioButton.Text = 'Enable Idle States'
    $enableRadioButton.Location = New-Object System.Drawing.Point(20, 130) 
    $enableRadioButton.Size = New-Object System.Drawing.Size($buttonWidth, 20)
    $enableRadioButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)  
    $enableRadioButton.Checked = $true  # Default to Enable
    $enableRadioButton.ForeColor = [System.Drawing.Color]::White
    $enableRadioButton.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $form.Controls.Add($enableRadioButton)

    # (Disable Idle States)
    $disableRadioButton = New-Object System.Windows.Forms.RadioButton
    $disableRadioButton.Text = 'Disable Idle States'
    $disableRadioButton.Location = New-Object System.Drawing.Point(240, 130) 
    $disableRadioButton.Size = New-Object System.Drawing.Size($buttonWidth, 20)
    $disableRadioButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular) 
    $disableRadioButton.ForeColor = [System.Drawing.Color]::White
    $disableRadioButton.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $form.Controls.Add($disableRadioButton)

    # Add Apply and Cancel buttons
    $applyButton = New-Object System.Windows.Forms.Button
    $applyButton.Text = 'Apply'
    $applyButton.Location = New-Object System.Drawing.Point(80, 180) 
    $applyButton.Size = New-Object System.Drawing.Size(80, 30)
    $applyButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold) 
    $applyButton.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
    $applyButton.ForeColor = [System.Drawing.Color]::White
    $applyButton.Add_Click({
        if ($enableRadioButton.Checked) {
            Toggle-ProcessorIdleStates -Disable $false
            [System.Windows.Forms.MessageBox]::Show("Processor Idle States have been enabled for better power efficiency.", "Action Completed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } elseif ($disableRadioButton.Checked) {
            Toggle-ProcessorIdleStates -Disable $true
            [System.Windows.Forms.MessageBox]::Show("Processor Idle States have been disabled for better performance.", "Action Completed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        $form.Close()
    })
    $form.Controls.Add($applyButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = New-Object System.Drawing.Point(220, 180) 
    $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
    $cancelButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)  
    $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(169, 169, 169)
    $cancelButton.ForeColor = [System.Drawing.Color]::White
    $cancelButton.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($cancelButton)

    $form.ShowDialog()
})

    # Select All and Unselect All Button
    $selectAllButton.Add_Click({
        $tweaksPanel.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] } | ForEach-Object {
            $_.Checked = $true
        }
    })

    $unselectAllButton.Add_Click({
        $tweaksPanel.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] } | ForEach-Object {
            $_.Checked = $false
        }
    })

    # Apply Button
    $applyButton.Add_Click({
        $selectedTweaks = $tweaksPanel.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckBox] -and $_.Checked -and $_.Tag -ne $null }
        
        $selectedTweaks | ForEach-Object {
            try {
                Write-Host "`nApplying Tweak: $($_.Tag.Name)" -ForegroundColor Magenta
                $_.Tag.Action.Invoke()
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error applying tweak: $($_.Tag.Name)`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        
        [System.Windows.Forms.MessageBox]::Show("Selected optimizations completed!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    })

    $form.ShowDialog()
}


Clear-Host
$asciiArtStart = @"
--------------------------------------------------
                 
                                               _   
                                              | |  
  _ __ _   _ _ __ _   _   ______    ___  _ __ | |_ 
 | '__| | | | '__| | | | |______|  / _ \| '_ \| __|
 | |  | |_| | |  | |_| |          | (_) | |_) | |_ 
 |_|   \__,_|_|   \__,_|           \___/| .__/ \__|
                                        | |        
                                        |_|                    
-------------- ruru windows meowkit --------------
                    v0.0.1
"@
Write-Host $asciiArtStart -ForegroundColor White

Create-OptimizationGUI


$asciiArtComplete = @"
                            _      _         
                           | |    | |        
   ___ ___  _ __ ___  _ __ | | ___| |_ ___   
  / __/ _ \| '_ ` _ \| '_ \| |/ _ \ __/ _ \  
 | (_| (_) | | | | | | |_) | |  __/ ||  __/_ 
  \___\___/|_| |_| |_| .__/|_|\___|\__\___(_)
                     | |                     
                     |_|                     
  tweaks implemented.     
"@
Write-Host $asciiArtComplete -ForegroundColor Green
