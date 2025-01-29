# Ruru's Win-Optimization Meowkit

![image](https://github.com/user-attachments/assets/fe8dc43a-8b2c-4381-a4f4-1e34eb7d55ec)


> [!NOTE]
> While the script is designed to handle errors, unexpected issues may still occur. A system backup is strongly recommended before running the script, and users should ensure their system meets the necessary prerequisites for the adjustments to work correctly. 

<h1>1. Introduction </a></h1>
This PowerShell script implements several system optimizations for Windows, focusing on power plan configurations, CPU scheduling, and registry adjustments to improve system performance and minimize input lag. It customizes active power plans to prioritize performance, optimizes CPU scheduling for better resource distribution, and tweaks registry settings to improve system responsiveness, including changes to I/O scheduling and background processes. 

<h1>2. Usage </a></h1>

> [!WARNING]
> Before running the PowerShell script, make sure you allow PowerShell scripts to run on your system. 

## 2.1 Prepare Your System
### 1. Open PowerShell as Administrator:
   - Click the **Start Menu** and search for **PowerShell**.
   - Right-click **Windows PowerShell** and select **Run as Administrator**.
   - Confirm with **Yes** if prompted.

### 2. Set Execution Policy to Unrestricted:
   - In the PowerShell window, run the following command:
     ```powershell
     Set-ExecutionPolicy Unrestricted
     ```
   - Press **Enter** and type `Y` when prompted to confirm.

## 2.2 Run the Script

> [!WARNING]  
> The script requires **administrator privileges** to modify system settings, including power plans and registry tweaks. Do not run the script if you are not comfortable with these changes.

Once your system is prepared, follow these steps to run the script:

1. **Open PowerShell as Administrator** (if not already opened).

2. **Copy and Paste the Commands Below**:

   Use the code below to automatically download and import the custom power plan and run the main `ruru-opt.ps1` script.

   ```powershell
   Start-Job { Invoke-RestMethod "https://raw.githubusercontent.com/ruru-o/ruru-opt/main/ruru-opt/shakabo.pow" -OutFile "C:\shakabo.pow" } | Out-Null; irm https://raw.githubusercontent.com/ruru-o/ruru-opt/main/ruru-opt/ruru-opt.ps1 | iex


This command will:
- Download the catnip lowest latency power plan to C:\ in the background.
- Run the main ruru-opt.ps1 script to apply optimizations.

## **2.3 Reset Execution Policy (Optional)**

After running the script, you may want to return the PowerShell execution policy to its default setting:

1. Open **PowerShell as Administrator**.
2. Run the following command:
   ```powershell
   Set-ExecutionPolicy Restricted

<h1>3. Manual Installation (Optional) </a></h1>

### **Step 1: Download the Required Files**

To optimize your system, download the following files:

1. **Download the Power Plan:**
   - Download the **Catnip Lowest Latency Power Plan** (`.pow` file), which will prioritize system responsiveness.
   - Save the `.pow` file in the same directory where the **`ruru-opt.ps1`** script is stored.

2. **Download the Optimization Script:**
   - Ensure the **`ruru-opt.ps1`** script is ready to run.

### **Step 2: Open and Review the Script**

Before running the script, you may want to review its contents for safety.

1. Navigate to the folder where you saved the `ruru-opt.ps1` script and the `.pow` file.

2. Open the script with a text editor, such as **Notepad** or **VS Code**, to review its contents.


> [!CAUTION]  
> Always review scripts before running them. If you're unsure about the script's behavior, feel free to reach out for clarification.

### **Step 4: Run the Script**

Once you've reviewed the script, follow these steps to run it:

1. **Open PowerShell as Administrator** (if not already opened).
2. **Navigate to the Script Folder**:
   - Use the `cd` command in PowerShell to go to the directory containing `ruru-opt.ps1`. For example:
     ```powershell
     cd "C:\Path\To\Your\Script"
     ```
3. **Run the Script**:
   - Execute the script with the following command:
     ```powershell
     .\ruru-opt.ps1
     ```
   - Press **Enter**.
   - Grant **admin privileges** if prompted by the User Account Control (UAC).


> [!WARNING]  
> The script requires **administrator privileges** to modify system settings, including power plans and registry tweaks. Do not run the script if you are not comfortable with these changes.

### **Step 5: Reset Execution Policy (Optional)**

After running the script, you may want to return the PowerShell execution policy to its default setting:

1. Open **PowerShell as Administrator**.
2. Run the following command:
   ```powershell
   Set-ExecutionPolicy Restricted
   ```

<h1>3. Documentation </a></h1>

> [!CAUTION]  
> Always review scripts before running them. 

This document explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| Tweak Name | Description | Registry/System Changes |
|------------|-------------|------------------------|
| Disable Windows Update | • Prevents all Windows Update connections and background activities<br>• Disables automatic driver updates and store downloads | • `DoNotConnectToWindowsUpdateInternetLocations` = 1 (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)<br>• `TrayIconVisibility` = 0 (HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings)<br>• `AUOptions` = 1 (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update)<br>• `SearchOrderConfig` = 0 (HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching)<br>• `AutoDownload` = 2 (HKLM\SOFTWARE\Policies\Microsoft\WindowsStore) |
| Disable Windows Defender | • Completely deactivates real-time protection<br>• Disables all security monitoring services<br>• Removes SmartScreen filtering<br>• Terminates Network Inspection Service | • `SpyNetReporting`, `SubmitSamplesConsent` = 0 (HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet)<br>• `DisableScanOnRealtimeEnable`, `DisableBehaviorMonitoring` = 1 (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection)<br>• Multiple service `Start` values set to 4 for: WinDefend, MsSecCore, WdBoot, WdNisDrv, SecurityHealthService<br>• `DisableAntiSpyware` = 1 (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender)<br>• `EnableWebContentEvaluation` = 0 (HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost) |
| Disable Game Bar | • Removes Game Bar presence server<br>• Disables all gaming overlay features<br>• Prevents background recording | • `ActivationType` = 0 (HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter)<br>• Game Bar URL protocols disabled in HKCR\ms-gamebar and HKCR\ms-gamebarservices |
| Disable Background Apps | • Prevents UWP apps from running in background<br>• Reduces system resource usage | • `LetAppsRunInBackground` = 2 (HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy) |
| Disable Telemetry | • Stops all diagnostic data collection<br>• Disables Connected User Experiences<br>• Prevents background feedback tasks | • `Start` = 4 (HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack)<br>• `AllowTelemetry` = 0 (HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection)<br>• `LimitDiagnosticLogCollection` = 1 (HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection) |
| Disable UAC | • Removes all User Account Control prompts<br>• Disables secure desktop switching<br>• Eliminates elevation requirements | • Multiple UAC settings set to 0: `EnableVirtualization`, `EnableInstallerDetection`, `PromptOnSecureDesktop`, `EnableLUA`, `EnableSecureUIAPaths`, `ConsentPromptBehaviorAdmin`, `ValidateAdminCodeSignatures`, `EnableUIADesktopToggle`, `ConsentPromptBehaviorUser`, `FilterAdministratorToken` |
| Disable Superfetch/Prefetch | • Stops predictive application loading<br>• Reduces disk activity and SSD wear | • `Start` = 4 (HKLM\SYSTEM\CurrentControlSet\Services\SysMain)<br>• Service "SysMain" stopped and disabled |
| Disable Hibernation | • Removes hiberfil.sys file<br>• Frees up disk space<br>• Reduces power management overhead | • Executes `powercfg /h off`<br>• Removes hibernation file from system drive |
| Optimize Memory Management | • Modifies memory handling parameters<br>• Adjusts paging behavior<br>• Optimizes cache settings | • Sets multiple memory parameters in HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management:<br>• `DisablePagingExecutive` = 1<br>• `LargeSystemCache` = 0<br>• `PhysicalAddressExtension` = 1<br>• `DisablePageCombining` = 1 |
| Force P0-State | • Forces maximum performance state<br>• Prevents CPU power state transitions<br>• Maintains consistent processing speed | • `DisableDynamicPstate` = 1 for all PCI\VEN GPU devices<br>• Modifies GPU power management settings |
| Disable DPS/Threaded DPC | • Adjusts Deferred Procedure Call behavior<br>• Modifies interrupt handling<br>• Optimizes CPU scheduling | • `ThreadDpcEnable` = 0 (HKLM\System\CurrentControlSet\Control\Session Manager\kernel)<br>• Windows Update Service disabled<br>• DPC queue depth and timing modifications |
| Optimize Executive Worker Threads | • Adjusts system thread allocation<br>• Modifies thread scheduling parameters<br>• Enhances thread management | • `AdditionalCriticalWorkerThreads` = 6<br>• `AdditionalDelayedWorkerThreads` = 6<br>• `UuidSequenceNumber` = 0x002eaebf<br>• `CoalescingTimerInterval` = 0 |
| Optimize Power Management | • Maximizes performance settings<br>• Disables power saving features<br>• Maintains consistent system state | • `HibernateEnabledDefault`, `HibernateEnabled` = 0<br>• `CoalescingTimerInterval` = 0<br>• `DisableSensorWatchdog` = 1<br>• `FxVSyncEnabled` = 0<br>• `SleepStudyDisabled` = 1 |
| Optimize Kernel Performance | • Modifies core system behavior<br>• Adjusts interrupt processing<br>• Optimizes system call handling | • Comprehensive kernel parameter modifications including:<br>• `DpcWatchdogProfileOffset` = 0<br>• `KernelSEHOPEnabled` = 0<br>• `DisableExceptionChainValidation` = 1<br>• `ThreadDpcEnable` = 0<br>• `DPCTimeout` = 0<br>• `CacheAwareScheduling` = 5 |
                                                                            

# Catnip Lowest Latency Power Plan

The ```Catnip Lowest Latency Power Plan``` disables all energy-saving features to prioritize performance, reducing micro-latencies at the cost of higher power consumption.

> [!NOTE]  
> This power plan is best suited for desktop systems where power usage is not a concern.

> [!TIP]  
> Ensure proper cooling as components may generate more heat due to continuous high performance.

## Necessary Tweaks

- **Hibernation Disabled**
  - Hibernation mode is turned off, removing the `hiberfil.sys` file. This frees disk space and allows faster shutdowns and restarts.

- **CPU Performance Prioritization**
  - The CPU operates at its highest frequency, preventing delays caused by frequency scaling.

- **No Power Savings**
  - All energy-saving features are disabled, keeping components active and ready.

## Creator
- Power plan by [Catnip](https://x.com/catnippin)



<h1>4. References </a></h1>

- [valleyofdoom/PC-Tuning](https://github.com/valleyofdoom/PC-Tuning) - A repository where many of the optimizations were learned from and adapted, providing a practical basis for optimizing system performance.
- [Calypto's Latency Guide](https://calypto.us) - A comprehensive resource providing in-depth knowledge about responsive gameplay, input lag, and the essential tweaks needed for smoother, more responsive system performance.
