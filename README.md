# Ruru's Win-Optimization Meowkit

![image](https://github.com/user-attachments/assets/fe8dc43a-8b2c-4381-a4f4-1e34eb7d55ec)


> [!NOTE]
> While the script is designed to handle errors, unexpected issues may still occur. A system backup is strongly recommended before running the script, and users should ensure their system meets the necessary prerequisites for the adjustments to work correctly. 

<h1>1. Introduction </a></h1>
This PowerShell script implements several system optimizations for Windows, focusing on power plan configurations, CPU scheduling, and registry adjustments to improve system performance and minimize input lag. It customizes active power plans to prioritize performance, optimizes CPU scheduling for better resource distribution, and tweaks registry settings to improve system responsiveness, including changes to I/O scheduling and background processes. 

<h1>2. Usage </a></h1>

> [!WARNING]
> Before running the PowerShell script, make sure you allow PowerShell scripts to run on your system. 

## 2.1 Open PowerShell as Administrator:
   - Click the **Start Menu** and search for **PowerShell**.
   - Right-click **Windows PowerShell** and select **Run as Administrator**.
   - Confirm with **Yes** if prompted.

## 2.2. Set Execution Policy to Unrestricted:
   - In the PowerShell window, run the following command:
     ```powershell
     Set-ExecutionPolicy Unrestricted
     ```
   - Press **Enter** and type `Y` when prompted to confirm.

## 2.3 Run the Script

> [!WARNING]  
> The script requires **administrator privileges** to modify system settings, including power plans and registry tweaks. Do not run the script if you are not comfortable with these changes.

### 1. **Open PowerShell as Administrator**
   - If you haven't done so already, right-click the PowerShell application and select **Run as Administrator**.

### 2. **Copy and Paste the Command Below**

```powershell
Start-Job { Invoke-RestMethod "https://raw.githubusercontent.com/ruru-o/ruru-opt/main/ruru-opt/shakabo.pow" -OutFile "C:\shakabo.pow" } | Out-Null; irm https://raw.githubusercontent.com/ruru-o/ruru-opt/main/ruru-opt/ruru-opt.ps1 | iex
```

## What the command does:
- **Downloads** the **Catnip Lowest Latency Power Plan** (`shakabo.pow` file) to `C:\` in the background.
- **Runs** the main ```ruru-opt.ps1``` script.

<h1>3. Manual Installation (Optional) </a></h1>

### **3.1. Download the Required Files**

To optimize your system, download the following files:

1. **Download the Power Plan:**
   - Download the **Catnip Lowest Latency Power Plan** (`.pow` file), which will prioritize system responsiveness.
   - Save the `.pow` file in the same directory where the **`ruru-opt.ps1`** script is stored.

2. **Download the Optimization Script:**
   - Ensure the **`ruru-opt.ps1`** script is ready to run.

### **3.2. Open and Review the Script**

Before running the script, you may want to review its contents for safety.

1. Navigate to the folder where you saved the `ruru-opt.ps1` script and the `.pow` file.

2. Open the script with a text editor, such as **Notepad** or **VS Code**, to review its contents.


> [!CAUTION]  
> Always review scripts before running them. If you're unsure about the script's behavior, feel free to reach out for clarification.

### **3.3. Run the Script**

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

### **3.4. Reset Execution Policy (Optional)**

After running the script, you may want to return the PowerShell execution policy to its default setting:

1. Open **PowerShell as Administrator**.
2. Run the following command:
   ```powershell
   Set-ExecutionPolicy Restricted
   ```

<h1>3. Documentation </a></h1>

> [!CAUTION]  
> Always review scripts before running them. 

This documentation explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| Tweak Name | Description | System Changes |
|------------|-------------|----------------|
| Disable Windows Update | Prevents Windows Update from automatically downloading and installing updates. | • Sets `DoNotConnectToWindowsUpdateInternetLocations=1` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`<br>• Sets `TrayIconVisibility=0` in `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`<br>• Sets `AUOptions=1` in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`<br>• Sets `SearchOrderConfig=0` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching`<br>• Sets `AutoDownload=2` in `HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore` |
| Disable Windows Defender | Deactivates Windows Defender's real-time protection, antimalware, network inspection, and security features. | • Sets `SpyNetReporting=0` and `SubmitSamplesConsent=0` in Spynet<br>• Disables services: Sense, WinDefend, MsSecCore, WdBoot, WdFilter<br>• Sets `DisableScanOnRealtimeEnable=1` and `DisableBehaviorMonitoring=1` in Real-Time Protection<br>• Disables SmartScreen (`SmartScreenEnabled=Off`)<br>• Sets `DisableAntiSpyware=1` in Windows Defender policies<br>• Disables HVCI (`Enabled=0` in DeviceGuard) |
| Disable Game Bar | Removes Xbox Game Bar and related gaming overlays. | • Sets `ActivationType=0` in GameBar PresenceWriter<br>• Disables ms-gamebar and ms-gamebarservices protocols<br>• Modifies registry paths to prevent Game Bar autostart |
| Disable Background Apps | Prevents Universal Windows Platform (UWP) apps from running in background. | • Sets `LetAppsRunInBackground=2` in AppPrivacy policies<br>• Affects all UWP app background execution |
| Disable Telemetry | Stops Windows diagnostic data collection and transmission to Microsoft. | • Sets `Start=4` for DiagTrack service<br>• Sets `AllowTelemetry=0` in DataCollection policies<br>• Enables `LimitDiagnosticLogCollection=1`<br>• Disables all telemetry reporting channels |
| Disable UAC | Removes User Account Control prompts and security checks. | • Sets multiple UAC-related registry values to 0:<br>- EnableVirtualization<br>- EnableInstallerDetection<br>- PromptOnSecureDesktop<br>- EnableLUA<br>- EnableSecureUIAPaths<br>- ConsentPromptBehaviorAdmin <br>- ValidateAdminCodeSignatures <br>- EnableUIADesktopToggle <br>- ConsentPromptBehaviorUser <br>- FilterAdministratorToken |
| Disable Superfetch/Prefetch | Stops Windows from preloading applications into memory. | • Sets `Start=4` for SysMain service<br>• Disables memory preallocation<br>• Stops predictive application loading |
| Optimize Memory Management | Modifies Windows memory handling for reduced paging and improved responsiveness. | • Disables page combining (`DisablePageCombining=1`)<br>• Sets `LargeSystemCache=0`<br>• Modifies pool quotas and sizes<br>• Disables memory compression<br>• Sets optimal memory management parameters |
| Optimize Executive Worker Threads | Adjusts system thread management for improved processing. | • Sets `AdditionalCriticalWorkerThreads=6`<br>• Sets `AdditionalDelayedWorkerThreads=6`<br>• Modifies thread scheduling parameters<br>• Optimizes thread priority handling |
| Optimize Kernel Performance | Fine-tunes kernel operations for system responsiveness. | • **Disables DPC Watchdog:** `DpcWatchdogProfileOffset` is set to `dword:00000000`, which disables the DPC (Deferred Procedure Call) watchdog timer, preventing automatic system restarts when a DPC delay exceeds a threshold. This allows critical processes more time to complete.<br> • **Sets Optimal Timer Resolution:** `GlobalTimerResolutionRequests` is set to `dword:00000001`, which improves the granularity of system timers, reducing latency and making time-sensitive operations more precise.<br> • **Modifies Interrupt Steering:** `InterruptSteeringDisabled` is set to `dword:00000000`, enabling interrupt steering. This ensures that hardware interrupts are distributed efficiently across multiple CPU cores, improving load balancing and reducing bottlenecks.<br> • **Adjusts DPC Queue Parameters:** `DpcQueueDepth` is set to `dword:00000001`, limiting the number of deferred procedure calls in the queue to avoid excessive delays in processing high-priority tasks.<br> • **Optimizes Cache-Aware Scheduling:** `CacheAwareScheduling` is set to `dword:00000005`, which allows the system to better schedule processes based on cache locality. This minimizes cache misses and improves the performance of multi-core processors by ensuring threads run on cores with the most relevant cached data.<br> • **Disables Speculative Execution Mitigations:** The `MitigationOptions` and `MitigationOptionsAudit` are set to `hex:22,22,22,...`, which disables certain mitigations for speculative execution vulnerabilities (like Spectre and Meltdown) that may reduce performance. This tweak is particularly useful in workloads where speed is critical and security mitigations are handled elsewhere.<br> • **Disables TSX (Transactional Synchronization Extensions):** `DisableTsx` is set to `dword:00000001`, which disables TSX. This prevents potential instability caused by certain workloads in CPUs with TSX support, improving reliability for specific tasks.<br> • **Reduces DPC Timeout:** `DpcWatchdogPeriod` is set to `dword:00000000`, removing the DPC watchdog timeout period, allowing more time for deferred procedures to complete without triggering an unnecessary system reboot.<br> • **Improves Interrupt Handling:** `InterruptSteeringFlags` is set to `dword:00000001`, optimizing how interrupt requests are distributed across cores, reducing interrupt latency and improving system responsiveness under heavy loads.<br> • **Unlimits DPC Queue:** `UnlimitDpcQueue` is set to `dword:00000001`, which removes the limit on the DPC queue size. This allows the system to handle more deferred tasks concurrently, reducing the risk of critical processes being delayed.<br> • **Reduces Foreground Boost Decay:** `ForceForegroundBoostDecay` is set to `dword:00000000`, which prevents the automatic reduction of foreground process priority, ensuring that interactive applications remain responsive during extended activity.<br> • **Distributes Timers More Efficiently:** `DistributeTimers` is set to `dword:00000001`, which improves the distribution of timer interrupts across all available CPU cores, reducing the chance of core overload and improving multitasking performance.<br> • **Optimizes CPU Clock Tick Scheduling:** `EnablePerCpuClockTickScheduling` is set to `dword:00000000`, which ensures that CPU clock ticks are not unnecessarily distributed across multiple cores, preserving power efficiency and reducing overhead.<br> • **Disables Auto-Boosting:** `DisableAutoBoost` is set to `dword:00000001`, which disables the automatic boosting of CPU power states for high-load situations. This can reduce power consumption and heat output, ensuring better thermal management during extended workloads.<br> |
| Disable Event Trace Sessions | Stops system diagnostic logging and event tracing. | • Disables SleepStudy, Kernel-Processor-Power tracers<br>• Removes Autologger functionality<br>• Stops all diagnostic data collection<br>• Disables performance monitoring traces |
                                                                            

## Catnip Lowest Latency Power Plan

The ```Catnip Lowest Latency Power Plan``` disables all energy-saving features to prioritize performance, reducing micro-latencies at the cost of higher power consumption. 
By [Catnip](https://x.com/catnippin)

> [!NOTE]  
> This power plan is best suited for desktop systems where power usage is not a concern.

> [!TIP]  
> Ensure proper cooling as components may generate more heat due to continuous high performance.

## Power Plan Tweaks

- Hibernation mode is turned off, removing the `hiberfil.sys` file. This frees disk space and allows faster shutdowns and restarts.
- The CPU operates at its highest frequency, preventing delays caused by frequency scaling.
- All energy-saving features are disabled, keeping components active and ready.
- Disable CPU idle states (the script provides an option to enable them if cooling is insufficient, as disabling idle keeps CPU at 100% usage, causing higher temps). See [Calypto's Latency Guide](https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4/edit?tab=t.0) for more info.
- Disables power saving features
- Disables core parking
- Sets maximum processor frequency
- Disables USB selective suspend
- Optimizes PCI Express power management

## Service Modifications

Disables multiple system services including:
- Print Spooler
- Windows Index Search (See [Search Indexing](https://github.com/valleyofdoom/PC-Tuning?tab=readme-ov-file#search-indexing) by [valleyofdoom](https://github.com/valleyofdoom) for more info)
- Windows Error Reporting
- Connected User Experiences
- Diagnostic Policy Service
- Various Xbox services
- Multiple background system services

## File System Optimizations

- Disables 8.3 filename creation
- Disables last access timestamp updates
- Optimizes NTFS parameters

## Additional System Changes

- Removes OneDrive integration
- Disables Windows Explorer features (Quick Access, Home, Gallery)
- Modifies system timer resolution (see [Clock Interrupt Frequency (Timer Resolution)](https://github.com/valleyofdoom/PC-Tuning?tab=readme-ov-file#clock-interrupt-frequency-timer-resolution) by [valleyofdoom](https://github.com/valleyofdoom))
- Adjusts processor scheduling policies
- Optimizes network settings
- Disables various system monitoring features
- Forces P0 (maximum performance) state

<h1>4. References </a></h1>

- [valleyofdoom/PC-Tuning](https://github.com/valleyofdoom/PC-Tuning) - A repository where many of the optimizations were learned from and adapted, providing a practical basis for optimizing system performance.
- [Calypto's Latency Guide](https://calypto.us) - A comprehensive resource providing in-depth knowledge about responsive gameplay, input lag, and the essential tweaks needed for smoother, more responsive system performance.
