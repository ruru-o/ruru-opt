# Ruru's Win-Optimization Meowkit

![image](https://github.com/user-attachments/assets/fe8dc43a-8b2c-4381-a4f4-1e34eb7d55ec)


> [!NOTE]
> While the script is designed to handle errors, unexpected issues may still occur. A system backup is strongly recommended before running the script, and users should ensure their system meets the necessary prerequisites for the adjustments to work correctly. 

<h1>1. Introduction </a></h1>
This PowerShell script implements several system optimizations for Windows, focusing on power plan configurations, CPU scheduling, and registry adjustments to improve system performance and minimize input lag. It customizes active power plans to prioritize performance, optimizes CPU scheduling for better resource distribution, and tweaks registry settings to improve system responsiveness, including changes to I/O scheduling and background processes. 

<h1>2. Usage </a></h1>

> [!CAUTION]  
> Always review the script if you're unsure of what it does.


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

> [!CAUTION]  
> Always review the script if you're unsure of what it does.

### **3.1. Download the Required Files**

To optimize your system, download the following files:

2. **Download [ruru-opt.ps1](https://github.com/ruru-o/ruru-opt/releases/download/0.0.1/ruru-opt.ps1)**
1. **Download the Power Plan:**
   - Download the [Catnip Lowest Latency Power Plan](https://github.com/ruru-o/ruru-opt/releases/download/0.0.1/shakabo.pow)
   - Save the `.pow` file in the same directory where the **`ruru-opt.ps1`** script is stored.

### **3.2. Open and Review the Script**

1. Navigate to the folder where you saved the `ruru-opt.ps1` script and the `.pow` file.

2. Open the script with a text editor, such as **Notepad++** or **VS Code**, to review its contents.

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

This documentation explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| Change | Description | System Changes |
|------------|-------------|----------------|
| Disable Windows Update | Prevents Windows Update from automatically downloading and installing updates. | • Sets `DoNotConnectToWindowsUpdateInternetLocations=1` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`<br>• Sets `TrayIconVisibility=0` in `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`<br>• Sets `AUOptions=1` in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`<br>• Sets `SearchOrderConfig=0` in `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching`<br>• Sets `AutoDownload=2` in `HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore` |
| Disable Windows Defender |  Deactivates Windows Defender's real-time protection, antimalware, network inspection, and security features. <br> <br> This prevents issues with the CPU entering C-State 0 ([1](https://www.techpowerup.com/295877/windows-defender-can-significantly-impact-intel-cpu-performance-we-have-the-fix))  | • Sets `SpyNetReporting=0` and `SubmitSamplesConsent=0` in Spynet<br>• Disables services: Sense, WinDefend, MsSecCore, WdBoot, WdFilter<br>• Sets `DisableScanOnRealtimeEnable=1` and `DisableBehaviorMonitoring=1` in Real-Time Protection<br>• Disables SmartScreen (`SmartScreenEnabled=Off`)<br>• Sets `DisableAntiSpyware=1` in Windows Defender policies<br>• Disables HVCI (`Enabled=0` in DeviceGuard) |
| Disable Game Bar | Removes Xbox Game Bar and related gaming overlays. | • Sets `ActivationType=0` in GameBar PresenceWriter<br>• Disables ms-gamebar and ms-gamebarservices protocols<br>• Modifies registry paths to prevent Game Bar autostart |
| Disable Background Apps | Prevents Universal Windows Platform (UWP) apps from running in background. | • Sets `LetAppsRunInBackground=2` in AppPrivacy policies<br>• Affects all UWP app background execution |
| Disable Telemetry | Stops Windows diagnostic data collection and transmission to Microsoft. | • Sets `Start=4` for DiagTrack service<br>• Sets `AllowTelemetry=0` in DataCollection policies<br>• Enables `LimitDiagnosticLogCollection=1`<br>• Disables all telemetry reporting channels |
| Disable UAC | Removes User Account Control prompts and security checks. | • Sets multiple UAC-related registry values to 0:<br>- EnableVirtualization<br>- EnableInstallerDetection<br>- PromptOnSecureDesktop<br>- EnableLUA<br>- EnableSecureUIAPaths<br>- ConsentPromptBehaviorAdmin <br>- ValidateAdminCodeSignatures <br>- EnableUIADesktopToggle <br>- ConsentPromptBehaviorUser <br>- FilterAdministratorToken |
| Disable Superfetch/Prefetch | Stops Windows from preloading applications into memory. | • Sets `Start=4` for SysMain service<br>• Disables memory preallocation<br>• Stops predictive application loading |
| Optimize Memory Management | Modifies Windows memory handling for reduced paging and improved responsiveness. | • Disables page combining (`DisablePageCombining=1`)<br>• Sets `LargeSystemCache=0`<br>• Modifies pool quotas and sizes<br>• Disables memory compression<br>• Sets optimal memory management parameters |
| Optimize Executive Worker Threads | Adjusts system thread management for improved processing. | • Sets `AdditionalCriticalWorkerThreads=6`<br>• Sets `AdditionalDelayedWorkerThreads=6`<br>• Modifies thread scheduling parameters<br>• Optimizes thread priority handling |
| Optimize Kernel Performance | Fine-tunes kernel operations for system responsiveness. | • Sets DPC watchdog to disable: `0`<br>• Sets optimal timer resolution: `1`<br>• Sets interrupt steering: `1`, `0`<br>• Sets DPC queue depth: `1`<br>• Sets unlimited DPC queue: `1`<br>• Sets cache-aware scheduling: `5`<br>• Sets speculative execution mitigations to disable: `22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22`, `22,22,22,22,22,22,22,22`, `1`<br>• Sets exception chain validation to disable: `1`<br>• Sets timer expiration serialization: `2`<br>• Sets auto-boost to disable: `1`<br>• Sets timer distribution: `1`<br>• Sets thread DPC processing to disable: `0`<br>• Sets foreground boost decay to disable: `0`<br>• Sets per-CPU clock tick scheduling to disable: `0`<br>• Sets DPC timeout: `0`<br>• Sets DPC threshold: `0`<br>• Sets kernel exception handling options: `0`<br>• Sets timer check flags: `0`<br>• Sets maximum shared ready queue size: `1`<br>• Sets minimum DPC rate: `0`<br>• Sets DPC watchdog period: `0` |
| Disable Event Trace Sessions | Stops system diagnostic logging and event tracing. | • Disables SleepStudy, Kernel-Processor-Power tracers<br>• Removes Autologger functionality<br>• Stops all diagnostic data collection<br>• Disables performance monitoring traces |

## Kernel Adjustments

1. ```DPC Watchdog Disabled``` - Disables DPC watchdog to prevent unnecessary monitoring of deferred procedure calls, which can reduce processing delays.
2. ```Interrupt Steering Adjusted``` - Configures interrupt steering to optimize CPU affinity for interrupts, potentially reducing CPU contention.
3. ```DPC Queue and Scheduling Adjustments``` - Modifies the DPC queue depth and removes restrictions on queue length, improving handling of deferred procedure calls without unnecessary throttling. Enables cache-aware scheduling to reduce CPU cache misses during thread execution.
4. ```Speculative Execution Mitigations Disabled``` - Disables certain speculative execution mitigations to enhance performance, acknowledging potential trade-offs in security.
5. ```Exception Chain Validation Disabled``` - Disables the validation of exception chains, allowing faster execution at the cost of less security for exception handling.
6. ```Disabling Unnecessary Features``` - Disables thread DPC processing, foreground boost decay, and per-CPU clock tick scheduling, and reducing overhead.
                                                                            

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
