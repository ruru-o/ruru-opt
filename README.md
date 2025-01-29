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
> Always review scripts from untrusted sources before running them. If you're unsure about the script's behavior, feel free to reach out for clarification.

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
> Under construction. Needs more technical description.

This document explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| Tweak | Description | Technical Implementation | Impact |
|-------|-------------|-------------------------|---------|
| Disable Windows Update | Prevents automatic updates by modifying core update policies. Sets `DoNotConnectToWindowsUpdateInternetLocations=1`, `TrayIconVisibility=0`, `AUOptions=1`. | Modifies registry keys under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` and related paths. | Eliminates background update processes and network activity, but leaves system potentially vulnerable to security issues. |
| Disable Windows Defender | Comprehensively disables Windows security features by setting multiple registry values to `0` or `4`. Disables real-time protection, behavior monitoring, and sample submission. | Modifies extensive registry paths including `HKLM:\SOFTWARE\Microsoft\Windows Defender` and related service configurations. Sets all security service startup types to `4` (Disabled). | Significant performance improvement but removes critical system protection. Alternative security measures strongly recommended. |
| Disable Game Bar | Removes gaming overlay and background recording features. Sets `ActivationType=0` for the Game Bar presence writer. | Modifies registry under `HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId` and disables related protocols. | Reduces gaming-related background processes and potential frame drops. |
| Disable Background Apps | Prevents UWP apps from running in background by setting `LetAppsRunInBackground=2`. | Modifies `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy`. | Reduces memory usage and background CPU utilization. |
| Disable Telemetry | Blocks data collection by setting `AllowTelemetry=0`, disabling DiagTrack service (value `4`), and limiting diagnostic logs. | Modifies multiple registry paths under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection`. | Improves privacy and reduces background network activity. |
| Disable UAC | Disables User Account Control by setting multiple security parameters to `0`. | Modifies `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` with comprehensive security parameter changes. | Removes permission prompts but significantly reduces security. |
| Disable Superfetch/Prefetch | Disables Windows' predictive file and application loading by setting SysMain service to `4` (Disabled). | Modifies service configuration in registry under `HKLM:\SYSTEM\CurrentControlSet\Services\SysMain`. | Can improve SSD longevity and reduce disk activity. |
| Force P0-State | Forces GPU to maintain highest performance state by setting `DisableDynamicPstate=1`. | Modifies GPU driver registry settings. | Ensures consistent GPU performance but increases power consumption. |
| Optimize Memory Management | Comprehensive memory optimization including disabling page combining (`DisablePageCombining=1`) and adjusting pool sizes. | Modifies multiple values under `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`. | Optimizes memory usage for high-performance scenarios. |
| Disable DPS and Threaded DPC | Disables Diagnostic Policy Service and sets `ThreadDpcEnable=0`. | Modifies kernel parameters and service configurations. | Can improve system responsiveness but may affect system diagnostics. |
| Optimize Executive Worker Threads | Adjusts system thread management by setting additional worker threads and timer intervals. | Modifies `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive` with specific thread count adjustments. | Potentially improves multi-threaded application performance. |
| Optimize File System | Disables 8.3 filename creation and last access time updates. | Uses `fsutil` to modify system behaviors. | Improves file system performance and reduces disk overhead. |
                                                                            

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
