# shooki-opt

## 1. Introduction
This PowerShell script implements several system optimizations for Windows, focusing on power plan configurations, CPU scheduling, and registry adjustments to improve system performance and minimize input lag. It customizes active power plans to prioritize performance, optimizes CPU scheduling for better resource distribution, and tweaks registry settings to improve system responsiveness, including changes to I/O scheduling and background processes. 

> [!NOTE]
> While the script is designed to handle errors, unexpected issues may still occur. A system backup is strongly recommended before running the script, and users should ensure their system meets the necessary prerequisites for the adjustments to work correctly. 

## 2. Getting Started

### **Step 1: Prepare Your System**

Before running the PowerShell script, make sure you allow PowerShell scripts to run on your system.

1. **Open PowerShell as Administrator**:
   - Click the **Start Menu** and search for **PowerShell**.
   - Right-click **Windows PowerShell** and select **Run as Administrator**.
   - Confirm with **Yes** if prompted.

2. **Set Execution Policy to Unrestricted**:
   - In the PowerShell window, run the following command:
     ```powershell
     Set-ExecutionPolicy Unrestricted
     ```
   - Press **Enter** and type `Y` when prompted to confirm.

### **Step 2: Download the Required Files**

To optimize your system, download the following files:

1. **Download the Power Plan:**
   - Download the **Catnip Lowest Latency Power Plan** (`.pow` file), which will prioritize system responsiveness.
   - Save the `.pow` file in the same directory where the **`shooki-opt.ps1`** script is stored.

2. **Download the Optimization Script:**
   - Ensure the **`shooki-opt.ps1`** script is ready to run.

### **Step 3: Open and Review the Script**

Before running the script, you may want to review its contents for safety.

1. Navigate to the folder where you saved the `shooki-opt.ps1` script and the `.pow` file.

2. Open the script with a text editor, such as **Notepad** or **VS Code**, to review its contents.

> [!CAUTION]  
> Always review scripts from untrusted sources before running them. If you're unsure about the script's behavior, feel free to reach out for clarification.

### **Step 4: Run the Script**

Once you've reviewed the script, follow these steps to run it:

1. **Open PowerShell as Administrator** (if not already opened).
2. **Navigate to the Script Folder**:
   - Use the `cd` command in PowerShell to go to the directory containing `shooki-opt.ps1`. For example:
     ```powershell
     cd "C:\Path\To\Your\Script"
     ```
3. **Run the Script**:
   - Execute the script with the following command:
     ```powershell
     .\shooki-opt.ps1
     ```
   - Press **Enter**.
   - Grant **admin privileges** if prompted by the User Account Control (UAC).

> [!WARNING]  
> The script requires **administrator privileges** to modify system settings, including power plans and registry tweaks. Do not run the script if you are not comfortable with these changes.

### **Step 5: Apply the Catnip Power Plan**

Apply the **Catnip Lowest Latency Power Plan** (.pow file) through the script to optimize system performance for low-latency tasks. 

> [!CAUTION]  
> The **Catnip Lowest Latency Power Plan** disables power-saving features to prioritize performance, reducing latency for tasks like gaming or real-time processing. This may increase power consumption and reduce battery life on laptops. Use it when performance matters most.

### **Step 6: Reset Execution Policy (Optional)**

After running the script, you may want to return the PowerShell execution policy to its default setting:

1. Open **PowerShell as Administrator**.
2. Run the following command:
   ```powershell
   Set-ExecutionPolicy Restricted
   ```

## 3. Documentation
This document explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| **Name**                           | **Description**                                                                                                                                                                                | **Action**                                                                                                                                                               |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Disable Windows Update**         | Prevents automatic downloading and installation of Windows updates, which can reduce background network activity and system interruptions during critical tasks. Ideal for systems requiring minimal background activity. | Disables Windows Update service via registry, reducing its background consumption.                                                                                      |
| **Disable Windows Defender**       | Turns off Windows Defender, the built-in antivirus. This reduces security monitoring, but is recommended only for advanced users who have an alternative security solution.                        | Disables Defender service by adjusting registry values for security settings. Caution: lowers system protection.                                                       |
| **Disable Game Bar**               | Disables Windows Game Bar and related overlay features. This can help improve system performance during gaming or resource-intensive tasks by reducing background overhead.                        | Disables Game Bar through registry tweaks to prevent background app launch and overlays.                                                                               |
| **Disable Background Apps**        | Stops universal apps from running in the background, reducing resource consumption and limiting unnecessary network usage. Ideal for low-latency tasks that need all system resources available.    | Disables background apps through registry and task scheduler adjustments.                                                                                             |
| **Disable Telemetry**              | Stops the collection and transmission of diagnostic data to Microsoft, which reduces background network communication and enhances privacy.                                                     | Turns off telemetry service by modifying registry settings related to data collection.                                                                                 |
| **Disable UAC**                    | Turns off User Account Control (UAC) prompts. While this improves responsiveness by avoiding unnecessary interruptions, it significantly reduces security, as permission checks are removed.         | Disables UAC service by setting registry keys to disable prompt checks, enhancing responsiveness but reducing security.                                                 |
| **Disable Superfetch and Prefetch**| Disables services that preload application data, which can reduce disk wear on SSDs and potentially improve system responsiveness in certain configurations.                                         | Modifies registry to disable Superfetch and Prefetch services. This might improve responsiveness at the cost of application load time efficiency.                        |
| **Disable Hibernation**            | Disables hibernation, which saves a portion of the system's memory to the disk to allow for faster shutdowns and restarts. This also frees up disk space by removing the hiberfil.sys file.         | Disables hibernation by modifying registry and system settings to remove the hiberfil.sys file. Reduces disk space used by system and improves restart time.              |
| **Remove OneDrive**                | Uninstalls Microsoft OneDrive completely, removing its startup entries and integration from File Explorer. This is ideal for systems not using OneDrive for cloud storage.                          | Uninstalls OneDrive and removes its traces in the registry, disabling it from startup processes.                                                                       |
| **Remove Explorer Quick Access Home and Gallery** | Removes the default views in File Explorer like Home and Gallery, simplifying the file browsing experience and reducing system resource consumption. | Modifies registry to change Explorer’s default view to 'This PC' and removes 'Home' and 'Gallery' sections.                                                            |
| **Disable Event Trace Sessions**   | Stops Windows diagnostic and performance logging services, which can reduce background data collection and potentially improve system performance, especially on low-power systems.                  | Disables event trace and logging services through the registry to limit unnecessary background activities.                                                            |
| **Optimize File System**           | Applies various optimizations like disabling 8.3 filename creation and disabling the last access timestamp, which can improve disk I/O performance.                                                  | Updates registry settings to disable certain file system operations that may impact disk performance (e.g., file naming and access tracking).                          |
| **Perform Disk Cleanup**           | Runs the disk cleanup utility to remove temporary files, system logs, and other unnecessary data, freeing up disk space and improving overall system efficiency.                                  | Executes Disk Cleanup command via PowerShell or registry to remove system caches and unnecessary files.                                                               |
| **Disable HDCP**                   | Disables High-bandwidth Digital Content Protection (HDCP), potentially improving graphics performance and reducing associated system overhead.                                                   | Disables HDCP settings by modifying registry values related to graphics hardware.                                                                                    |
| **Disable Services**               | Disables unnecessary system services to free up background resources and improve system efficiency. Ideal for systems that need to minimize background processes.                                  | Modifies registry to disable specific Windows services deemed unnecessary for optimized performance.                                                                  |
| **Disable DPS and Threaded DPC**   | Disables the Diagnostic Policy Service (DPS) and adjusts Threaded DPC settings to enhance system responsiveness, particularly by optimizing CPU thread management.                                  | Changes registry settings to disable DPS and adjust DPC, which can improve overall system responsiveness.                                                            |
| **Optimize Memory Management**     | Applies advanced memory management settings, including optimizations to memory allocation and caching, to improve performance on systems with specific memory requirements.                         | Modifies registry for advanced memory management, including better allocation and caching strategies.                                                                 |
| **Optimize Executive Worker Threads** | Optimizes the management of worker threads that process background tasks, improving system responsiveness for multitasking and resource-intensive tasks. | Configures system registry settings to optimize the management of executive worker threads, boosting performance for multitasking.                                     |
| **Optimize Power Management Settings** | Applies advanced power management configurations designed to reduce power consumption while maintaining system performance, ideal for devices requiring battery optimization.                  | Adjusts registry values related to power management, ensuring a balanced but efficient use of power resources.                                                         |
| **Optimize Kernel Performance**    | Applies low-level kernel optimizations to improve system performance in terms of process scheduling and computational efficiency.                                                                  | Adjusts registry and kernel settings for better resource scheduling, improving overall computational efficiency.                                                     |
| **Power Plan (Catnip)**            | Provides the lowest latency power plan by disabling all power-saving features, including hibernation, and prioritizing power to performance. This ensures the system remains responsive at all times. | Applies the Catnip power plan to optimize system performance for low-latency applications. Hibernation is disabled, and performance is prioritized over energy savings. |

## Power Plan Details

### Catnip Lowest Latency Power Plan
This power plan is optimized for low-latency tasks such as gaming or real-time applications. The **Catnip Power Plan** disables all energy-saving features, including hibernation, to ensure the system maintains high performance at all times. By eliminating unnecessary power-saving mechanisms, such as CPU throttling and drive sleep, this plan ensures that the system stays responsive under demanding conditions.

- **Hibernation Disabled**: The hibernation mode, which normally saves the system's state to the disk to conserve power, is disabled. This removes the hiberfil.sys file, freeing up disk space and ensuring a quicker shutdown and restart process.
- **CPU Performance Prioritization**: The CPU is set to always perform at its highest available frequency, reducing latency in tasks that require quick processing.
- **No Power Savings**: All energy-saving features that reduce CPU speed or turn off non-essential components are disabled to maximize performance.
  
Running this plan may increase power consumption, so it is ideal for desktop systems that prioritize performance over battery life.

---

## Notes
- **Always backup your system** before making significant changes like those outlined here, especially if you are unfamiliar with registry editing.
- The tweaks listed above involve modifying system configurations, which may lead to unexpected behaviors if improperly applied. **Only advanced users or those familiar with system optimization should proceed**.
- **Security Warning**: Disabling Windows Defender or any other security-related service may expose your system to potential threats. Always ensure alternative security software is in place if you choose to disable such services.
- **System Responsiveness**: Some of these optimizations, particularly those related to disabling services, may impact how certain background functions operate. This is expected behavior but can lead to system behavior changes that users should be aware of.


## 4. References

- [valleyofdoom/PC-Tuning](https://github.com/valleyofdoom/PC-Tuning) - A repository where many of the optimizations were learned from and adapted, providing a practical basis for optimizing system performance.
- [Calypto's Latency Guide](https://calypto.us) - A comprehensive resource providing in-depth knowledge about responsive gameplay, input lag, and the essential tweaks needed for smoother, more responsive system performance.
