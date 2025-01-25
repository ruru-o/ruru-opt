# shooki-opt

<h1>1. Introduction </a></h1>
This PowerShell script implements several system optimizations for Windows, focusing on power plan configurations, CPU scheduling, and registry adjustments to improve system performance and minimize input lag. It customizes active power plans to prioritize performance, optimizes CPU scheduling for better resource distribution, and tweaks registry settings to improve system responsiveness, including changes to I/O scheduling and background processes. 


> [!NOTE]
> While the script is designed to handle errors, unexpected issues may still occur. A system backup is strongly recommended before running the script, and users should ensure their system meets the necessary prerequisites for the adjustments to work correctly. 

<h1>2. Getting Started </a></h1>

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

<h1>3. Documentation </a></h1>

This document explains the system tweaks applied by the PowerShell optimization script, including registry changes, power plan configurations, and other adjustments intended to reduce latency and improve system responsiveness.

| **Name**                           | **Description**                                                                                                                                                                                | **Action**                                                                                                                                                               |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Disable Windows Update**         | Prevents automatic Windows updates, reducing background activity and interruptions.                                                                                                             | Disables updates via registry, including update service, notifications, and driver searches.                                                                            |
| **Disable Windows Defender**       | Turns off the built-in antivirus for advanced users with alternative solutions.                                                                                                                 | Modifies registry to disable Defender services and features.                                                                                                            |
| **Disable Game Bar**               | Stops Game Bar and overlays, reducing background overhead for gaming or intensive tasks.                                                                                                       | Adjusts registry to disable Game Bar and related features.                                                                                                              |
| **Disable Background Apps**        | Stops apps from running in the background, freeing system resources for critical tasks.                                                                                                         | Disables background apps through registry and task scheduler.                                                                                                           |
| **Disable Telemetry**              | Halts diagnostic data collection to enhance privacy and reduce network activity.                                                                                                                | Disables telemetry by modifying data collection registry settings.                                                                                                      |
| **Disable UAC**                    | Removes User Account Control prompts, improving flow but reducing security.                                                                                                                     | Disables UAC prompts through registry changes.                                                                                                                          |
| **Disable Superfetch and Prefetch**| Turns off preloading services, reducing disk activity on SSDs.                                                                                                                                 | Disables Superfetch and Prefetch via registry adjustments.                                                                                                              |
| **Disable Hibernation**            | Disables hibernation, freeing disk space and improving shutdown/restart times.                                                                                                                  | Removes hibernation and deletes the hiberfil.sys file through system settings.                                                                                          |
| **Remove OneDrive**                | Uninstalls OneDrive and removes its integration from File Explorer.                                                                                                                             | Removes OneDrive and related entries via registry.                                                                                                                      |
| **Remove Explorer Quick Access Home and Gallery** | Simplifies File Explorer by removing default views like Home and Gallery.                                                                                         | Sets Explorer’s default view to 'This PC' and removes unnecessary sections via registry.                                                                                |
| **Disable Event Trace Sessions**   | Stops diagnostic logging services, reducing unnecessary background processes.                                                                                                                   | Disables trace and logging services via registry adjustments.                                                                                                           |
| **Optimize File System**           | Enhances disk performance by disabling unnecessary file system operations like 8.3 filenames and last access tracking.                                                                           | Updates file system-related registry settings.                                                                                                                          |
| **Perform Disk Cleanup**           | Clears temporary files, logs, and other redundant data to free disk space.                                                                                                                      | Executes cleanup commands via PowerShell and registry changes.                                                                                                          |
| **Disable HDCP**                   | Disables HDCP to reduce graphics overhead, improving performance.                                                                                                                               | Modifies HDCP-related registry values.                                                                                                                                  |
| **Disable Services**               | Stops non-essential services to optimize background resource usage.                                                                                                                             | Adjusts registry to disable unnecessary system services.                                                                                                                |
| **Disable DPS and Threaded DPC**   | Optimizes CPU thread management by disabling Diagnostic Policy Service and adjusting DPC.                                                                                                       | Modifies registry to improve CPU responsiveness and efficiency.                                                                                                         |
| **Optimize Memory Management**     | Configures advanced memory allocation and caching for better resource utilization.                                                                                                              | Adjusts memory-related registry settings for optimized performance.                                                                                                     |
| **Optimize Executive Worker Threads** | Enhances task handling by optimizing background worker thread management.                                                                                            | Updates registry to streamline thread processing.                                                                                                                       |
| **Optimize Power Management Settings** | Applies configurations to balance performance and power consumption for battery efficiency.                                                                                                    | Tweaks power management registry settings.                                                                                                                              |
| **Optimize Kernel Performance**    | Improves process scheduling and computational tasks via kernel-level adjustments.                                                                                                               | Modifies kernel registry settings for efficient resource allocation.                                                                                                    |
                                                                            

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


<h1>4. References </a></h1>

- [valleyofdoom/PC-Tuning](https://github.com/valleyofdoom/PC-Tuning) - A repository where many of the optimizations were learned from and adapted, providing a practical basis for optimizing system performance.
- [Calypto's Latency Guide](https://calypto.us) - A comprehensive resource providing in-depth knowledge about responsive gameplay, input lag, and the essential tweaks needed for smoother, more responsive system performance.
