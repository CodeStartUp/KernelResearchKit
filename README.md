# DrvLoader - Advanced Windows 11 DSE Bypass Tool

![Build Status](https://img.shields.io/badge/Platform-Windows%2011%2026200-blue)
![Bypass Type](https://img.shields.io/badge/Technique-SeCiCallbacks%20Patch-orange)

DrvLoader is a state-of-the-art research tool designed to bypass **Driver Signature Enforcement (DSE)** on the most recent builds of Windows 11 (including Build 26200+). It utilizes a sophisticated surgical manipulation of the kernel's Code Integrity (CI) callbacks to allow the loading of unsigned drivers without requiring Test Signing mode or disabling Secure Boot.

## 🚀 Why DrvLoader?

Most DSE bypass tools are currently broken on Windows 11 Build 26200 because Microsoft has stripped critical symbols and enhanced Kernel Data Protection (KDP). DrvLoader is specifically engineered to overcome these challenges.

### 🔬 Key Technical Innovations

*   **Symbol-Less Resolution**: Since `SeCiCallbacks` is no longer in public PDBs, DrvLoader uses a **Dynamic PE Pattern Scanner** to locate the callback table by analyzing `ntoskrnl.exe` instructions at runtime.
*   **KDP Bypass (Split-Write Strategy)**: Windows 11 hypervisors monitor 8-byte atomic writes to kernel pointers. DrvLoader bypasses this by utilizing a **32-bit Forced Write** fallback, splitting the 64-bit pointer into two 32-bit operations that evade current monitoring.
*   **Multi-Slot Patching (8-Slot Coverage)**: To resolve the "Driver Blocked" (Error `0x241`) issue, DrvLoader patches the first **64 bytes** (8 callback slots) of the CI structure, ensuring every possible verification path is covered.
*   **Native NT Pathing**: Uses the `\??\` prefix for all driver operations, eliminating "Invalid Name" (Error `0x7B`) issues caused by modern SCM path parsing.
*   **Idempotent Loading**: Smart driver lifecycle management prevents "Marked for Delete" (Error `1072`) conflicts by reusing existing helper handles.

## 🛠 Features

*   **Interactive GUI/CLI**: Real-time DSE status monitoring and control.
*   **Automatic HVCI Detection**: Identifies if Memory Integrity is blocking the patch.
*   **Safe Restoration**: Reverts all 8 patched slots to their original state using the same robust write strategy.
*   **PDB Fallback**: Maintains the ability to use PDB symbols if they are available for your build.
*   **State Persistence**: Saves original callback data to the registry to ensure safe restoration even after a crash or restart.

## 📖 Usage

1.  **Run as Administrator**: DrvLoader requires elevated privileges to interact with the kernel.
2.  **Patch DSE (Option 1)**: Disables signature enforcement system-wide. You will see 8 slots being patched successfully.
3.  **Load Driver (Option 2)**: Provide the full path to your `.sys` file. The tool handles the service creation and path normalization automatically.
4.  **Restore DSE (Option 1 again)**: Re-enables signature enforcement and cleans up the helper driver.

## ⚠️ Troubleshooting (Windows 11 26200)

*   **Error 0x241 (Driver Blocked)**: This means DSE is still partially active. Ensure you are using the latest version of DrvLoader that patches 8 slots.
*   **Error 1072 (Marked for Delete)**: Close any open Services window (`services.msc`) or Task Manager and try again. If it persists, a reboot is required to clear the service state.
*   **Memory Integrity**: If the patch fails, ensure "Memory Integrity" (HVCI) is disabled in Windows Security under "Core Isolation".

## ⚖️ Disclaimer

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

This framework demonstrates advanced Windows kernel security concepts. The author is not responsible for any misuse or damage caused by this tool. Always test in a controlled VM environment.

---
*Developed for the Kernel Research Community.*
