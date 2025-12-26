# ArchGuard

This repository implements a **proof-of-concept (PoC) Windows kernel driver** designed to audit the architectural integrity of the system by validating critical CPU registers against expected kernel boundaries.

The project serves as a fundamental software layer for a broader research initiative on **Hardware-Assisted System Integrity**. While `AMDStackGuard` focuses on dynamic execution flow, **ArchGuard** focuses on the static architectural state, detecting anomalies in system call handlers and interrupt tables.

> Tested on Windows 10 22H2 

## Research Context

Sophisticated rootkits and bootkits compromise systems by modifying model-specific registers (MSRs) or control registers (CRs) to hijack execution flow before the Operating System processes it. These "architectural hooks" often remain invisible to traditional file scanners or user-mode hooks.

To detect this, a trusted monitor must validate that the hardware pointers (like the Syscall entry point) point to legitimate kernel memory regions.

## Technical Architecture

<p>

The solution consists of a standalone Kernel Driver (`.sys`) that performs three distinct audits:

1.  **Syscall Integrity (MSR_LSTAR):**
*   Reads the `MSR_LSTAR` register, which controls the entry point for system calls (`syscall` instruction).
*   Verifies that the target address lies within the valid memory range of `ntoskrnl.exe`.

2.  **Interrupt Table Integrity (IDTR):**
*   Executes the `sidt` instruction to retrieve the Interrupt Descriptor Table base.
*   Ensures the table resides in canonical high-kernel memory, detecting "IDT Shadowing" attacks.

3.  **Security Feature Verification (CR4):**
*   Checks the `CR4` register to ensure **SMEP** (Supervisor Mode Execution Prevention) is enabled, detecting configuration downgrades that allow Ring 0 to execute Ring 3 code.

</p>



<p align="center">
  <img width="717" alt="Baseline Integrity" src="https://github.com/user-attachments/assets/9ad3f6bd-00aa-4dc0-ad8b-7cceaed3421c" />
  <br>
  <em><strong>Figure 1: Baseline Integrity Verification.</strong> The auditor confirms that MSR_LSTAR points within valid ntoskrnl limits and critical security features (SMEP) are active.</em>
</p>

<br>

<p align="center">
  <img width="717" alt="Attack Detection" src="https://github.com/user-attachments/assets/f020f8ef-4f23-4aa1-be56-d801c98f6f4a" />
  <br>
  <em><strong>Figure 2: Detection of Simulated Compromise. </strong>The auditor successfully flags a hooked Syscall entry pointing to unknown memory and detects disabled hardware protections.</em>
</p>



### A Note on Integrity & API Usage

To establish the valid memory range of `ntoskrnl.exe`, this PoC currently utilizes the **`ZwQuerySystemInformation`** API (SystemModuleInformation class).

> **Research Note:** In a hostile environment where a rootkit has already hooked the SSDT or the `ZwQuerySystemInformation` function itself, this baseline could be spoofed. A robust, production-grade implementation would bypass OS APIs entirely by walking the **IDT** to find the `KiPageFault` handler and scanning backwards in memory to locate the kernel's PE header (`MZ`), establishing a trust anchor purely based on hardware structures.



## Current Capabilities

- [x] **LSTAR Validation:** Detects if the system call entry point has been redirected outside the kernel image.
- [x] **IDT Verification:** Flags suspicious Interrupt Descriptor Table bases located in non-standard memory regions.
- [x] **SMEP Auditing:** Alerts if hardware exploit mitigations have been disabled at runtime.


## Disclaimer

This code is intended for educational and research purposes only. Its purpose is to demonstrate core programming concepts and memory management techniques.

## TODO

- [ ] **Robust Kernel Discovery:**
- Implement the "IDT Walking" technique mentioned above to remove dependency on `ZwQuerySystemInformation`.
- [ ] **GDT Analysis:**
- Add validation for the Global Descriptor Table (GDTR) to detect Task Gate misuse.
- [ ] **Hypervisor Detection:**
- Implement CPUID timing checks or MSR validity checks to determine if the auditor itself is being virtualized.
