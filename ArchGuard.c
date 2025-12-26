#include <ntddk.h>
#include <intrin.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// amd hardware definitions
#define MSR_LSTAR           0xC0000082
#define CR4_SMEP_MASK       0x100000

typedef struct _IDTR {
    UINT16 Limit;
    UINT64 Base;
} IDTR, * PIDTR;

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;


NTSTATUS LocateKernelImage() {
    NTSTATUS status;
    ULONG bytes = 0;
    PSYSTEM_MODULE_INFORMATION pMods = NULL;

	// check how much memory we need
    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

    if (bytes == 0) return STATUS_UNSUCCESSFUL;

	// asign memory in pool
    pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, bytes, 'SysM');
    if (pMods == NULL) return STATUS_INSUFFICIENT_RESOURCES;

 
    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status)) {
		// in windows , the first module is always the kernel
        PVOID kernelBase = pMods->Module[0].ImageBase;
        ULONG kernelSize = pMods->Module[0].ImageSize;

        g_KernelBase = kernelBase;
        g_KernelSize = kernelSize;

        DbgPrint("[-] ArchGuard: Kernel Found via ZwQuerySystemInformation.\n");
        DbgPrint("    Base: %p | Size: 0x%X | Name: %s\n",
            g_KernelBase, g_KernelSize, pMods->Module[0].FullPathName + pMods->Module[0].OffsetToFileName);
    }

    ExFreePoolWithTag(pMods, 'SysM');

    if (g_KernelBase == NULL) return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}


VOID AuditSyscallEntry() {
    ULONG64 lstar = __readmsr(MSR_LSTAR);

    if (lstar >= (ULONG64)g_KernelBase && lstar < ((ULONG64)g_KernelBase + g_KernelSize)) {
        DbgPrint("[+] ArchGuard: MSR_LSTAR points to valid Kernel code: %llx\n", lstar);
    }
    else {
        DbgPrint("[!] ArchGuard: MSR_LSTAR points outside ntoskrnl!: %llx\n", lstar);
    }
}

VOID AuditIDT() {
    IDTR idtr;
    __sidt(&idtr);
    // the idt needs to be in "high" memory addresses
    if (idtr.Base > 0xFFFF800000000000) {
        DbgPrint("[+] ArchGuard: IDT Base is in High Kernel Memory: %llx\n", idtr.Base);
    }
    else {
        DbgPrint("[!] ArchGuard: IDT Base looks suspicious: %llx\n", idtr.Base);
    }
}

VOID AuditSecurityFeatures() {
    ULONG64 cr4 = __readcr4();
    if (cr4 & CR4_SMEP_MASK) {
        DbgPrint("[+] ArchGuard: SMEP is ENABLED.\n");
    }
    else {
        DbgPrint("[!] ArchGuard: SMEP is DISABLED.\n");
    }
}


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[-] ArchGuard Unloaded.\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;


    status = LocateKernelImage();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Failed to locate Kernel Base. Aborting.\n");
        return status;
    }


    AuditSyscallEntry();
    AuditIDT();
    AuditSecurityFeatures();



    return STATUS_SUCCESS;
}