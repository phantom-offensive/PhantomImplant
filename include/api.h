#ifndef _API_H
#define _API_H

#include "common.h"

// =============================================
// Jenkins One-At-A-Time hashing (ASCII + Unicode)
// =============================================
DWORD HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);
DWORD HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);

// =============================================
// Custom GetProcAddress replacement
// Walks PE export table to resolve function address by hash
// No IAT footprint - uses hash comparison instead of string
// =============================================
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash);

// =============================================
// Custom GetModuleHandle replacement
// Walks PEB->Ldr linked list to find loaded DLL by hash
// No IAT footprint - uses hash comparison instead of string
// =============================================
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash);

// =============================================
// Case-insensitive string comparison helper
// =============================================
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);

#endif // _API_H
