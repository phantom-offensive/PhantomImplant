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

#endif // _EVASION_H
