#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "common.h"

// =============================================
// AES-256-CBC key and IV sizes
// =============================================
#define AES_KEYSIZE     32
#define AES_IVSIZE      16

// =============================================
// AES structure
// =============================================
typedef struct _AES {
    PBYTE   pPlainText;
    DWORD   dwPlainSize;
    PBYTE   pCipherText;
    DWORD   dwCipherSize;
    PBYTE   pKey;
    PBYTE   pIv;
} AES, *PAES;

// =============================================
// XOR encryption/decryption (bidirectional)
// =============================================

// Single-byte XOR
VOID XorByOneKey(IN PBYTE pData, IN SIZE_T sDataSize, IN BYTE bKey);

// XOR with index-based key expansion (harder to brute force)
VOID XorByiKeys(IN PBYTE pData, IN SIZE_T sDataSize, IN BYTE bKey);

// Multi-byte key XOR (repeating key)
VOID XorByInputKey(IN PBYTE pData, IN SIZE_T sDataSize, IN PBYTE bKey, IN SIZE_T sKeySize);

// =============================================
// AES-256-CBC via Windows bCrypt library
// =============================================

// Encrypt plaintext -> ciphertext (allocates output on heap)
BOOL AesEncrypt(IN PVOID pPlainTextData, IN DWORD sPlainTextSize,
                IN PBYTE pKey, IN PBYTE pIv,
                OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);

// Decrypt ciphertext -> plaintext (allocates output on heap)
BOOL AesDecrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize,
                IN PBYTE pKey, IN PBYTE pIv,
                OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);

// =============================================
// Helpers
// =============================================
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);

#endif // _CRYPTO_H
