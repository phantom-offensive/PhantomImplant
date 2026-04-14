/**
 * PhantomImplant - Minimal Msgpack Decoder
 *
 * Decodes Phantom C2 server responses (RegisterResponse, CheckInResponse).
 * Only implements the subset of msgpack needed for our protocol:
 *   - fixmap, map16
 *   - fixstr, str8, str16
 *   - fixint, uint8, uint16, uint32, int8, int16, int32
 *   - fixarray, array16
 *   - bin8, bin16, bin32
 *   - nil, true, false
 */

#include "common.h"
#include "transport.h"
#include <stdio.h>
#include <string.h>

// =============================================
// Msgpack type masks
// =============================================
#define MP_FIXMAP_MASK      0x80
#define MP_FIXSTR_MASK      0xA0
#define MP_FIXARRAY_MASK    0x90
#define MP_FIXINT_MASK      0x00
#define MP_NIL              0xC0
#define MP_FALSE            0xC2
#define MP_TRUE             0xC3
#define MP_BIN8             0xC4
#define MP_BIN16            0xC5
#define MP_BIN32            0xC6
#define MP_UINT8            0xCC
#define MP_UINT16           0xCD
#define MP_UINT32           0xCE
#define MP_INT8             0xD0
#define MP_INT16            0xD1
#define MP_INT32            0xD2
#define MP_STR8             0xD9
#define MP_STR16            0xDA
#define MP_MAP16            0xDE
#define MP_ARRAY16          0xDC

// =============================================
// Read a string value from msgpack stream
// Returns bytes consumed, 0 on error
// =============================================
static DWORD MsgpackReadString(PBYTE pData, DWORD dwDataLen, PCHAR pOut, DWORD dwOutSize, DWORD* pdwStrLen) {
    if (dwDataLen == 0) return 0;

    BYTE b = pData[0];
    DWORD offset = 1;
    DWORD slen = 0;

    if ((b & 0xE0) == MP_FIXSTR_MASK) {
        slen = b & 0x1F;
    } else if (b == MP_STR8) {
        if (dwDataLen < 2) return 0;
        slen = pData[1];
        offset = 2;
    } else if (b == MP_STR16) {
        if (dwDataLen < 3) return 0;
        slen = (pData[1] << 8) | pData[2];
        offset = 3;
    } else {
        return 0;
    }

    if (offset + slen > dwDataLen) return 0;
    if (slen >= dwOutSize) slen = dwOutSize - 1;

    memcpy(pOut, pData + offset, slen);
    pOut[slen] = '\0';
    if (pdwStrLen) *pdwStrLen = slen;

    return offset + slen;
}

// =============================================
// Read an integer value from msgpack stream
// =============================================
static DWORD MsgpackReadInt(PBYTE pData, DWORD dwDataLen, INT* pOut) {
    if (dwDataLen == 0) return 0;

    BYTE b = pData[0];

    // Positive fixint (0x00 - 0x7F)
    if ((b & 0x80) == 0) {
        *pOut = (INT)b;
        return 1;
    }
    // Negative fixint (0xE0 - 0xFF)
    if ((b & 0xE0) == 0xE0) {
        *pOut = (INT)(CHAR)b;
        return 1;
    }

    switch (b) {
        case MP_UINT8:
            if (dwDataLen < 2) return 0;
            *pOut = (INT)pData[1];
            return 2;
        case MP_UINT16:
            if (dwDataLen < 3) return 0;
            *pOut = (INT)((pData[1] << 8) | pData[2]);
            return 3;
        case MP_UINT32:
            if (dwDataLen < 5) return 0;
            *pOut = (INT)((pData[1] << 24) | (pData[2] << 16) | (pData[3] << 8) | pData[4]);
            return 5;
        case MP_INT8:
            if (dwDataLen < 2) return 0;
            *pOut = (INT)(CHAR)pData[1];
            return 2;
        case MP_INT16:
            if (dwDataLen < 3) return 0;
            *pOut = (INT)(SHORT)((pData[1] << 8) | pData[2]);
            return 3;
        case MP_INT32:
            if (dwDataLen < 5) return 0;
            *pOut = (INT)((pData[1] << 24) | (pData[2] << 16) | (pData[3] << 8) | pData[4]);
            return 5;
        default:
            return 0;
    }
}

// =============================================
// Skip a msgpack value (used to skip unknown keys)
// =============================================
static DWORD MsgpackSkipValue(PBYTE pData, DWORD dwDataLen) {
    if (dwDataLen == 0) return 0;
    BYTE b = pData[0];

    // fixint
    if ((b & 0x80) == 0 || (b & 0xE0) == 0xE0) return 1;

    // fixstr
    if ((b & 0xE0) == MP_FIXSTR_MASK) {
        DWORD slen = b & 0x1F;
        return 1 + slen;
    }

    // fixmap
    if ((b & 0xF0) == MP_FIXMAP_MASK) {
        DWORD count = b & 0x0F;
        DWORD offset = 1;
        for (DWORD i = 0; i < count * 2; i++) {
            DWORD skip = MsgpackSkipValue(pData + offset, dwDataLen - offset);
            if (skip == 0) return 0;
            offset += skip;
        }
        return offset;
    }

    // fixarray
    if ((b & 0xF0) == MP_FIXARRAY_MASK) {
        DWORD count = b & 0x0F;
        DWORD offset = 1;
        for (DWORD i = 0; i < count; i++) {
            DWORD skip = MsgpackSkipValue(pData + offset, dwDataLen - offset);
            if (skip == 0) return 0;
            offset += skip;
        }
        return offset;
    }

    switch (b) {
        case MP_NIL: case MP_FALSE: case MP_TRUE: return 1;
        case MP_UINT8: case MP_INT8: return 2;
        case MP_UINT16: case MP_INT16: return 3;
        case MP_UINT32: case MP_INT32: return 5;
        case MP_STR8: return 2 + pData[1];
        case MP_STR16: return 3 + ((pData[1] << 8) | pData[2]);
        case MP_BIN8: return 2 + pData[1];
        case MP_BIN16: return 3 + ((pData[1] << 8) | pData[2]);
        case MP_BIN32: return 5 + ((pData[1] << 24) | (pData[2] << 16) | (pData[3] << 8) | pData[4]);
        case MP_MAP16: {
            DWORD count = (pData[1] << 8) | pData[2];
            DWORD offset = 3;
            for (DWORD i = 0; i < count * 2; i++) {
                DWORD skip = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                if (skip == 0) return 0;
                offset += skip;
            }
            return offset;
        }
        case MP_ARRAY16: {
            DWORD count = (pData[1] << 8) | pData[2];
            DWORD offset = 3;
            for (DWORD i = 0; i < count; i++) {
                DWORD skip = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                if (skip == 0) return 0;
                offset += skip;
            }
            return offset;
        }
        default: return 0;
    }
}

// =============================================
// Parse RegisterResponse from msgpack
// Expected: {"agent_id": str, "name": str, "sleep": int, "jitter": int}
// =============================================
BOOL MsgpackParseRegisterResponse(PBYTE pData, DWORD dwDataLen,
                                   PCHAR szAgentID, DWORD dwAgentIDSize,
                                   PCHAR szName, DWORD dwNameSize,
                                   INT* pSleep, INT* pJitter) {

    if (dwDataLen < 1) return FALSE;

    BYTE b = pData[0];
    DWORD mapCount = 0;
    DWORD offset = 0;

    if ((b & 0xF0) == MP_FIXMAP_MASK) {
        mapCount = b & 0x0F;
        offset = 1;
    } else if (b == MP_MAP16) {
        if (dwDataLen < 3) return FALSE;
        mapCount = (pData[1] << 8) | pData[2];
        offset = 3;
    } else {
        return FALSE;
    }

    for (DWORD i = 0; i < mapCount; i++) {
        // Read key (string)
        CHAR szKey[64] = { 0 };
        DWORD consumed = MsgpackReadString(pData + offset, dwDataLen - offset, szKey, sizeof(szKey), NULL);
        if (consumed == 0) return FALSE;
        offset += consumed;

        // Read value based on key name
        if (strcmp(szKey, "agent_id") == 0) {
            consumed = MsgpackReadString(pData + offset, dwDataLen - offset, szAgentID, dwAgentIDSize, NULL);
        } else if (strcmp(szKey, "name") == 0) {
            consumed = MsgpackReadString(pData + offset, dwDataLen - offset, szName, dwNameSize, NULL);
        } else if (strcmp(szKey, "sleep") == 0) {
            consumed = MsgpackReadInt(pData + offset, dwDataLen - offset, pSleep);
        } else if (strcmp(szKey, "jitter") == 0) {
            consumed = MsgpackReadInt(pData + offset, dwDataLen - offset, pJitter);
        } else {
            consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
        }

        if (consumed == 0) return FALSE;
        offset += consumed;
    }

    return TRUE;
}

// =============================================
// Parse CheckInResponse tasks from msgpack
// Expected: {"tasks": [{...}, {...}]}
// Each task: {"id": str, "type": uint8, "args": [str,...], "data": bin}
// =============================================
BOOL MsgpackParseCheckInResponse(PBYTE pData, DWORD dwDataLen,
                                  PC2_TASK pTasks, DWORD dwMaxTasks, DWORD* pdwTaskCount) {
    if (dwDataLen < 1) return FALSE;

    BYTE b = pData[0];
    DWORD mapCount = 0;
    DWORD offset = 0;

    if ((b & 0xF0) == MP_FIXMAP_MASK) {
        mapCount = b & 0x0F;
        offset = 1;
    } else if (b == MP_MAP16) {
        mapCount = (pData[1] << 8) | pData[2];
        offset = 3;
    } else {
        return FALSE;
    }

    *pdwTaskCount = 0;

    for (DWORD i = 0; i < mapCount; i++) {
        CHAR szKey[64] = { 0 };
        DWORD consumed = MsgpackReadString(pData + offset, dwDataLen - offset, szKey, sizeof(szKey), NULL);
        if (consumed == 0) return FALSE;
        offset += consumed;

        if (strcmp(szKey, "tasks") == 0) {
            // Read array
            BYTE ab = pData[offset];
            DWORD arrCount = 0;

            if ((ab & 0xF0) == MP_FIXARRAY_MASK) {
                arrCount = ab & 0x0F;
                offset++;
            } else if (ab == MP_ARRAY16) {
                arrCount = (pData[offset + 1] << 8) | pData[offset + 2];
                offset += 3;
            } else if (ab == MP_NIL) {
                offset++;
                continue;
            }

            for (DWORD t = 0; t < arrCount && t < dwMaxTasks; t++) {
                // Each task is a map
                BYTE tb = pData[offset];
                DWORD taskMapCount = 0;
                if ((tb & 0xF0) == MP_FIXMAP_MASK) {
                    taskMapCount = tb & 0x0F;
                    offset++;
                } else {
                    consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                    offset += consumed;
                    continue;
                }

                for (DWORD k = 0; k < taskMapCount; k++) {
                    CHAR szTKey[64] = { 0 };
                    consumed = MsgpackReadString(pData + offset, dwDataLen - offset, szTKey, sizeof(szTKey), NULL);
                    if (consumed == 0) break;
                    offset += consumed;

                    if (strcmp(szTKey, "id") == 0) {
                        consumed = MsgpackReadString(pData + offset, dwDataLen - offset,
                            pTasks[t].szTaskID, sizeof(pTasks[t].szTaskID), NULL);
                    } else if (strcmp(szTKey, "type") == 0) {
                        INT typeVal = 0;
                        consumed = MsgpackReadInt(pData + offset, dwDataLen - offset, &typeVal);
                        pTasks[t].bType = (BYTE)typeVal;
                    } else if (strcmp(szTKey, "args") == 0) {
                        // Parse string array
                        BYTE arb = pData[offset];
                        if ((arb & 0xF0) == MP_FIXARRAY_MASK) {
                            DWORD argCount = arb & 0x0F;
                            offset++;
                            for (DWORD a = 0; a < argCount && a < 4; a++) {
                                DWORD alen = MsgpackReadString(pData + offset, dwDataLen - offset,
                                    pTasks[t].szArgs[a], sizeof(pTasks[t].szArgs[a]), NULL);
                                if (alen == 0) break;
                                offset += alen;
                                pTasks[t].dwArgCount++;
                            }
                            consumed = 0; // Already advanced offset
                        } else {
                            consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                        }
                    } else if (strcmp(szTKey, "data") == 0) {
                        // Binary data
                        BYTE db = pData[offset];
                        if (db == MP_NIL) {
                            consumed = 1;
                        } else if (db == MP_BIN8) {
                            DWORD dlen = pData[offset + 1];
                            pTasks[t].pData = pData + offset + 2;
                            pTasks[t].dwDataLen = dlen;
                            consumed = 2 + dlen;
                        } else if (db == MP_BIN16) {
                            DWORD dlen = (pData[offset + 1] << 8) | pData[offset + 2];
                            pTasks[t].pData = pData + offset + 3;
                            pTasks[t].dwDataLen = dlen;
                            consumed = 3 + dlen;
                        } else {
                            consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                        }
                    } else {
                        consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
                    }

                    if (consumed > 0) offset += consumed;
                }
                (*pdwTaskCount)++;
            }
        } else {
            consumed = MsgpackSkipValue(pData + offset, dwDataLen - offset);
            if (consumed == 0) return FALSE;
            offset += consumed;
        }
    }

    return TRUE;
}
