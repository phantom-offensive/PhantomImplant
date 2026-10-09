#ifndef _LSASS_H
#define _LSASS_H

#include "common.h"

// Find the PID of lsass.exe via a process snapshot.
BOOL FindLsassPid(OUT DWORD* pdwPid);

// Dump LSASS memory to disk using handle duplication + NtCreateProcessEx
// fork (PPL bypass) + MiniDumpWriteDump into an in-memory buffer.
BOOL DumpLsassViaMiniDump(IN DWORD dwLsassProcessId, IN PCHAR cDumpFileName);

#endif // _LSASS_H
