# PhantomImplant - Build System
# Cross-compile from Linux (MinGW) or native Windows (MSVC)

# =============================================
# MinGW Cross-Compilation (from Kali/Linux)
# =============================================
CC_WIN64    = x86_64-w64-mingw32-gcc
ASM_WIN64   = nasm
CFLAGS      = -Wall -O2 -Iinclude -DUNICODE -D_UNICODE
LDFLAGS     = -lntdll -s -nostdlib -lkernel32 -luser32

# Output
BUILD_DIR   = build
BIN_NAME    = phantom-implant.exe
HASHGEN     = hashgen.exe

# Sources
SRC         = src/main.c src/api.c src/syscalls.c
ASM_SRC     = asm/syscalls.asm
HASHGEN_SRC = src/hashgen.c

# =============================================
# Targets
# =============================================

.PHONY: all clean hashgen test-hashgen help

all: $(BUILD_DIR)/$(BIN_NAME)

# Build the implant (MinGW + NASM)
$(BUILD_DIR)/$(BIN_NAME): $(SRC) $(ASM_SRC) | $(BUILD_DIR)
	@echo "[*] Assembling syscall stubs..."
	$(ASM_WIN64) -f win64 $(ASM_SRC) -o $(BUILD_DIR)/syscalls.obj
	@echo "[*] Compiling implant..."
	$(CC_WIN64) $(CFLAGS) $(SRC) $(BUILD_DIR)/syscalls.obj -o $@ $(LDFLAGS)
	@echo "[+] Built: $@"
	@ls -lh $@

# Build hash generator (native Linux or MinGW)
hashgen: $(BUILD_DIR)/$(HASHGEN)

$(BUILD_DIR)/$(HASHGEN): $(HASHGEN_SRC) | $(BUILD_DIR)
	@echo "[*] Building hash generator..."
	gcc $(HASHGEN_SRC) -o $(BUILD_DIR)/hashgen-linux
	@echo "[+] Built: $(BUILD_DIR)/hashgen-linux"
	@echo "[*] Run: ./$(BUILD_DIR)/hashgen-linux > hashes.h"

# Generate hashes and update common.h
gen-hashes: $(BUILD_DIR)/hashgen-linux
	@echo "[*] Generating API hashes..."
	./$(BUILD_DIR)/hashgen-linux

$(BUILD_DIR)/hashgen-linux: $(HASHGEN_SRC) | $(BUILD_DIR)
	gcc $(HASHGEN_SRC) -o $@

# Build for Windows (MSVC) - run from VS Developer Command Prompt
msvc:
	@echo "[*] Building with MSVC..."
	@echo "    Run from VS Developer Command Prompt:"
	@echo "    ml64 /c /Fo build\\syscalls.obj asm\\syscalls.asm"
	@echo "    cl /O2 /Iinclude src\\main.c src\\api.c src\\syscalls.c build\\syscalls.obj /Fe:build\\phantom-implant.exe"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "PhantomImplant Build Targets:"
	@echo "  make all         - Build implant (MinGW cross-compile)"
	@echo "  make hashgen     - Build hash generator utility"
	@echo "  make gen-hashes  - Generate and print API hashes"
	@echo "  make msvc        - Print MSVC build commands"
	@echo "  make clean       - Remove build artifacts"
	@echo ""
	@echo "MSVC Build (on Windows):"
	@echo "  ml64 /c /Fo build\\syscalls.obj asm\\syscalls.asm"
	@echo "  cl /O2 /Iinclude src\\*.c build\\syscalls.obj /Fe:build\\phantom-implant.exe"
