BITS 64

; >>> flag = "flag{it's_easy!}"; print ['0x' + x[::-1].encode('hex') for x in [flag[n:n+4] for n in range(0, len(flag), 4)]]
; ['0x67616c66', '0x2774697b', '0x61655f73', '0x7d217973']

section .text
    global _start
str_correct: 
    db `correct\n`
str_wrong:
    db `wrong;(\n`
print:
    mov rax, 1      ; sys_write
    mov rdi, 1      ; stdout (int fd = 1)
    mov rsi, rcx    ; char * buf
    mov rdx, 8      ; int count
    syscall
    ret
_start:
    push rbp
    mov rbp, rsp
    mov rax, [rsp+0x18] ; *(argv[1])
    test rax, rax
    jz fail
    cmp dword [rax+0], 0x67616c66
    jne fail
    cmp dword [rax+4], 0x2774697b
    jne fail
    cmp dword [rax+8], 0x61655f73
    jne fail
    cmp dword [rax+12], 0x7d217973
    jne fail
clear:
    mov rcx, str_correct
    call print
    jmp exit
fail:
    mov rcx, str_wrong
    call print
exit:
    mov rax, 60; sys_exit
    mov rdi, 0
    syscall
    ; Never returns