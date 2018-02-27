uc-loader
====

a simple elf loader for Unicorn Engine

How to build
----
```
make
```

How to use
----
following commands demonstrates emulation with argv.

```bash
./loader sample_elf/correct-argv1.elf
./loader sample_elf/correct-argv1.elf flag
```

### sample run
```
% ./loader sample_elf/correct-argv1.elf
=== [segments] ===
0 (addr=0x400000, offset=0x0, size=0x102, type=1)
=== [memory map] ===
region: 0x400000 - 0x401000
[*] emulation start
>>> Tracing instruction at 0x4000a5, instruction size = 0x1
        0x4000a5:       push            rbp
>>> Tracing instruction at 0x4000a6, instruction size = 0x3
        0x4000a6:       mov             rbp, rsp
>>> Tracing instruction at 0x4000a9, instruction size = 0x5
        0x4000a9:       mov             rax, qword ptr [rsp +0x18]
>>> Tracing instruction at 0x4000ae, instruction size = 0x3
        0x4000ae:       test            rax, rax
>>> Tracing instruction at 0x4000b1, instruction size = 0x2
        0x4000b1:       je              0x4000e7
>>> Tracing instruction at 0x4000e7, instruction size = 0xa
        0x4000e7:       movabs          rcx, 0x400088
>>> Tracing instruction at 0x4000f1, instruction size = 0x5
        0x4000f1:       call            0x400090
>>> Tracing instruction at 0x400090, instruction size = 0x5
        0x400090:       mov             eax, 1
>>> Tracing instruction at 0x400095, instruction size = 0x5
        0x400095:       mov             edi, 1
>>> Tracing instruction at 0x40009a, instruction size = 0x3
        0x40009a:       mov             rsi, rcx
>>> Tracing instruction at 0x40009d, instruction size = 0x5
        0x40009d:       mov             edx, 8
>>> Tracing instruction at 0x4000a2, instruction size = 0x2
        0x4000a2:       syscall
>>> syscall write(fd=1, *buf='wrong;(
', count=8)
>>> Tracing instruction at 0x4000a4, instruction size = 0x1
        0x4000a4:       ret
>>> Tracing instruction at 0x4000f6, instruction size = 0x5
        0x4000f6:       mov             eax, 0x3c
>>> Tracing instruction at 0x4000fb, instruction size = 0x5
        0x4000fb:       mov             edi, 0
>>> Tracing instruction at 0x400100, instruction size = 0x2
        0x400100:       syscall
>>> enumation stoped because of sys_exit(error_code=0)
```