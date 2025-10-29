from pwn import *

context(log_level='debug',os='linux',arch='amd64')

p=remote('node5.buuoj.cn',28853)

p.interactive()
