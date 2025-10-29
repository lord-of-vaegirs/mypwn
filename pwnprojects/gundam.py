from pwn import *

context(log_level="debug",os="linux",arch="amd64")

libc=ELF("/home/lixingjian/")