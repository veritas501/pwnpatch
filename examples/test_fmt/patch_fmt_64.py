from pwn import *
from pwnpatch import *

patcher = Patch('./t_fmt_64')
bin = ELF('./t_fmt_64',checksec=False)

asmcode='''
mov rsi,rdi
mov rdi, 0x0000000000400735
'''

patcher.patch(0x0000000000400735,byte='%s\x00')
patcher.hook(0x0000000000400681,asm=asmcode)
patcher.save()