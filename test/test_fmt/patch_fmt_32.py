from pwn import *
from pwnpatch import *

patcher = Patch('./t_fmt_32')
bin = ELF('./t_fmt_32',checksec=False)

asmcode='''
pop eax
push 0x080485FC
push eax
'''

patcher.patch(0x080485FC,byte='%s\x00')
patcher.hook(0x08048526,asm=asmcode)
patcher.save()