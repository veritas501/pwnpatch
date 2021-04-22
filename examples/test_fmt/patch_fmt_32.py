from pwnpatch import patcher

pt = patcher('./t_fmt_32')
pt.add_byte('%s\x00','new_fmt_str')
asmcode='''
pop eax
push {new_fmt_str}
push eax
'''
pt.hook_asm(0x08048526, asmcode)
pt.save()