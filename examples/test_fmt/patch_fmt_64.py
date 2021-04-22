from pwnpatch import patcher

pt = patcher('./t_fmt_64')
pt.add_byte('%s\x00','new_fmt_str')
asmcode='''
mov rsi,rdi
mov rdi, {new_fmt_str}
'''
pt.hook_asm(0x400681, asmcode)
pt.save()