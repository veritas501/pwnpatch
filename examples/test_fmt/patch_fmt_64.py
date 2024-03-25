import pwnpatch

pt = pwnpatch.get_patcher('./t_fmt_64')
pt.add_byte('%s\x00', 'new_fmt_str')
asm_code = '''
mov rsi,rdi
mov rdi, {new_fmt_str}
'''
pt.hook_asm(0x400681, asm_code)
pt.save()
