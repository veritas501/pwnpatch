import pwnpatch

pt = pwnpatch.get_patcher('./t_fmt_32')
pt.add_byte('%s\x00', 'new_fmt_str')
asm_code = '''
pop eax
push {new_fmt_str}
push eax
'''
pt.hook_asm(0x08048526, asm_code)
pt.save()
