#!/usr/bin/env python3
from pwnpatch import patcher
import subprocess as sp


def test_64_pie():
    p = patcher("./example_64_pie")
    # func1 use patch
    asm = '''
    mov rax,1
    ret
    '''
    p.patch_asm(0x1189, asm)
    # func2 use hook
    asm = '''
    mov rax,0xdeadbeef
    '''
    p.hook_asm(0x11B0, asm)
    # func3 use add
    p.add_byte("this_is_str2\x00", "str2")
    p.patch_asm(0x11f8, "lea rdi, [{str2}]")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


def test_64_nopie():
    p = patcher("./example_64_nopie")
    # func1 use patch
    asm = '''
    mov rax,1
    ret
    '''
    p.patch_asm(0x401176, asm)
    # func2 use hook
    asm = '''
    mov rax,0xdeadbeef
    '''
    p.hook_asm(0x40119D, asm)
    # func3 use add
    p.add_byte("this_is_str2\x00", "str2")
    p.patch_asm(0x4011E5, "lea rdi, [{str2}]")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


def test_32_pie():
    p = patcher("./example_32_pie")
    # func1 use patch
    asm = '''
    mov eax,1
    ret
    '''
    p.patch_asm(0x120D, asm)
    # func2 use hook
    asm = '''
    mov eax,0xdeadbeef
    '''
    p.hook_asm(0x1256, asm)
    # func3 use add
    p.add_byte("this_is_str2\x00", "str2")
    p.add_asm("mov edx,[esp];ret", "pc_thunk_dx")
    asm = '''
    call {pc_thunk_dx}
    pc: sub edx, pc - {str2}
    push edx
    jmp 0x12AF
    '''
    p.add_asm(asm, "patch1")
    p.patch_asm(0x12A8, "jmp {patch1}")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


def test_32_nopie():
    p = patcher("./example_32_nopie")
    # func1 use patch
    asm = '''
    mov eax,1
    ret
    '''
    p.patch_asm(0x080491D6, asm)
    # func2 use hook
    asm = '''
    mov eax,0xdeadbeef
    '''
    p.hook_asm(0x0804921F, asm)
    # func3 use add
    p.add_byte("this_is_str2\x00", "str2")
    p.add_asm("mov edx,[esp];ret", "pc_thunk_dx")
    asm = '''
    call {pc_thunk_dx}
    pc: sub edx, pc - {str2}
    push edx
    jmp 0x08049278
    '''
    p.add_asm(asm, "patch1")
    p.patch_asm(0x08049271, "jmp {patch1}")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


def test_64_static():
    p = patcher("./example_64_static")
    # func1 use patch
    asm = '''
    mov rax,1
    ret
    '''
    p.patch_asm(0x401CE5, asm)
    # func2 use hook
    asm = '''
    mov rax,0xdeadbeef
    '''
    p.hook_asm(0x401D0C, asm)
    # func3 use add
    p.add_byte("this_is_str2\x00", "str2")
    p.patch_asm(0x401D54, "lea rdi, [{str2}]")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


def test_aarch64_static():
    p = patcher("./example_aarch64_static")
    # func1 use patch
    asm = '''
    mov x0,1
    ret
    '''
    p.patch_asm(0x4006AC, asm)
    # TODO: aarch64 not support hook
    # func2 use <s>hook</s> patch
    asm = '''
    CSET            W0, NE
    '''
    p.patch_asm(0x4006F0, asm)
    # func3 use add
    str2_p = p.add_byte("this_is_str2\x00", "str2")
    p.patch_asm(0x400740, f"adrp x0, {str2_p & ~0xfff}; add x0, x0, {str2_p & 0xfff}")
    # test add_segment
    p.add_segment()
    p.add_segment(prot=5)
    p.add_segment()
    c_code = '''
    int main(){
        return getpid();
    }
    '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen(["qemu-aarch64-static", "./patch_result"])
    io.communicate()
    assert io.returncode == 0


def test_mingw64():
    p = patcher("./example_mingw64.exe")
    # func1 use patch
    asm = '''
        mov rax,1
        ret
        '''
    p.patch_asm(0x401560, asm)
    # TODO: pe not support hook
    # func2 use <s>hook</s> patch
    asm = '''
        setnz al
        '''
    p.patch_asm(0x401590, asm)
    # func3 use add
    str2_p = p.add_byte("this_is_str2\x00", "str2")
    p.patch_asm(0x4015C4, "lea rcx, [{str2}]")
    # test add_segment
    # TODO: pe not support add_segment
    # p.add_segment()
    # p.add_segment(prot=5)
    # p.add_segment()
    c_code = '''
        int main(){
            return 0x1337;
        }
        '''
    p.add_c(c_code)
    p.save("patch_result")
    io = sp.Popen("./patch_result")
    io.communicate()
    assert io.returncode == 0


if __name__ == '__main__':
    test_mingw64()
