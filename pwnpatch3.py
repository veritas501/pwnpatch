#coding=utf8
import pwn
from struct import pack,unpack
import subprocess
import os
import io
try:
    file_types = (file, io.IOBase)
except NameError:
    file_types = (io.IOBase,)

arch_enum={'i386':1,'amd64':2}

class Memory(object):
    def __init__(self,fileobj):
        if isinstance(fileobj,str):
            self.mem = open(fileobj,'rb').read()
        elif isinstance(fileobj,file_types):
            self.mem = fileobj.read()
        else:
            error_log("in Memory init : type error!")
            exit(0)

        self.len = len(self.mem)
    
    def read(self,start,length):
        if start > self.len or start < 0:
            return b''
        elif start + length > self.len:
            return self.mem[start:]
        else:
            return self.mem[start:start+length]

    def write(self,start,data):
        if isinstance(start,slice):
            __start=0
            __end = len(self.mem)
            if start.start is not None:
                __start = start.start
            if start.stop is not None:
                __end = start.stop      
            data = data[:__end]
            start = __start
        len_data = len(data)
        if start+len_data > self.len:
            self.len = start+len_data
            self.mem.ljust(self.len,b'\x00')
        if isinstance(data,str):
            data = data.encode()
        self.mem = self.mem[:start]+data+self.mem[start+len_data:]
    
    def __getitem__(self,idx):
        return self.mem[idx]

    def __setitem__(self,_slice,data):
        self.write(_slice,data)

    def __repr__(self):
        return self.mem
    
    def __str__(self):
        return self.mem
    
    def __len__(self):
        return len(self.mem)
    
    def ljust(self,length,padding):
        self.mem = self.mem.ljust(length,padding)
        return self.mem

def success_log(s,level=0):
    print('[\033[1;32m√\033[0m]'+'    '*level,s)

def error_log(s,level=0):
    print('[\033[1;31m×\033[0m]'+'    '*level,s)

def info_log(s,level=0):
    print('[\033[1;36m*\033[0m]'+'    '*level,s)


class Patch(object):
    '''
    提供给user的class
    '''
    def __init__(self,filename):
        try:
            self.ELFobj = pwn.ELF(filename,checksec=False)
        except IOError as e:
            error_log(e)
            exit(0)
        self.filepath = self.ELFobj.path
        self.file = open(self.filepath,'rb')
        self.mem = Memory(self.file)
        success_log("binary \033[32;4m%s\033[0m loaded."%self.filepath)
        self.arch = arch_enum.get(self.ELFobj.arch,-1)
        if self.arch == -1:
            error_log("arch %s is NOT supported!!"%self.ELFobj.arch)
            exit(0)
        info_log("arch : %s"%self.ELFobj.arch)

        self.header = self._parse_header()
        self.segments = self._parse_segments()
    
    def _parse_header(self):
        return Header(self.mem,self.arch)

    def _parse_segments(self):
        return Segment(self.header,self.mem,self._refresh_ELFobj)

    def add_segment(self,addr,length=0x1000,prot=7,pht_size=0x400):
        '''
        新增一个段
        '''
        new_seg = self.segments.add_segments(addr,length,prot,pht_size)
        return new_seg

    def _refresh_ELFobj(self):
        tmpfile=self.filepath+'.tmp'
        self.save(tmpfile,False)
        self.ELFobj = pwn.ELF(tmpfile,checksec=False)
        os.remove(tmpfile)

    def set_execstack(self,able):
        '''
        设置栈是否可以执行
        '''
        self.segments.set_execstack(able)
        if able:
            success_log('set execstack @ Enable')
        else:
            success_log('set execstack @ Disable')

    def set_norelro(self):
        '''
        修改为norelro，即中间不存在只读段
        '''
        self.segments.set_norelro()
        success_log("set NO-RELRO @ Enable")

    def patch(self,vaddr,asm=None,byte=None,c=None):
        '''
        通过汇编代码或是byte或是c代码的方式打patch
        '''
        addr = self._vaddr_to_offset(vaddr)
        if asm is not None:
            self.mem[addr:] = pwn.asm(asm,arch=self.ELFobj.arch)
        elif byte is not None:
            self.mem[addr:] = byte
        elif c is not None:
            self.mem[addr:] = self._c2asm(c,vaddr)
        else:
            # Do nothing.
            pass
        
        success_log("patch @ 0x%x(0x%x)"%(vaddr,addr))

    def hook(self,vaddr,asm=None,c=None,byte=None):
        '''
        插入hook代码，同时原有指令依然能够执行
        如果插入的是c代码，需要考虑库函数调用的问题
        '''
        success_log("hook @ 0x%x"%vaddr)
        addr = self._vaddr_to_offset(vaddr)
        if c is not None:
            byte_len = len(self._c2asm(c,vaddr))#此处va是错的,用这种方式获取长度
            usr_code_addr = self.segments.alloc(byte_len+1)#分配空间
            byte = self._c2asm(c,usr_code_addr)#根据正确的va生成正确的代码
        if asm is not None:
            byte = pwn.asm(asm,arch=self.ELFobj.arch)
        if byte is not None:
            # 1.写入用户的hook代码
            if c is None:
                usr_code_addr = self.segments.alloc(len(byte)+1)#如果是c类型，则已经分配过空间，不需要二次分配
            self.patch(usr_code_addr,byte=byte+b'\xc3')#在后面放一个ret
            '''
            思路：

            1.patch原函数处为jmp func1 + orgin2
            2.func1 由三部分组成，第一部分将原函数patch成 origin1 + jmp func2,
                第二部分为 call 用户的patch代码 （需要保证函数内堆栈平衡）
                第三部分为 jmp到 origin1
            3.执行完origin1，遇到后面的jmp func2
            4.func2 将原函数处再patch成 jmp func1 + origin2 , 然后再jmp到 origin2
            5.执行完origin2 ，等待下次hook。
            '''
            # 2. backup the origin asm code
            first_inst_len = 0
            while first_inst_len < 5:
                first_inst_len += self.get_first_inst_length(vaddr+first_inst_len)
            origin_code = self.mem[addr:addr+first_inst_len+5] # first_inst+jmp 的长度

            if self.arch == 1: # i386
                appro_size = 0x80 # 因为采用了alloc的机制，传入size才能获得虚拟地址，因此只能先大致算一个
                shellcode_addr = self.segments.alloc(appro_size)
                patch_byte_len = first_inst_len+5
                patch_bytes1 = origin_code[:first_inst_len] + pwn.asm('jmp $+%d'%((shellcode_addr+2*patch_byte_len+0x2a)-(vaddr+first_inst_len))).ljust(5,b'\x90')
                patch_bytes2 = pwn.asm('jmp $+%d'%(shellcode_addr+2*patch_byte_len-(vaddr))).ljust(5,b'\x90')+origin_code[5:]

                sc='''
                func1:
                    pushad
                    call get_pc
                    pop edi /* pc */
                    mov esi, edi
                    sub edi, %d /* off_origin_addr */
                    sub edi, 6
                    sub esi, %d /* off_patch_bytes1 */
                    mov ecx, %d /* patch_byte_len */
                    call mymemcpy
                    popad
                    call $+%d /* hook_func */
                    jmp $+%d /* origin1 */
                func2:
                    pushad
                    call get_pc
                    pop edi
                    mov esi, edi
                    sub edi, %d /* off_origin_addr */
                    sub edi, 48
                    sub esi, %d /* off_patch_bytes2 */
                    mov ecx, %d /* patch_byte_len */
                    call mymemcpy
                    popad
                    jmp $+%d /* origin2 */
                mymemcpy:
                    cld
                    rep movsb
                    ret
                get_pc:
                    push [esp]
                    ret
                '''%((shellcode_addr+2*patch_byte_len)-vaddr,                   # off_origin_addr
                2*patch_byte_len+6,                                             # off_patch_bytes1
                patch_byte_len,                                                 # patch_byte_len
                usr_code_addr-(shellcode_addr+2*patch_byte_len+0x20),           # hook_func
                vaddr-(shellcode_addr+2*patch_byte_len+37),                     # jmp_origin1
                (shellcode_addr+2*patch_byte_len)-vaddr,                        # off_origin_addr
                len(patch_bytes1)+48,                                           # off_patch_bytes2
                patch_byte_len,                                                 # patch_byte_len
                (vaddr+first_inst_len)-(shellcode_addr+2*patch_byte_len+74)) # jmp_origin2
            else: # amd64
                appro_size = 0x100 # 因为采用了alloc的机制，传入size才能获得虚拟地址，因此只能先大致算一个
                shellcode_addr = self.segments.alloc(appro_size)
                patch_byte_len = first_inst_len+5
                patch_bytes1 = origin_code[:first_inst_len] + pwn.asm('jmp $+%d'%((shellcode_addr+2*patch_byte_len+0x2a)-(vaddr+first_inst_len))).ljust(5,b'\x90')
                patch_bytes2 = pwn.asm('jmp $+%d'%(shellcode_addr+2*patch_byte_len-(vaddr))).ljust(5,b'\x90')+origin_code[5:]
                sc='''
                func1:
                    push rdi /* backup reg */
                    push rsi
                    push rcx
                    lea rdi, [rip - %d] /* off_origin_addr */
                    lea rsi, [rip - %d] /* off_patch_bytes1 */
                    mov rcx, %d /* patch_byte_len */
                    call mymemcpy
                    pop rcx /* restore reg */
                    pop rsi
                    pop rdi
                    call $+%d /* hook_func */
                    jmp $+%d /* origin1 */
                func2:
                    push rdi /* backup reg */
                    push rsi
                    push rcx
                    lea rdi, [rip - %d] /* off_origin_addr */
                    lea rsi, [rip - %d] /* off_patch_bytes2 */
                    mov rcx, %d /* patch_byte_len */
                    call mymemcpy
                    pop rcx /* restore reg */
                    pop rsi
                    pop rdi
                    jmp $+%d /* origin2 */
                mymemcpy:
                    cld
                    rep movsb
                    ret
                '''%((shellcode_addr+2*patch_byte_len+10)-vaddr,                # off_origin_addr
                2*patch_byte_len+0x11,                                          # off_patch_bytes1
                patch_byte_len,                                                 # patch_byte_len
                usr_code_addr-(shellcode_addr+2*patch_byte_len+0x20),           # hook_func
                vaddr-(shellcode_addr+2*patch_byte_len+37),                     # jmp_origin1
                (shellcode_addr+2*patch_byte_len+0x34)-vaddr,                   # off_origin_addr
                len(patch_bytes1)+0x3b,                                         # off_patch_bytes2
                patch_byte_len,                                                 # patch_byte_len
                (vaddr+first_inst_len)-(shellcode_addr+2*patch_byte_len+74))    # jmp_origin2

            hook_code = patch_bytes1+patch_bytes2+pwn.asm(sc,arch=self.ELFobj.arch)
            self.patch(shellcode_addr,byte=hook_code)
            self.patch(vaddr,byte=patch_bytes2)
            # 将程序段权限设置位rwx
            self.segments.set_code_segment_prot(7)
        else:
            # Do nothing.
            pass

    def _vaddr_to_offset(self,va):
        f_addr = self.ELFobj.vaddr_to_offset(va)
        return f_addr
    
    def get_first_inst_length(self,vaddr):
        return len(pwn.asm(pwn.disasm(self.ELFobj.read(vaddr,16),offset=0,byte=0,arch=self.ELFobj.arch).split('\n')[0],arch=self.ELFobj.arch,vma=vaddr))

    def _c2asm(self,code,vaddr):
        '''
        为了使函数能够正常运行，这里的c代码有一些限制。
        1.不能使用全局变量，哪怕是rodata段的字符串，如果要使用字符串，请用char buf[] = "test";这种形式将字符串放在栈上。
        2.虽然可以使用多函数，但必须将第一个调用的函数放在最前面，其他的函数用申明的形式，函数体放在主函数的后面。
        3.支持调用libc中的函数，但由于使用dynelf的shellcode做函数解析，所以格式有点变化。
            方法如下：
            先添加如下两句，
                typedef void(*f)();
                f dynelf(char * name);
            如果要调用system，
                char arg[] = "/bin/sh";
                char system_name[] = "system";
                dynelf(system_name)(arg);
        '''
        compile_arg=['gcc','-xc','-S','-masm=intel','-o-','-','-mno-sse','-fno-pic','-ffreestanding','-fno-stack-protector',
                '-fno-toplevel-reorder','-fno-asynchronous-unwind-tables']
        # test : gcc -xc -S -masm=intel -o- - -mno-sse -fno-pic -ffreestanding -fno-stack-protector -fno-toplevel-reorder -fno-asynchronous-unwind-tables
        need_dyn=False #是否用到了dyn

        if self.arch == 1: # i386
            compile_arg.append('-m32')

        p = subprocess.Popen(compile_arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if isinstance(code,str):
            code = code.encode()
        asm_raw, err = p.communicate(code)
        if b'error:' in err.lower():
            error_log(err)
            exit(0)
        asm_raw = asm_raw.decode()
        asm1=''

        for lines in asm_raw.split('\n'):
            if '.text' in lines:
                continue
            elif '.globl' in lines:
                continue
            elif '.file' in lines:
                continue
            elif '.type' in lines:
                continue
            elif '.size' in lines:
                continue
            elif '.ident' in lines:
                continue
            elif '.section' in lines:
                continue
            elif '#' in lines:
                continue
            elif 'call' in lines and 'dynelf' in lines: # 处理dynelf函数的调用
                need_dyn = True
                asm1+=lines+'\n'
            else:
                asm1+=lines+'\n'

        if need_dyn:
            if self.arch == 1: #i386
                asm1+='''dynelf:
                push ebx /* backup ebx outside (for pie) */
                jmp pass_getpc
                get_pc:
                pop ebx
                push ebx
                ret
                pass_getpc:
                call get_pc
                sub ebx,%d /* code_base in ebx*/
                push -1
                pop eax
                shl eax,12
                and ebx,eax

                cmp dword ptr [ebx],0x464c457f
                je get_base_success
                push -1
                pop eax
                ret /* ret -1 */
                get_base_success:

                jmp pass_get_dyn

                func_get_dyn: /* ebx(base) -> eax(dynamic) affect: edi*/
                xor edi,edi
                push ebx
                pop eax
                add eax,dword ptr [ebx+0x1c] /* phoff in eax */
                cmp word ptr [ebx+0x10],3 /* ET_DYN */
                cmovz edi,ebx /* store code base in edi */
                loop2:
                cmp dword ptr [eax],0x2 /* PT_DYNAMIC */
                jz lbl2
                add eax,0x20 /* pht_size */
                jmp loop2
                lbl2: 
                mov eax,dword ptr[eax+8] /* get Dynamic segment (no pie)*/
                test edi,edi
                je jmpout1
                add eax,edi /* get Dynamic segment (have pie)*/
                jmpout1:
                ret

                pass_get_dyn:
                call func_get_dyn

                loop3:
                cmp dword ptr [eax],0x3 /* find DT_PLTGOT */
                jz lbl3
                add eax,8
                jmp loop3
                lbl3:
                mov eax, dword ptr [eax+4] /* got address in eax */

                add eax,0xc
                loop4:
                mov ebx, dword ptr [eax]
                shr ebx,24
                cmp bl,0xf7
                jz lbl4
                add eax,4
                jmp loop4
                lbl4:
                mov ebx, dword ptr [eax] /* libc address in ebx*/

                push -1
                pop eax
                shl eax,12
                and ebx,eax
                loop5:
                cmp dword ptr [ebx],0x464c457f
                jz lbl5
                sub ebx, 0x1000
                jmp loop5
                lbl5: /* now libc_base in ebx */

                call func_get_dyn

                push ebx /* backup libc base */

                push eax
                pop ebx
                loop7:
                cmp dword ptr [ebx],0x5 /* find DT_STRTAB */
                jz lbl7
                add ebx,8
                jmp loop7
                lbl7:
                mov ebx, dword ptr [ebx+4] /* strtab address in ebx */

                loop8:
                cmp dword ptr [eax],0x6 /* find DT_SYMTAB */
                jz lbl8
                add eax,8
                jmp loop8
                lbl8:
                mov edx, dword ptr [eax+4] /* symtab address in eax */

                /* now edx -> symtab */
                /* now ebx -> strtab */

                /* calc str length */
                mov edi,dword ptr [esp+0xc]
                push edi /* backup edi */
                xor eax,eax
                push -1
                pop ecx
                repnz scas al, byte ptr [edi]
                /* inc ecx */
                neg ecx
                pop edi /* restore edi */

                pop eax /* restore libc base */

                loop9:
                push ecx
                mov esi, dword ptr [edx]
                add esi,ebx
                push edi /* backup edi */
                repz cmps byte ptr [esi],byte ptr [edi]
                pop edi /* restore edi */
                test ecx,ecx
                pop ecx
                je match
                add edx,0x10 /* next symtab(sym size) */
                jmp loop9
                match:
                mov ebx, dword ptr [edx+4]
                add eax,ebx
                pop ebx /* restore ebx outside (for pie) */
                ret /* function pointer in eax */
                '''%(vaddr-self.segments.load_addr) # 大致取到代码段，低12bits置零得到程序基地址
            else:
                asm1+='''dynelf:
                lea rax,[rip-%d] /* get code base */
                push -1
                pop rbx
                shl rbx,12
                and rax,rbx
                xor r10,r10

                jmp pass_func

                func_get_dyn:
                mov rbx,rax
                add rbx,qword ptr [rax+0x20] /* phoff in rbx */
                cmp word ptr [rax+0x10],3 /* ET_DYN */
                cmovz r10,rax /* store code base in r10 */
                loop2:
                cmp dword ptr [rbx],0x2 /* PT_DYNAMIC */
                jz lbl2
                add rbx,0x38 /* pht_size */
                jmp loop2
                lbl2: 
                mov rbx,qword ptr[rbx+0x10] /* get Dynamic segment (no pie)*/
                test r10,r10
                je jmpout1
                add rbx,r10 /* get Dynamic segment (have pie)*/
                jmpout1:
                ret

                pass_func:
                call func_get_dyn

                loop3:
                cmp qword ptr [rbx],0x3 /* find DT_PLTGOT */
                jz lbl3
                add rbx,0x10
                jmp loop3
                lbl3:
                mov rax, qword ptr [rbx+8] /* got address in rax */

                add rax,0x18
                loop4:
                mov rbx, qword ptr [rax]
                shr rbx,40
                cmp bl,0x7f
                jz lbl4
                add rax,8
                jmp loop4
                lbl4:
                mov rax, qword ptr [rax] /* libc address in rbx*/

                push -1
                pop rbx
                shl rbx,12
                and rax,rbx
                loop5:
                cmp dword ptr [rax],0x464c457f
                jz lbl5
                sub rax, 0x1000
                jmp loop5
                lbl5: /* now libc_base in rax */
                mov r10,rax

                call func_get_dyn

                push rbx
                loop7:
                cmp qword ptr [rbx],0x5 /* find DT_STRTAB */
                jz lbl7
                add rbx,0x10
                jmp loop7
                lbl7:
                mov rbx, qword ptr [rbx+8] /* strtab address in rbx */

                pop rax
                loop8:
                cmp qword ptr [rax],0x6 /* find DT_SYMTAB */
                jz lbl8
                add rax,0x10
                jmp loop8
                lbl8:
                mov rdx, qword ptr [rax+8] /* symtab address in rax */

                /* now rdx -> symtab */
                /* now rbx -> strtab */

                /* calc str length */
                push rdi /* backup rdi */
                xor eax,eax
                push -1
                pop rcx
                repnz scas al, BYTE PTR [rdi]
                /* inc rcx */
                neg rcx
                pop rdi /* restore rdi */

                loop9:
                push rcx
                mov esi, dword ptr [rdx]
                add rsi,rbx
                push rdi /* backup rdi */
                repz cmps byte ptr [rsi],byte ptr [rdi]
                pop rdi /* restore rdi */
                test rcx,rcx
                pop rcx
                je match
                add rdx,0x18 /* next symtab(sym size) */
                jmp loop9
                match:
                mov rax, qword ptr [rdx+8]
                add rax,r10
                ret /* function pointer in rax*/
                '''%(vaddr-self.segments.load_addr) # 大致取到代码段，低12bits置零得到程序基地址

        asm_result=pwn.asm(asm1,arch=self.ELFobj.arch)
        return asm_result

    def save(self,filename=None,print_log=True):
        '''
        将文件保存出来，默认文件名为原文件名.patched，可以通过传入filename设置
        '''
        if filename is None:
            savename = self.filepath+'.patched'
        else:
            savename = filename
        self.header.dump_header()
        open(savename,'wb').write(self.mem.mem)

        if print_log:
            success_log("save binary @ \033[32;4m%s\033[0m"%savename)

class Header(object):
    '''
    parse and dump header
    '''

    def __init__(self,mem,arch):
        self.mem = mem

        (self.file_identification,self.ei_class_2,self.ei_data,
                    self.ei_version,self.ei_osabi,self.ei_abiversion,self.ei_pad1,self.ei_pad2,self.ei_nident_SIZE
                    ) = unpack("<IBBBBBIHB",self.mem[:0x10])

        if self.file_identification != 1179403647: # magic header
            pwn.error("not ELF file")

        if arch != self.ei_class_2: # arch
            pwn.error("arch not right")

        if 1 != self.ei_data: # LSB little endian
            pwn.error("not LSB")
        
        if self.ei_class_2 == 1: # i386
            (self.e_type,self.e_machine,self.e_version,
                        self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,self.e_ehsize,self.e_phentsize,
                        self.e_phnum,self.e_shentsize,self.e_shnum,self.e_shtrndx
                        ) = unpack("<HHIIIIIHHHHHH",self.mem[0x10:0x10+0x24])
        else: # amd64
            (self.e_type,self.e_machine,self.e_version,
                        self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,self.e_ehsize,self.e_phentsize,
                        self.e_phnum,self.e_shentsize,self.e_shnum,self.e_shtrndx
                        ) = unpack("<HHIQQQIHHHHHH",self.mem[0x10:0x10+0x30])       

    def dump_header(self):
        self.packed_header=b''
        self.packed_header+= pack("<IBBBBBIHB",*(self.file_identification,self.ei_class_2,self.ei_data,
                    self.ei_version,self.ei_osabi,self.ei_abiversion,self.ei_pad1,self.ei_pad2,self.ei_nident_SIZE))
        
        if self.ei_class_2 == 1: # i386
            self.packed_header+= pack("<HHIIIIIHHHHHH",*(self.e_type,self.e_machine,self.e_version,
                        self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,self.e_ehsize,self.e_phentsize,
                        self.e_phnum,self.e_shentsize,self.e_shnum,self.e_shtrndx))
        else: # amd64
            self.packed_header+= pack("<HHIQQQIHHHHHH",*(self.e_type,self.e_machine,self.e_version,
                        self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,self.e_ehsize,self.e_phentsize,
                        self.e_phnum,self.e_shentsize,self.e_shnum,self.e_shtrndx))

        self.mem[:len(self.packed_header)] = self.packed_header
        return self.packed_header

class Segment(object):
    '''
    parse and dump Segments
    '''
    def __init__(self,header,mem,refresh_func):
        self.header = header
        self.mem = mem
        
        self.p_type = [ _ for _ in range(self.header.e_phnum)]
        self.p_offset = [ _ for _ in range(self.header.e_phnum)]
        self.p_vaddr = [ _ for _ in range(self.header.e_phnum)]
        self.p_paddr = [ _ for _ in range(self.header.e_phnum)]
        self.p_filesz = [ _ for _ in range(self.header.e_phnum)]
        self.p_memsz = [ _ for _ in range(self.header.e_phnum)]
        self.p_flags = [ _ for _ in range(self.header.e_phnum)]
        self.p_align = [ _ for _ in range(self.header.e_phnum)]

        for i in range(self.header.e_phnum):
            if self.header.ei_class_2 == 1: # i386
                (self.p_type[i],self.p_offset[i],self.p_vaddr[i],self.p_paddr[i],self.p_filesz[i],
                            self.p_memsz[i],self.p_flags[i],self.p_align[i]
                            ) = unpack("<IIIIIIII",self.mem[self.header.e_phoff+self.header.e_phentsize*i:self.header.e_phoff+self.header.e_phentsize*(i+1)])
            else: # amd64
                (self.p_type[i],self.p_flags[i],self.p_offset[i],self.p_vaddr[i],self.p_paddr[i],
                            self.p_filesz[i],self.p_memsz[i],self.p_align[i]
                            ) = unpack("<IIQQQQQQ",self.mem[self.header.e_phoff+self.header.e_phentsize*i:self.header.e_phoff+self.header.e_phentsize*(i+1)])     

        self.has_new_pht = False
        for i in range(self.header.e_phnum):
            if self.p_type[i] == 1 and self.p_offset[i] == 0: # to find code end
                self.load_addr = self.p_vaddr[i]
                break

        self.refresh_func = refresh_func
    
    def _find_cave(self,length):
        '''
        方案1：
            在code段的后面找一块空闲的地方来放新的pht
        方案2：
            在文件末尾加段，但需要padding到段不会重叠
        '''
            # 先尝试找cave
        code_end = None
        data_start = None
        for i in range(self.header.e_phnum):
            if self.p_type[i] == 1 and self.p_offset[i] == 0: # to find code end
                self.load_addr = self.p_vaddr[i]
                code_end = self.p_offset[i]+self.p_filesz[i]
                if self.p_type[i+1] == 1:
                    data_start = self.p_offset[i+1]
                else:
                    # error_log("can't find data segment")
                    break
                break
            
        if code_end != None and data_start != None and data_start-code_end >= length:
            self.cave_addr = code_end
            self.cave_len = data_start-code_end
        else:   
            # 没有找到cave，采用在文件末尾padding数据
            segment_end=0
            for i in range(self.header.e_phnum):
                padding_end = self.p_vaddr[i]+self.p_memsz[i]
                if padding_end %0x1000 !=0:
                    padding_end-=padding_end%0x1000
                    padding_end+=0x1000
                if padding_end != 0:
                    # 64位程序因为代码段和数据段不连在一起，这样不处理会使在0x600000后面填充pht，因此会patch很大一段0字节
                    if segment_end == 0 or (padding_end-segment_end)<0x100000:
                        segment_end = max(padding_end,segment_end)
            if len(self.mem) > (segment_end-self.load_addr):# 还是由于64两个段分的很开的原因
                self.mem.ljust(((len(self.mem)&~0xfff)+0x1000)+length,b'\x00')
            else:
                self.mem.ljust(segment_end-self.load_addr+length,b'\x00')
            self.cave_addr = len(self.mem)-length

    def set_code_segment_prot(self,prot):
        for i in range(self.header.e_phnum):
            if self.p_type[i] == 1 and self.p_offset[i] == 0: # to find code segment
                self.p_flags[i] = prot
                break
        self.mem[self.header.e_phoff:] = self.dump_segments()
        success_log("set code segment prot : %d"%prot)

    def alloc(self,length):
        '''
        提供给patch的内部接口，将分配出来的segment空间合理利用
        '''
        try:
            self.alloc_addr
            self.alloc_len
        except AttributeError:#尝试初始化
            self.alloc_addr=0x6000000
            self.alloc_len=0

        if self.alloc_len < length:
            # need alloc
            if length <= 0x1000:
                length1=0x1000
                self.alloc_addr = self.add_segments(self.alloc_addr+self.alloc_len,0x1000,7)
            else:
                length1=(length&~0xfff)+0x1000
                self.alloc_addr = self.add_segments(self.alloc_addr+self.alloc_len,length1,7)
            self.alloc_len = length1
        
        # now we have enough memory
        ret_addr = self.alloc_addr
        self.alloc_addr+=length
        self.alloc_len-=length
        return ret_addr

    def add_segments(self,addr,length=0x1000,prot=7,pht_size=0x400):
        '''
        添加一个新段
        '''
        if not self.has_new_pht:
            '''
            需要先找一个地方来放新的段表
            '''
            self._find_cave(pht_size)
            self.has_new_pht=True
            self.header.e_phoff = self.cave_addr
            # update segment info
            for i in range(self.header.e_phnum):
                if self.p_type[i] == 6: # PT_PHDR 
                    self.p_offset[i] = self.cave_addr
                    self.p_vaddr[i] = self.load_addr+self.cave_addr
                    self.p_paddr[i] = self.p_vaddr[i]
                if self.p_type[i] == 1 and self.p_offset[i] == 0: # update code load segment
                    self.p_filesz[i] = self.cave_addr+pht_size
                    self.p_memsz[i] = self.p_filesz[i]

        '''
        现在我们把段表安置好了，可以添加我们自己的段了
        默认添加在文件的尾部
        '''
        if addr > (addr&~0xfff):
            addr=(addr&~0xfff)+0x1000
        seg_addr = addr+(len(self.mem)&0xfff)

        self.p_type.append(1) # PT_LOAD
        self.p_offset.append(len(self.mem))
        self.p_vaddr.append(seg_addr) # PT_LOAD 必须 align
        self.p_paddr.append(seg_addr)
        self.p_filesz.append(length)
        self.p_memsz.append(length)
        self.p_flags.append(prot)
        self.p_align.append(4)

        self.mem[len(self.mem):] = b'\x00'*length

        self.header.e_phnum+=1
        self.mem[self.header.e_phoff:] = self.dump_segments().ljust(pht_size,b'\x00')
        #由于vaddr转换用到了pwntools，因此需要先把binary写出，刷新self.ELFobj
        self.refresh_func()

        success_log('add new segment @ 0x%x, length 0x%x, prot %d'%(seg_addr,length,prot))
        return seg_addr

    def set_execstack(self,able):
        for i in range(self.header.e_phnum):
            if self.p_type[i] == 0x6474E551: # PT_GNU_STACK
                if able == False:
                    self.p_flags[i] = 6 #rw
                else:
                    self.p_flags[i] = 7 #rwx
                self.mem[self.header.e_phoff:] = self.dump_segments()
                return
        error_log('execstack: stack not find')
    
    def set_norelro(self):
        for i in range(self.header.e_phnum):
            if self.p_type[i] == 0x6474E552: # PT_GNU_RELRO
                self.p_type[i] = 0 # PT_NULL
                self.mem[self.header.e_phoff:] = self.dump_segments()
                return
        error_log('set_relro : relro not find')

    def dump_segments(self):
        self.packed_segments=b''
        
        for i in range(self.header.e_phnum):

            if self.header.ei_class_2 == 1: # i386
                self.packed_segments+= pack("<IIIIIIII",*(self.p_type[i],self.p_offset[i],self.p_vaddr[i],self.p_paddr[i],self.p_filesz[i],
                            self.p_memsz[i],self.p_flags[i],self.p_align[i]))
            else: # amd64
                self.packed_segments+= pack("<IIQQQQQQ",*(self.p_type[i],self.p_flags[i],self.p_offset[i],self.p_vaddr[i],self.p_paddr[i],
                            self.p_filesz[i],self.p_memsz[i],self.p_align[i]))

        return self.packed_segments
