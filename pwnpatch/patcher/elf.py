import io
from typing import Optional

from elftools.elf import constants
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.segments import Segment

from pwnpatch.enums import *
from pwnpatch.exceptions import *
from pwnpatch.log_utils import log
from pwnpatch.patcher.base import BasePatcher


class ElfPatcher(BasePatcher):
    def __init__(self, filename: str) -> None:
        self._elffile_stream = open(filename, 'rb')
        self._elffile: ELFFile = ELFFile(self._elffile_stream)

        # internal variables
        self._phdr_reallocated: bool = False

        super().__init__(filename)
        self._init_code_cave()

    def _init_basic_info(self) -> bool:
        # 初始化基础信息
        self.exe_type = EXE.ELF
        e_machine = self._elffile.header.e_machine
        self.arch = {
            'EM_386': Arch.I386,
            'EM_X86_64': Arch.AMD64,
            'EM_ARM': Arch.ARM,
            'EM_AARCH64': Arch.ARM64,
            'EM_MIPS': Arch.MIPS,
        }.get(e_machine, Arch.NONE)
        if self.arch == Arch.NONE:
            raise UnsupportedBinaryException(
                "Unsupported arch: {}".format(e_machine))
        is_little_endian = self._elffile.little_endian
        self.endian = Endian.LSB if is_little_endian else Endian.MSB
        bit_size = self._elffile.header.e_ident['EI_CLASS']
        self.bit_size = {
            'ELFCLASS32': BitSize.X32,
            'ELFCLASS64': BitSize.X64,
        }.get(bit_size, BitSize.NONE)
        if self.bit_size == BitSize.NONE:
            raise UnsupportedBinaryException(
                "Unsupported bit size: {}".format(bit_size))

        return True

    def _init_code_cave(self) -> bool:
        eh_frame_section = self._elffile.get_section_by_name(".eh_frame")
        if not eh_frame_section:
            return False

        # 如果 .eh_frame的权限为只读，需要patch一下segment的权限 +x
        eh_frame_segment = self._find_segment_hold_section(eh_frame_section)
        if not eh_frame_segment:
            log.warning(
                "Can't find which segment hold .eh_frame section, skip add .eh_frame section to code cave")
            return True
        if not eh_frame_segment.header.p_flags & constants.P_FLAGS.PF_X:
            log.success("Modify .eh_frame section prot +x")
            segment_idx = self._get_phdr_idx(eh_frame_segment)
            eh_frame_segment.header.p_flags |= constants.P_FLAGS.PF_X
            self._replace_phdr_by_idx(eh_frame_segment, segment_idx)
            self._reload()

        self.add_range_to_code_cave(eh_frame_section['sh_addr'],
                                    eh_frame_section['sh_size'])
        log.info("Add .eh_frame to code cave")
        return True

    @property
    def _phoff(self) -> int:
        return self._elffile.header.e_phoff

    @property
    def _phnum(self) -> int:
        return self._elffile.header.e_phnum

    @property
    def _phentsize(self) -> int:
        return self._elffile.header.e_phentsize

    @property
    def image_base(self) -> int:
        min_addr = (1 << 64) - 1
        for segment in self._elffile.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                min_addr = min(min_addr, segment.header.p_vaddr)
        return min_addr

    def _find_segment_hold_section(self, section: Section) -> Optional[Segment]:
        for segment in self._elffile.iter_segments():
            if segment.section_in_segment(section):
                return segment

        return None

    def _get_phdr_idx(self, segment: Segment) -> int:
        target_phdr_data = self._elffile.structs.Elf_Phdr.build(segment.header)

        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            tmp_phdr_data = self._elffile.structs.Elf_Phdr.build(seg.header)
            if target_phdr_data == tmp_phdr_data:
                return i

        raise Exception("can't find target phdr")

    def _replace_phdr_by_idx(self, segment: Segment, idx: int) -> bool:
        if idx > self._phnum:
            log.warning(
                "segment index out of range: {} > {}".format(idx, self._phnum))
            return False

        phdr_file_offset = self._phoff + self._phentsize * idx
        phdr_data = self._elffile.structs.Elf_Phdr.build(segment.header)
        self._set_file_bytes(phdr_file_offset, phdr_data)
        return True

    @property
    def _can_add_segment(self) -> bool:
        return True

    def _add_segment(self, addr: int = 0, length: int = 0x1000,
                     prot: int = 7) -> int:
        if not self._phdr_reallocated:
            self._alloc_new_segment_for_phdr()

        if not addr:
            # 自动计算地址
            new_seg = self._auto_next_segment(length, prot)
            if not new_seg:
                return 0
        else:
            new_seg = self._elffile.structs.Elf_Phdr.parse(
                bytes(self._elffile.structs.Elf_Phdr.sizeof()))
            new_seg.p_type = 'PT_LOAD'
            new_seg.p_flags = prot
            new_seg.p_offset = self.align(self.binary_size)
            new_seg.p_vaddr = addr
            new_seg.p_paddr = addr
            new_seg.p_filesz = length
            new_seg.p_memsz = length
            new_seg.p_align = 0x1000

        # segment内容用全0填充
        self._set_file_bytes(new_seg.p_offset, bytes(new_seg.p_filesz))

        pht_data = bytearray()
        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            phdr = seg.header
            if phdr.p_type == 'PT_PHDR':
                # 修改PHDR的size
                phdr.p_filesz += self._phentsize
                phdr.p_memsz += self._phentsize
            pht_data += self._elffile.structs.Elf_Phdr.build(phdr)
        pht_data += self._elffile.structs.Elf_Phdr.build(new_seg)

        # 写入新 phdr 数据
        self._set_file_bytes(self._phoff, pht_data)
        # 更新并写入 ehdr
        self._elffile.header.e_phnum += 1
        new_ehdr = self._elffile.structs.Elf_Ehdr.build(self._elffile.header)
        self._set_file_bytes(0, new_ehdr)
        self._reload()

        log.success("Add segment @ {}({}) {}{}{}".format(
            hex(new_seg.p_vaddr), hex(new_seg.p_memsz),
            "r" if new_seg.flags & constants.P_FLAGS.PF_R else "-",
            "w" if new_seg.flags & constants.P_FLAGS.PF_W else "-",
            "x" if new_seg.flags & constants.P_FLAGS.PF_X else "-",
        ))
        return new_seg.p_vaddr

    def _auto_next_segment(self, length: int, prot: int):
        aligned_file_end = self.align(self.binary_size)
        next_segment_addr = aligned_file_end
        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            if seg.header.p_type == 'PT_LOAD':
                seg_start = seg.header.p_vaddr - self.image_base
                seg_end = self.align(seg_start + seg.header.p_memsz)
                if seg_start > aligned_file_end:
                    continue
                next_segment_addr = max(next_segment_addr, seg_end)

        res_seg = self._elffile.structs.Elf_Phdr.parse(
            bytes(self._elffile.structs.Elf_Phdr.sizeof()))
        res_seg.p_type = 'PT_LOAD'
        res_seg.p_flags = prot
        res_seg.p_offset = next_segment_addr
        res_seg.p_vaddr = next_segment_addr + self.image_base
        res_seg.p_paddr = next_segment_addr + self.image_base
        res_seg.p_filesz = length
        res_seg.p_memsz = length
        res_seg.p_align = 0x1000
        return res_seg

    def _alloc_new_segment_for_phdr(self) -> int:
        new_seg_for_phdr = self._auto_next_segment(0x1000, 5)
        self._set_file_bytes(new_seg_for_phdr.p_paddr,
                             bytes(new_seg_for_phdr.p_filesz))
        pht_data = bytearray()
        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            phdr = seg.header
            if phdr.p_type == 'PT_PHDR':
                # 修改PHDR file_offset 和 size
                phdr.p_offset = new_seg_for_phdr.p_offset
                phdr.p_paddr = new_seg_for_phdr.p_paddr
                phdr.p_vaddr = new_seg_for_phdr.p_vaddr
                phdr.p_filesz += self._phentsize
                phdr.p_memsz += self._phentsize
            pht_data += self._elffile.structs.Elf_Phdr.build(phdr)
        pht_data += self._elffile.structs.Elf_Phdr.build(new_seg_for_phdr)
        # 写入新 phdr 数据
        self._set_file_bytes(new_seg_for_phdr.p_offset, pht_data)
        # 更新并写入 ehdr
        self._elffile.header.e_phoff = new_seg_for_phdr.p_offset
        self._elffile.header.e_phnum += 1
        new_ehdr = self._elffile.structs.Elf_Ehdr.build(self._elffile.header)
        self._set_file_bytes(0, new_ehdr)
        self._reload()

        self._phdr_reallocated = True
        return new_seg_for_phdr.p_paddr

    def _segment_from_virtual_address(self, virtual_addr: int) -> Segment:
        for seg in self._elffile.iter_segments():
            if seg.header.p_type == 'PT_LOAD':
                if seg.header.p_vaddr <= virtual_addr < seg.header.p_vaddr + seg.header.p_memsz:
                    return seg

        raise Exception(
            "Can't found segment from virtual address: 0x{:x}".format(
                virtual_addr))

    def _reload(self) -> bool:
        """
        当patch对header等重要数据做出修改后，需要更新一下elffile
        :return:
        """
        self._elffile = ELFFile(io.BytesIO(self.binary_data))
        return True

    def _hook_byte_intel(self, vaddr: int,
                         byte: str or bytes or bytearray) -> bool:
        if isinstance(byte, str):
            byte = byte.encode('latin-1')
        if isinstance(byte, bytes):
            byte = bytearray(byte)
        byte += b'\xc3'  # append ret
        self.add_byte(byte, "user_hook_{}".format(hex(vaddr)))
        return self._hook_intel(vaddr)

    def _hook_asm_intel(self, vaddr: int, asm: str) -> bool:
        asm += ';ret;'  # append ret
        addr = self._add_asm(asm)
        if not addr:
            return False
        self._label(addr, "user_hook_{}".format(hex(vaddr)))
        return self._hook_intel(vaddr)

    def _hook_intel(self, vaddr: int) -> bool:
        x86_jmp_inst_length = 5
        disasm_data = bytearray(self._get_byte(vaddr, 0x20))
        cs_disasm = self.cs.disasm(disasm_data, vaddr)
        origin1_jmp_addr = vaddr
        tmp_len = 0
        for i, disasm in enumerate(cs_disasm):
            if i == 0 or tmp_len < x86_jmp_inst_length:
                tmp_len += len(disasm.bytes)
        origin1_jmp_length = tmp_len
        origin2_jmp_addr = vaddr + origin1_jmp_length
        backup_length = origin1_jmp_length + x86_jmp_inst_length
        backup1 = self._add_byte(bytearray(backup_length))
        if not backup1:
            return False
        self._label(backup1, "backup1_{}".format(hex(vaddr)))
        backup2 = self._add_byte(bytearray(backup_length))
        if not backup2:
            return False
        self._label(backup2, "backup2_{}".format(hex(vaddr)))
        if self.arch == Arch.I386:
            detour1_asm = '''
    pushad
    call get_pc
    pc: mov esi,edi
    sub edi, pc - {}
    sub esi, pc - {{backup2_{}}}
    mov ecx, {} /* patch_byte_len */
    cld
    rep movsb
    popad
    call {{user_hook_{}}} /* hook_func */
    jmp {} /* origin1 */
get_pc:
    mov edi, [esp]
    ret
'''.format(vaddr, hex(vaddr), backup_length, hex(vaddr), origin1_jmp_addr)

            detour2_asm = '''
    pushf
    pushad
    call get_pc
    pc: mov esi,edi
    sub edi, pc - {}
    sub esi, pc - {{backup1_{}}}
    mov ecx, {} /* patch_byte_len */
    cld
    rep movsb
    popad
    popf
    jmp {} /* origin2 */
get_pc:
    mov edi, [esp]
    ret
'''.format(vaddr, hex(vaddr), backup_length, origin2_jmp_addr)
        elif self.arch == Arch.AMD64:
            detour1_asm = '''
    push rdi /* backup reg */
    push rsi
    push rcx
    lea rdi, [{}]
    lea rsi, [{{backup2_{}}}]
    mov rcx, {} /* patch_byte_len */
    cld
    rep movsb
    pop rcx /* restore reg */
    pop rsi
    pop rdi
    call {{user_hook_{}}} /* hook_func */
    jmp {} /* origin1 */
'''.format(vaddr, hex(vaddr), backup_length, hex(vaddr), origin1_jmp_addr)

            detour2_asm = '''
    pushf
    push rdi /* backup reg */
    push rsi
    push rcx
    lea rdi, [{}]
    lea rsi, [{{backup1_{}}}]
    mov rcx, {} /* patch_byte_len */
    cld
    rep movsb
    pop rcx /* restore reg */
    pop rsi
    pop rdi
    popf
    jmp {} /* origin2 */
'''.format(vaddr, hex(vaddr), backup_length, origin2_jmp_addr)
        else:
            # should not be here
            return False

        detour1 = self._add_asm(detour1_asm)
        if not detour1:
            return False
        self._label(detour1, "detour1_{}".format(hex(vaddr)))
        detour2 = self._add_asm(detour2_asm)
        if not detour2:
            return False
        self._label(detour2, "detour2_{}".format(hex(vaddr)))
        origin1_jmp, inst_cnt = self._asm(
            "jmp {{detour1_{}}}".format(hex(vaddr)), origin1_jmp_addr)
        origin2_jmp, inst_cnt = self._asm(
            "jmp {{detour2_{}}}".format(hex(vaddr)), origin2_jmp_addr)
        backup1_bytes = bytearray(
            self._get_byte(vaddr, backup_length))
        backup1_bytes[:len(origin1_jmp)] = origin1_jmp
        backup2_bytes = bytearray(
            self._get_byte(vaddr, backup_length))
        backup2_bytes[origin1_jmp_length:] = origin2_jmp
        self._patch_byte(backup1, backup1_bytes)
        self._patch_byte(backup2, backup2_bytes)
        self._patch_byte(vaddr, backup1_bytes)
        segment = self._segment_from_virtual_address(vaddr)
        if not segment.header.p_flags & constants.P_FLAGS.PF_W:
            log.success("Modify hook segment prot +w")
            segment_idx = self._get_phdr_idx(segment)
            segment.header.p_flags |= constants.P_FLAGS.PF_W
            self._replace_phdr_by_idx(segment, segment_idx)
            self._reload()
        return True

    def rva_to_offset(self, rva: int) -> int:
        for segment in self._elffile.iter_segments():
            # 检查虚拟地址是否在该段的范围内
            if segment['p_vaddr'] <= rva < segment['p_vaddr'] + segment[
                'p_memsz']:
                # 计算偏移量并返回
                return rva - segment['p_vaddr'] + segment['p_offset']

        # 如果没有找到对应的段，可能是节中的地址
        for section in self._elffile.iter_sections():
            # 检查虚拟地址是否在该节的范围内
            if section['sh_addr'] <= rva < section['sh_addr'] + section[
                'sh_size']:
                # 计算偏移量并返回
                return rva - section['sh_addr'] + section['sh_offset']

        raise PatchException("no such virtual address: 0x{:x}".format(rva))

    def add_segment(self, addr: int = 0, length: int = 0x1000,
                    prot: int = 7) -> int:
        """
        新增一个段
        :param addr: 虚拟地址，默认为0表示自动计算
        :param length: 长度，默认0x1000
        :param prot: 保护权限，默认rwx
        :return: 成功则返回申请的地址，失败返回0
        """
        if addr & 0xfff:
            log.fail("address 0x{:x} is not page aligned".format(addr))
            return 0
        return self._add_segment(addr, length, prot)

    def set_execstack(self, enabled: bool) -> bool:
        """
        开启或关闭execstack（只支持ELF）
        :param enabled: 是否开启execstack
        :return:
        """

        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            if seg.header.p_type == 'PT_GNU_STACK':
                if enabled:
                    seg.header.p_flags = constants.P_FLAGS.PF_R | constants.P_FLAGS.PF_W | constants.P_FLAGS.PF_X
                else:
                    seg.header.p_flags = constants.P_FLAGS.PF_R | constants.P_FLAGS.PF_W

                # 更新ph_data
                if not self._replace_phdr_by_idx(seg, i):
                    log.fail("Modify stack phdr failed")
                    return False

                log.success("Set execstack -> {}".format(
                    "enabled" if enabled else "disabled"))
                return True

        log.fail("Can't find GNU_STACK segment")
        return False

    def set_norelro(self) -> bool:
        """
        取消ELF的relro
        :return:
        """

        for i in range(self._elffile.num_segments()):
            seg = self._elffile.get_segment(i)
            if seg.header.p_type == 'PT_GNU_RELRO':
                seg.header.p_type = 'PT_NULL'
                if not self._replace_phdr_by_idx(seg, i):
                    log.fail("Modify phdr failed")
                    return False
                log.success("Set norelro -> enabled")
                return True

        log.fail("Can't find GNU_RELRO segment")
        return False

    def hook_byte(self, vaddr: int, byte: str or bytes or bytearray,
                  label: str = None) -> bool:
        """
        在指定地址插入bytes作为hook代码
        :param vaddr: 虚拟地址
        :param byte: bytes数组
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return:
        """
        if self.arch in [Arch.I386, Arch.AMD64]:
            if self._hook_byte_intel(vaddr, byte):
                self._label(vaddr, label)
                log.success("Hook @ {}".format(hex(vaddr)))
                return True
            else:
                log.fail("Hook @ {} failed".format(hex(vaddr)))
                return False
        else:
            raise TODOException("Only support hook i386 & amd64 for now")

    def hook_asm(self, vaddr: int, asm: str, label: str = None) -> bool:
        """
        在指定地址插入asm作为hook代码
        :param vaddr: 虚拟地址
        :param asm: 汇编代码
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return:
        """
        if self.arch in [Arch.I386, Arch.AMD64]:
            if self._hook_asm_intel(vaddr, asm):
                self._label(vaddr, label)
                log.success("Hook @ {}".format(hex(vaddr)))
                return True
            else:
                log.fail("Hook @ {} failed".format(hex(vaddr)))
                return False
        else:
            raise TODOException("Only support hook i386 & amd64 for now")
