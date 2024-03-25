import math
from collections import namedtuple
from typing import Tuple

import pefile
from pefile import PE

from pwnpatch.enums import *
from pwnpatch.exceptions import *
from pwnpatch.log_utils import log
from pwnpatch.patcher.base import BasePatcher

RealignedSection = namedtuple('RealignedSection',
                              ['name', 'src_offset', 'src_size', 'src_buf',
                               'dst_offset', 'dst_size', 'dst_padding'])


class PePatcher(BasePatcher):
    def __init__(self, filename: str, need_detail=True):
        self.fast_load = not need_detail

        with open(filename, 'rb') as f:
            self._pefile: PE = pefile.PE(data=f.read(),
                                         fast_load=self.fast_load)

        super().__init__(filename)
        self._init_code_cave()

    def _init_basic_info(self):
        # 初始化基础信息
        self.exe_type = EXE.PE
        machine = self._pefile.NT_HEADERS.FILE_HEADER.Machine
        self.arch = {
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: Arch.I386,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: Arch.AMD64,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: Arch.ARM,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']: Arch.ARM64,
        }.get(machine, Arch.NONE)
        if self.arch == Arch.NONE:
            raise UnsupportedBinaryException(
                "Unsupported arch: 0x{:x} ({})".format(
                    machine, pefile.MACHINE_TYPE[machine]))
        self.endian = Endian.LSB
        self.bit_size = {
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: BitSize.X32,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: BitSize.X64,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: BitSize.X32,
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']: BitSize.X64,
        }.get(machine, BitSize.NONE)
        if self.bit_size == BitSize.NONE:
            raise UnsupportedBinaryException(
                "Unsupported arch: 0x{:x} ({})".format(
                    machine, pefile.MACHINE_TYPE[machine]))

        return True

    @property
    def has_overlay(self):
        """
        判断PE文件末尾是否有overlay数据
        :return:
        """
        return self._pefile.get_overlay_data_start_offset() is not None

    @property
    def binary_data(self) -> bytearray:
        if not isinstance(self._pefile.__data__, bytearray):
            self._pefile.__data__ = bytearray(self._pefile.__data__)
        return self._pefile.__data__

    @binary_data.setter
    def binary_data(self, data: bytearray) -> None:
        self._pefile.__data__ = data

    def _init_code_cave(self) -> bool:
        res = False
        for i, section in enumerate(self._pefile.sections):
            # 判断类似.text段的flags
            characteristics = section.Characteristics
            target_flags = [
                'IMAGE_SCN_CNT_CODE',
                'IMAGE_SCN_CNT_INITIALIZED_DATA',
                'IMAGE_SCN_MEM_EXECUTE',
                'IMAGE_SCN_MEM_READ'
            ]
            target_characteristics_mask = 0
            for flag_name in target_flags:
                target_characteristics_mask |= pefile.SECTION_CHARACTERISTICS[
                    flag_name]

            # flags 不满足条件，跳过下一个
            if characteristics & target_characteristics_mask != target_characteristics_mask:
                continue

            file_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize
            if file_size > virtual_size:
                # 更新 virtual size, 否则后续 rva_to_offset 地址可能会转换出错
                section.Misc_VirtualSize = file_size
                section.Misc = section.Misc_VirtualSize
                section.Misc_PhysicalAddress = section.Misc_VirtualSize

                self._reload(self.fast_load)

                # 添加到 code cave
                self.add_range_to_code_cave(
                    self.image_base + section.VirtualAddress + virtual_size,
                    file_size - virtual_size)

                res |= True
                log.info(
                    "add range 0x{:x} - 0x{:x} (0x{:x} bytes) to code cave".format(
                        self.image_base + section.VirtualAddress + virtual_size,
                        self.image_base + section.VirtualAddress + file_size,
                        file_size - virtual_size
                    ))

        return res

    @property
    def _can_add_segment(self) -> bool:
        return True

    def _reload(self, fast_load=True):
        self._pefile = pefile.PE(data=self._pefile.write(),
                                 fast_load=fast_load)

    def _has_room_for_new_section_header(self) -> bool:
        max_header_addr = math.inf
        for i, section in enumerate(self._pefile.sections):
            if section.PointerToRawData == 0:
                continue
            max_header_addr = min(max_header_addr, section.PointerToRawData)

        section_header_size = self._pefile.sections[0].sizeof()
        now_header_end = self._pefile.sections[-1].get_file_offset() + \
                         section_header_size

        return (max_header_addr - now_header_end) // section_header_size >= 1

    def _fix_image_size(self):
        size_of_image = 0
        section_alignment = self._pefile.NT_HEADERS.OPTIONAL_HEADER.SectionAlignment
        file_alignment = self._pefile.NT_HEADERS.OPTIONAL_HEADER.FileAlignment
        for section in self._pefile.sections:
            # 计算区段的舍入后大小
            virtual_size = self.align(section.Misc_VirtualSize,
                                      section_alignment)

            # 更新映像的大小
            size_of_image = max(size_of_image,
                                section.VirtualAddress + virtual_size)

        # 确保整个映像的大小是分页大小的倍数
        size_of_image = self.align(size_of_image, file_alignment)
        self._pefile.OPTIONAL_HEADER.SizeOfImage = size_of_image

    def _alloc_room_for_new_section_header(self) -> bool:
        if self._has_room_for_new_section_header():
            return False

        max_header_addr = math.inf
        for i, section in enumerate(self._pefile.sections):
            if section.PointerToRawData == 0:
                continue
            max_header_addr = min(max_header_addr, section.PointerToRawData)

        section_header_size = self._pefile.sections[0].sizeof()
        alignment = self._pefile.NT_HEADERS.OPTIONAL_HEADER.FileAlignment
        new_max_header_addr = self.align(
            max_header_addr + section_header_size,
            alignment)

        # mod from https://gist.github.com/williballenthin/d43cbc98fa127211c9099f46d2e73d2c
        # the offset at which the current section should begin
        dst_offset = new_max_header_addr
        # list of RealignedSection instances
        dst_secs = []
        for section in sorted(self._pefile.sections,
                              key=lambda s: s.PointerToRawData):
            dst_size = self.align(section.SizeOfRawData, alignment)
            padding = bytes(dst_size - section.SizeOfRawData)

            # collect pointers to the section data
            sec = RealignedSection(
                section.Name,
                section.PointerToRawData,
                section.SizeOfRawData,
                self.binary_data[
                section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData],
                dst_offset,
                dst_size,
                padding)

            log.debug(
                '\tresizing {}\toffset: 0x{:x}\traw size: 0x{:x}  \t--> offset: 0x{:x}\traw size: 0x{:x}'.format(
                    section.Name.decode().strip("\x00"),
                    section.PointerToRawData,
                    section.SizeOfRawData,
                    dst_offset,
                    dst_size))

            dst_secs.append(sec)

            # fixup the section pointers
            section.PointerToRawData = dst_offset
            section.SizeOfRawData = dst_size
            dst_offset += dst_size

        mod_buf = self._pefile.write()
        ret = [mod_buf[:max_header_addr],
               bytes(new_max_header_addr - max_header_addr)]
        for sec in dst_secs:
            ret.append(sec.src_buf)
            ret.append(sec.dst_padding)

        self.binary_data = b''.join(ret)
        self._reload()
        self._fix_image_size()
        self._pefile.NT_HEADERS.OPTIONAL_HEADER.SizeOfHeaders = new_max_header_addr
        self._reload(self.fast_load)
        return True

    def _add_segment(self, addr: int = 0, length: int = 0x1000,
                     prot: int = 7) -> int:
        self._alloc_room_for_new_section_header()
        if not self._has_room_for_new_section_header():
            raise Exception("no room for new section header")

        def auto_last_segment() -> Tuple[int, int]:
            virtual_addr = 0
            file_offset = 0
            for s in self._pefile.sections:
                virtual_addr = self.align(
                    max(virtual_addr, s.VirtualAddress + s.Misc_VirtualSize),
                    self._pefile.NT_HEADERS.OPTIONAL_HEADER.SectionAlignment)
                file_offset = self.align(
                    max(file_offset, s.PointerToRawData + s.SizeOfRawData),
                    self._pefile.NT_HEADERS.OPTIONAL_HEADER.FileAlignment)

            return virtual_addr, file_offset

        def get_new_section_offset() -> int:
            s = max(self._pefile.sections, key=lambda ss: ss.get_file_offset())
            return s.get_file_offset() + s.sizeof()

        last_rva, last_file_offset = auto_last_segment()

        target_flags = [
            'IMAGE_SCN_CNT_CODE',
            'IMAGE_SCN_CNT_INITIALIZED_DATA',
            'IMAGE_SCN_MEM_EXECUTE',
            'IMAGE_SCN_MEM_READ'
        ]
        if prot & SegProt.R.value:
            target_flags.append('IMAGE_SCN_MEM_READ')
        if prot & SegProt.W.value:
            target_flags.append('IMAGE_SCN_MEM_WRITE')
        if prot & SegProt.X.value:
            target_flags.append('IMAGE_SCN_MEM_EXECUTE')
        target_characteristics = 0
        for flag_name in target_flags:
            target_characteristics |= pefile.SECTION_CHARACTERISTICS[
                flag_name]

        new_section = pefile.SectionStructure(
            self._pefile.__IMAGE_SECTION_HEADER_format__)
        new_section.__unpack__(bytes(new_section.sizeof()))

        # 设置 section 属性
        new_section.set_file_offset(get_new_section_offset())
        new_section.Name = b'.patch'
        new_section.Misc_VirtualSize = length
        new_section.Misc = new_section.Misc_VirtualSize
        new_section.Misc_PhysicalAddress = new_section.Misc_VirtualSize
        new_section.VirtualAddress = last_rva
        new_section.SizeOfRawData = length
        new_section.PointerToRawData = last_file_offset
        new_section.PointerToRelocations = 0
        new_section.PointerToLinenumbers = 0
        new_section.NumberOfRelocations = 0
        new_section.NumberOfLinenumbers = 0
        new_section.Characteristics = target_characteristics

        overlay_offset = self._pefile.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay_data = self.binary_data[overlay_offset:]
        else:
            overlay_data = None

        self._set_file_bytes(new_section.PointerToRawData,
                             bytes(new_section.SizeOfRawData))

        # 添加新的 section 到 sections 数组
        self._pefile.sections.append(new_section)
        self._pefile.__structures__.append(new_section)

        # 更新 PE 头信息
        self._pefile.FILE_HEADER.NumberOfSections += 1
        self._fix_image_size()
        self._reload(self.fast_load)

        # 追加之前保存的 overlay 数据
        overlay_offset = self._pefile.get_overlay_data_start_offset()
        if overlay_data is not None:
            self._set_file_bytes(overlay_offset, overlay_data)

        return last_rva + self.image_base

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

        section = self._pefile.get_section_by_rva(vaddr - self.image_base)
        if not section.Characteristics & pefile.SECTION_CHARACTERISTICS[
            'IMAGE_SCN_MEM_WRITE']:
            log.success("Modify hook section prot +w")
            section.Characteristics |= pefile.SECTION_CHARACTERISTICS[
                'IMAGE_SCN_MEM_WRITE']
            self._reload()
        return True

    @property
    def image_base(self) -> int:
        return self._pefile.NT_HEADERS.OPTIONAL_HEADER.ImageBase

    def rva_to_offset(self, rva: int) -> int:
        return self._pefile.get_offset_from_rva(rva - self.image_base)

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
        new_segment = self._add_segment(addr, length, prot)
        if new_segment:
            log.success("Add segment @ 0x{:x}, size: 0x{:x}".format(new_segment,
                                                                    length))
        return new_segment

    def save(self, filename: str = None) -> bool:
        # fix checksum
        self._reload()
        self._pefile.OPTIONAL_HEADER.CheckSum = self._pefile.generate_checksum()

        self._reload(self.fast_load)
        return super().save(filename)

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
