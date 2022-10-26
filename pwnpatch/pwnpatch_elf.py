from pwnpatch.loader import Loader
from pwnpatch.pwnpatch_common import PatcherCommon
from pwnpatch.log_utils import log
from pwnpatch.enums import *
from pwnpatch.exceptions import *
import lief
import struct


class PatcherELF(PatcherCommon):
    def __init__(self, loader: Loader):
        super().__init__(loader)
        # elf phdr segment for add segment
        self.new_phdr_faddr = 0
        # init code cave
        self._init_code_cave()

    def set_execstack(self, enabled: bool) -> bool:
        """
        开启或关闭execstack（只支持ELF）
        :param enabled: 是否开启execstack
        :return:
        """
        for seg in self.ldr.binary.segments:
            # 查找GNU_STACK类型的segment
            if seg.type == lief.ELF.SEGMENT_TYPES.GNU_STACK:
                # dump ph_data，并修改flags
                old_ph_data = self._dump_segment(seg)
                if enabled:
                    seg.flags = lief.ELF.SEGMENT_FLAGS(7)  # rwx
                else:
                    seg.flags = lief.ELF.SEGMENT_FLAGS(6)  # rw-
                new_ph_data = self._dump_segment(seg)
                # 更新ph_data
                if not self._update_segment(old_ph_data, new_ph_data):
                    log.fail("Modify segment failed")
                    return False
                if enabled:
                    log.success("Set execstack -> enabled")
                else:
                    log.success("Set execstack -> disabled")
                return True
        log.fail("Can't find GNU_STACK segment")
        return False

    def set_norelro(self) -> bool:
        """
        取消ELF的relro
        :return:
        """
        for seg in self.ldr.binary.segments:
            if seg.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO:
                old_ph_data = self._dump_segment(seg)
                seg.type = lief.ELF.SEGMENT_TYPES.NULL
                new_ph_data = self._dump_segment(seg)
                if not self._update_segment(old_ph_data, new_ph_data):
                    log.fail("Modify segment failed")
                    return False
                log.success("Set norelro -> enabled")
                return True
        log.fail("Can't find GNU_RELRO segment")
        return False

    def add_segment(self, addr: int = 0, length: int = 0x1000, prot: int = 7) -> int:
        """
        新增一个段
        :param addr: 虚拟地址，默认为0表示自动计算
        :param length: 长度，默认0x1000
        :param prot: 保护权限，默认rwx
        :return: 成功则返回申请的地址，失败返回0
        """
        if addr & 0xfff:
            log.fail("address {} is not page aligned".format(hex(addr)))
            return 0
        return self._add_segment(addr, length, prot)

    def patch_byte(self, vaddr: int, byte: str or bytes or bytearray, label: str = None) -> bool:
        """
        patch字节
        :param vaddr: 虚拟地址
        :param byte: bytes数组
        :param label: 此patch的名字，后续在asm中可以以{name}的方式引用这个patch的地址
        :return: patch是否成功
        """
        return super().patch_byte(vaddr, byte, label)

    def patch_asm(self, vaddr: int, asm: str, label: str = None) -> bool:
        """
        patch汇编代码
        :param vaddr: 虚拟地址
        :param asm: 汇编代码
        :param label: 此patch的名字，后续在asm中可以以{name}的方式引用这个patch的地址
        :return: patch是否成功
        """
        return super().patch_asm(vaddr, asm, label)

    def patch_c(self, vaddr: int, c_code: str, label: str = None) -> bool:
        """
        patch c代码
        :param vaddr: 虚拟地址
        :param c_code: c代码
        :param label: 此patch的名字，后续在asm中可以以{name}的方式引用这个patch的地址
        :return: patch是否成功
        """
        return super().patch_c(vaddr, c_code, label)

    def add_byte(self, byte: str or bytes or bytearray, label: str = None) -> int:
        """
        插入byte到binary中，不关心修改的地址
        :param byte: bytes数组
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return: 插入地址
        """
        return super().add_byte(byte, label)

    def add_asm(self, asm: str, label: str = None) -> int:
        """
        插入asm到binary中，不关心修改的地址
        :param asm: 汇编代码
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return: 插入地址
        """
        return super().add_asm(asm, label)

    def add_c(self, c_code: str, label: str = None) -> int:
        """
        插入c代码到binary中，不关心修改的地址
        :param c_code: c代码
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return: 插入地址
        """
        return super().add_c(c_code, label)

    def hook_byte(self, vaddr: int, byte: str or bytes or bytearray, label: str = None) -> bool:
        """
        在指定地址插入bytes作为hook代码
        :param vaddr: 虚拟地址
        :param byte: bytes数组
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return:
        """
        if self.ldr.arch in [Arch.I386, Arch.AMD64]:
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
        if self.ldr.arch in [Arch.I386, Arch.AMD64]:
            if self._hook_asm_intel(vaddr, asm):
                self._label(vaddr, label)
                log.success("Hook @ {}".format(hex(vaddr)))
                return True
            else:
                log.fail("Hook @ {} failed".format(hex(vaddr)))
                return False
        else:
            raise TODOException("Only support hook i386 & amd64 for now")

    def hook_c(self, vaddr: int, c_code: str, label: str = None) -> bool:
        """
        在指定地址插入c代码作为hook代码，需要考虑库函数调用的问题
        :param vaddr: 虚拟地址
        :param c_code: c代码
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return:
        """
        # TODO
        raise TODOException("TODO")

    def label(self, vaddr: int, label_name: str) -> bool:
        """
        给指定地址起别名
        :param vaddr: 虚拟地址
        :param label_name: 名字，后续在asm中可以以{name}的方式引用此地址
        :return:
        """
        return super().label(vaddr, label_name)

    def save(self, filename: str = None) -> bool:
        """
        保存patch后的binary
        :param filename: 保存文件名（默认值为 <源文件名>.patched<.后缀>）
        :return:
        """
        return super().save(filename)

    def _hook_byte_intel(self, vaddr: int, byte: str or bytes or bytearray) -> bool:
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
        disasm_data = bytearray(self.ldr.binary.get_content_from_virtual_address(vaddr, 0x20))
        cs_disasm = self.ldr.cs.disasm(disasm_data, vaddr)
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
        if self.ldr.arch == Arch.I386:
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
        elif self.ldr.arch == Arch.AMD64:
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
        origin1_jmp, inst_cnt = self._asm("jmp {{detour1_{}}}".format(hex(vaddr)), origin1_jmp_addr)
        origin2_jmp, inst_cnt = self._asm("jmp {{detour2_{}}}".format(hex(vaddr)), origin2_jmp_addr)
        backup1_bytes = bytearray(self.ldr.binary.get_content_from_virtual_address(vaddr, backup_length))
        backup1_bytes[:len(origin1_jmp)] = origin1_jmp
        backup2_bytes = bytearray(self.ldr.binary.get_content_from_virtual_address(vaddr, backup_length))
        backup2_bytes[origin1_jmp_length:] = origin2_jmp
        self._patch_byte(backup1, backup1_bytes)
        self._patch_byte(backup2, backup2_bytes)
        self._patch_byte(vaddr, backup1_bytes)
        segment = self.ldr.binary.segment_from_virtual_address(vaddr)
        if not segment.flags & lief.ELF.SEGMENT_FLAGS.W:
            log.success("Modify hook segment prot +w")
            old_ph_data = self._dump_segment(segment)
            segment.flags = lief.ELF.SEGMENT_FLAGS(
                int(lief.ELF.SEGMENT_FLAGS.W) | int(segment.flags)
            )
            new_ph_data = self._dump_segment(segment)
            self._update_segment(old_ph_data, new_ph_data)
        return True

    def _init_code_cave(self) -> None:
        # 尝试将.eh_frame加入code cave buffer
        if self.ldr.binary.has_section(".eh_frame"):
            eh_frame_section = self.ldr.binary.get_section(".eh_frame")
            self.code_cave.append([eh_frame_section.virtual_address, eh_frame_section.size])
            # 如果 .eh_frame的权限为只读，需要patch一下segment的权限+x
            eh_frame_segment = list(eh_frame_section.segments)[0]
            if not eh_frame_segment.flags & lief.ELF.SEGMENT_FLAGS.X:
                log.success("Modify .eh_frame section prot +x")
                old_ph_data = self._dump_segment(eh_frame_segment)
                eh_frame_segment.flags = lief.ELF.SEGMENT_FLAGS(
                    int(lief.ELF.SEGMENT_FLAGS.X) | int(eh_frame_segment.flags)
                )
                new_ph_data = self._dump_segment(eh_frame_segment)
                self._update_segment(old_ph_data, new_ph_data)

    def _dump_segment(self, segment: lief.ELF.Segment) -> bytes or None:
        """
        将lief中的segment数据结构导出成bytes格式
        :param segment: lief的Segment类
        :return:
        """
        if self.ldr.bit_size == 64:
            return struct.pack("<IIQQQQQQ" if self.ldr.endian == Endian.LSB else ">IIQQQQQQ",
                               segment.type, segment.flags, segment.file_offset,
                               segment.virtual_address, segment.physical_address,
                               segment.physical_size, segment.virtual_size,
                               segment.alignment
                               )
        elif self.ldr.bit_size == 32:
            return struct.pack("<IIIIIIII" if self.ldr.endian == Endian.LSB else ">IIIIIIII",
                               segment.type, segment.file_offset,
                               segment.virtual_address, segment.physical_address,
                               segment.physical_size, segment.virtual_size,
                               segment.flags, segment.alignment
                               )
        else:
            return None

    def _dump_header(self) -> bytes or None:
        hdr = self.ldr.binary.header
        if self.ldr.bit_size == 64:
            return bytes(
                bytearray(self.ldr.binary.header.identity) +
                struct.pack(
                    "<HHIQQQIHHHHHH" if self.ldr.endian == Endian.LSB else ">HHIQQQIHHHHHH",
                    hdr.file_type, hdr.machine_type, hdr.object_file_version,
                    hdr.entrypoint, hdr.program_header_offset,
                    hdr.section_header_offset, hdr.processor_flag,
                    hdr.header_size, hdr.program_header_size,
                    hdr.numberof_segments, hdr.section_header_size,
                    hdr.numberof_sections, hdr.section_name_table_idx
                ))
        elif self.ldr.bit_size == 32:
            return bytes(
                bytearray(self.ldr.binary.header.identity) +
                struct.pack(
                    "<HHIIIIIHHHHHH" if self.ldr.endian == Endian.LSB else ">HHIIIIIHHHHHH",
                    hdr.file_type, hdr.machine_type, hdr.object_file_version,
                    hdr.entrypoint, hdr.program_header_offset,
                    hdr.section_header_offset, hdr.processor_flag,
                    hdr.header_size, hdr.program_header_size,
                    hdr.numberof_segments, hdr.section_header_size,
                    hdr.numberof_sections, hdr.section_name_table_idx
                ))
        else:
            return None

    def _update_segment(self, old_ph_data: bytes, new_ph_data: bytes) -> bool:
        """
        更新segment信息到binary上
        :param old_ph_data:
        :param new_ph_data:
        :return:
        """
        for ph_idx in range(self.ldr.phnum):
            ph_data_find = self._fetch_binary_data(
                self.ldr.phoff + ph_idx * self.ldr.phentsize, self.ldr.phentsize)
            if ph_data_find == old_ph_data:
                self._cover_binary_data(
                    self.ldr.phoff + ph_idx * self.ldr.phentsize, new_ph_data)
                return True
        return False

    def _update_header(self, header_data: bytes) -> bool:
        """
        更新elf的header信息
        :param header_data:
        :return:
        """
        self._cover_binary_data(0, header_data)
        return True

    def _add_segment(self, addr: int = 0, length: int = 0x1000, prot: int = 7) -> int:
        if not self.new_phdr_faddr:
            self._alloc_new_segment_for_phdr()
        if not addr:
            # 自动计算地址
            new_seg = self._auto_next_segment(length, prot)
            if not new_seg:
                return 0
        else:
            new_seg = lief.ELF.Segment()
            new_seg.type = lief.ELF.SEGMENT_TYPES.LOAD
            new_seg.flags = lief.ELF.SEGMENT_FLAGS(prot)
            new_seg.alignment = 0x1000
            new_seg.physical_size = length
            new_seg.virtual_size = length
            new_seg.physical_address = addr
            new_seg.virtual_address = addr
            new_seg.file_offset = self._align_page(self.ldr.binary_size())
        # segment内容用全0填充
        self._cover_binary_data(new_seg.file_offset, bytearray(new_seg.virtual_size))
        pht_data = bytearray()
        for seg in self.ldr.binary.segments:
            if seg.type == lief.ELF.SEGMENT_TYPES.PHDR:
                # 修改PHDR的size
                seg.physical_size += self.ldr.phentsize
                seg.virtual_size += self.ldr.phentsize
            pht_data += self._dump_segment(seg)
        pht_data += self._dump_segment(new_seg)
        # 在new_phdr_segment写入新pht_data
        self._cover_binary_data(self.new_phdr_faddr, pht_data)
        # 更新header
        self.ldr.binary.header.numberof_segments += 1
        self._update_header(self._dump_header())
        self.ldr.lief_reload_binary()
        log.success("Add segment @ {}({}) {}{}{}".format(
            hex(new_seg.virtual_address), hex(new_seg.virtual_size),
            "r" if new_seg.flags & 4 else "-",
            "w" if new_seg.flags & 2 else "-",
            "x" if new_seg.flags & 1 else "-",
        ))
        return new_seg.virtual_address

    def _auto_next_segment(self, length: int, prot: int) -> lief.ELF.Segment or None:
        aligned_file_end = self._align_page(len(self.ldr.binary_data))
        next_segment_addr = aligned_file_end
        for seg in self.ldr.binary.segments:
            if seg.type == lief.ELF.SEGMENT_TYPES.LOAD:
                seg_start = seg.virtual_address - self.ldr.binary.imagebase
                seg_end = self._align_page(seg_start + seg.virtual_size)
                if seg_start > aligned_file_end:
                    continue
                next_segment_addr = max(next_segment_addr, seg_end)
        ans_segment = lief.ELF.Segment()
        ans_segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        ans_segment.flags = lief.ELF.SEGMENT_FLAGS(prot)
        ans_segment.alignment = 0x1000
        ans_segment.physical_size = length
        ans_segment.virtual_size = length
        ans_segment.physical_address = next_segment_addr + self.ldr.binary.imagebase
        ans_segment.virtual_address = next_segment_addr + self.ldr.binary.imagebase
        ans_segment.file_offset = next_segment_addr
        return ans_segment

    def _alloc_new_segment_for_phdr(self) -> int:
        if self.new_phdr_faddr:
            return self.new_phdr_faddr

        phdr_seg = self._auto_next_segment(0x1000, 5)
        self._cover_binary_data(phdr_seg.file_offset, bytearray(phdr_seg.virtual_size))
        pht_data = bytearray()
        for seg in self.ldr.binary.segments:
            if seg.type == lief.ELF.SEGMENT_TYPES.PHDR:
                # 修改PHDR file_offset 和 size
                seg.file_offset = phdr_seg.file_offset
                seg.physical_address = phdr_seg.physical_address
                seg.virtual_address = phdr_seg.virtual_address
                seg.physical_size += self.ldr.phentsize
                seg.virtual_size += self.ldr.phentsize
            pht_data += self._dump_segment(seg)
        pht_data += self._dump_segment(phdr_seg)
        # 写入新pht_data
        self._cover_binary_data(phdr_seg.file_offset, pht_data)
        # 更新header
        self.ldr.binary.header.program_header_offset = phdr_seg.file_offset
        self.ldr.binary.header.numberof_segments += 1
        self._update_header(self._dump_header())
        self.ldr.lief_reload_binary()
        # 更新 new_phdr_faddr
        self.new_phdr_faddr = phdr_seg.file_offset
        return self.new_phdr_faddr
