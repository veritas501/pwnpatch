import os
from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Union, Tuple

import capstone as cs
import keystone as ks

from pwnpatch.enums import *
from pwnpatch.exceptions import *
from pwnpatch.log_utils import log


class BasePatcher(ABC):
    def __init__(self, filename: str) -> None:
        # 文件信息
        self.rel_binary_path = filename
        self.abs_binary_path = os.path.abspath(self.rel_binary_path)
        self.abs_dir, self.binary_name = os.path.split(self.abs_binary_path)

        # 基础信息 basic info
        self.exe_type: EXE = EXE.NONE
        self.arch: Arch = Arch.NONE
        self.endian: Endian = Endian.NONE
        self.bit_size: BitSize = BitSize.NONE

        # CS and KS
        self.cs: Optional[cs.Cs] = None
        self.ks: Optional[ks.Ks] = None

        # raw binary data
        self._raw_binary_data: Optional[bytearray] = None

        # 符号表
        self.symbols: Dict = {}

        # internal variables
        self._code_cave: List[List[int]] = []

        # 初始化patcher
        self._init_basic_info()
        self._init_cs_ks()

    def _init_cs_ks(self) -> bool:
        self._init_cs()
        self._init_ks()
        if self.cs is None:
            raise Exception("capstone init failed")
        if self.ks is None:
            raise Exception("keystone init failed")
        return True

    def _init_ks(self) -> bool:
        ks_arch = ks.KS_ARCH_X86
        ks_mode = ks.KS_MODE_LITTLE_ENDIAN if self.endian == Endian.LSB else ks.KS_MODE_BIG_ENDIAN
        if self.arch == Arch.AMD64:
            ks_arch = ks.KS_ARCH_X86
            ks_mode |= ks.KS_MODE_64
        elif self.arch == Arch.I386:
            ks_arch = ks.KS_ARCH_X86
            ks_mode |= ks.KS_MODE_32
        elif self.arch == Arch.MIPS:
            ks_arch = ks.KS_ARCH_MIPS
            ks_mode |= ks.KS_MODE_32 if self.bit_size == BitSize.X32 else ks.KS_MODE_64
        elif self.arch == Arch.ARM64:
            ks_arch = ks.KS_ARCH_ARM64
        elif self.arch == Arch.ARM:
            ks_arch = ks.KS_ARCH_ARM
            ks_mode |= ks.KS_MODE_ARM
        else:
            raise UnsupportedBinaryException("Unsupported binary")
        self.ks = ks.Ks(ks_arch, ks_mode)

        return True

    def _init_cs(self) -> bool:
        cs_arch = cs.CS_ARCH_X86
        cs_mode = cs.CS_MODE_LITTLE_ENDIAN if self.endian == Endian.LSB else cs.CS_MODE_BIG_ENDIAN
        if self.arch == Arch.AMD64:
            cs_arch = cs.CS_ARCH_X86
            cs_mode |= cs.CS_MODE_64
        elif self.arch == Arch.I386:
            cs_arch = cs.CS_ARCH_X86
            cs_mode |= cs.CS_MODE_32
        elif self.arch == Arch.MIPS:
            cs_arch = cs.CS_ARCH_MIPS
            cs_mode |= cs.CS_MODE_32 if self.bit_size == 32 else cs.CS_MODE_64
        elif self.arch == Arch.ARM64:
            cs_arch = cs.CS_ARCH_ARM64
        elif self.arch == Arch.ARM:
            cs_arch = cs.CS_ARCH_ARM
            cs_mode |= cs.CS_MODE_ARM
        else:
            raise UnsupportedBinaryException("Unsupported binary")
        self.cs = cs.Cs(cs_arch, cs_mode)

        return True

    @abstractmethod
    def _init_basic_info(self) -> bool:
        pass

    @abstractmethod
    def _init_code_cave(self) -> bool:
        pass

    def add_range_to_code_cave(self, rva: int, size: int) -> bool:
        new_cave_start = rva
        new_cave_end = rva + size

        # find overlap
        for i, (old_cave_start, old_cave_size) in enumerate(self._code_cave):
            old_cave_end = old_cave_start + old_cave_size
            # if new code cave overlap with the old one, update the old cave
            if new_cave_start <= old_cave_end and new_cave_end >= old_cave_start:
                final_cave_start = min(new_cave_start, old_cave_start)
                final_cave_end = max(new_cave_end, old_cave_end)
                self._code_cave[i] = [final_cave_start,
                                      final_cave_end - final_cave_start]
                return True

        # no overlap
        self._code_cave.append([rva, size])
        return True

    @property
    @abstractmethod
    def _can_add_segment(self) -> bool:
        pass

    @property
    @abstractmethod
    def image_base(self) -> int:
        pass

    def _set_file_bytes(self, offset: int,
                        data: Union[str, bytes, bytearray]) -> None:
        if offset < 0:
            raise Exception(
                "set_file_bytes offset < 0, offset: {}".format(offset))
        if isinstance(data, str):
            data = data.encode("latin-1")
        if offset > len(self.binary_data):
            self.binary_data += b'\x00' * (offset - len(self.binary_data))
        self.binary_data[offset:offset + len(data)] = bytearray(data)

    def _get_file_bytes(self, offset: int, size: int) -> bytearray:
        if offset < 0:
            raise Exception(
                "get_file_bytes offset < 0, offset: {}".format(offset))
        if offset + size > len(self.binary_data):
            raise Exception(
                "get_file_bytes offset+size too big, val: {}, max_size: {}".format(
                    offset + size, len(self.binary_data)))
        return self.binary_data[offset:offset + size]

    def _get_byte(self, rva: int, size: int) -> bytearray:
        start_file_offset = self.rva_to_offset(rva)
        end_file_offset = self.rva_to_offset(rva + size - 1)
        return self._get_file_bytes(start_file_offset, size)

    def _patch_byte(self, rva: int, data: Union[str, bytes, bytearray]):
        # 检查地址align
        if self.need_align and (rva % 4):
            # 因为patch的地址是用户传递的，因此这里只能warn一下
            log.warn("address {} is not 4 bytes aligned".format(hex(rva)))

        # 检查是否有对应的 rva
        start_file_offset = self.rva_to_offset(rva)
        end_file_offset = self.rva_to_offset(rva + len(data) - 1)

        self._set_file_bytes(start_file_offset, data)

    def _add_byte(self, data: Union[str, bytes, bytearray]) -> int:
        need_length = len(data)
        target_rva = 0
        for i in range(len(self._code_cave)):
            add_rva, add_length = self._code_cave[i]
            # 判断align
            if self.need_align:
                if add_rva % 4:
                    add_length -= 4 - add_rva % 4
                    add_rva += 4 - add_rva % 4
            if add_length >= need_length:
                target_rva = add_rva
                self._code_cave[i] = [add_rva + need_length,
                                      add_length - need_length]
                break

        # 现有code cave不够大
        if not target_rva:
            # 当前格式不支持添加新段
            if not self._can_add_segment:
                raise AddException("no enough space")

            seg_length = self.align(need_length)
            new_seg = self.add_segment(0, seg_length, 7)
            if new_seg:
                # 添加新段，并添加到code cave
                self._code_cave.append([new_seg, seg_length])
                # 递归调用
                return self._add_byte(data)
            else:
                raise AddException("Generate new memory failed")
        start_file_offset = self.rva_to_offset(target_rva)
        self._set_file_bytes(start_file_offset, data)
        return target_rva

    def _add_asm(self, asm: Union[str, bytes, bytearray]) -> int:
        target_rva = 0
        need_length = 0
        byte_code = bytes()
        for i in range(len(self._code_cave)):
            add_vaddr, add_length = self._code_cave[i]
            # 判断align
            if self.need_align:
                if add_vaddr % 4:
                    add_length -= 4 - add_vaddr % 4
                    add_vaddr += 4 - add_vaddr % 4
            # asm需要先预定位置才能判断长度
            byte_code, inst_cnt = self._asm(asm, add_vaddr)
            if not inst_cnt:
                return 0
            need_length = len(byte_code)
            if add_length >= need_length:
                target_rva = add_vaddr
                self._code_cave[i] = [add_vaddr + need_length,
                                      add_length - need_length]
                break

        # 现有code cave不够大
        if not target_rva:
            # 当前格式不支持添加新段
            if not self._can_add_segment:
                raise AddException("no enough space")

            if not need_length:
                # 没有target_vaddr，因此拿image base顶一下算出大概的need_length
                byte_code, inst_cnt = self._asm(asm, self.image_base)
                if not inst_cnt:
                    return 0
                need_length = len(byte_code)
            seg_length = self.align(need_length)
            new_seg = self.add_segment(0, seg_length, 7)
            if new_seg:
                # 添加新段，并添加到code cave
                self._code_cave.append([new_seg, seg_length])
                # 递归调用
                return self._add_asm(asm)
            else:
                raise AddException("Generate new memory failed")

        start_file_offset = self.rva_to_offset(target_rva)
        self._set_file_bytes(start_file_offset, byte_code)
        return target_rva

    def _label(self, rva: int, label_name: str) -> bool:
        """
        给指定地址起别名
        :param rva: 虚拟地址
        :param label_name: 名字，后续在asm中可以以{name}的方式引用此地址
        :return:
        """
        if not label_name:
            return False

        self.symbols[label_name] = rva
        return True

    def _asm(self, asm: Union[str, bytes, bytearray], rva: int) -> Tuple[
        bytes, int]:
        """
        将汇编代码转换为机器码
        :param asm: 汇编代码
        :param rva: 虚拟地址
        :return: (机器码，机器码长度)
        """
        if isinstance(asm, bytes) or isinstance(asm, bytearray):
            asm = asm.decode('latin-1')

        try:
            asm_formatted = asm.format(**self.symbols)
        except KeyError as ex:
            log.fail("Can't find symbol {}".format(ex))
            return bytes(), 0

        return self.ks.asm(asm_formatted, rva, True)

    def dump_code_cave(self):
        log.info("Dumping code cave info:")
        for i, (cave_start, cave_size) in enumerate(self._code_cave):
            log.info("\tcave-{}: 0x{:x} - 0x{:x} (0x{:x} bytes)".format(
                i, cave_start, cave_start + cave_size, cave_size))

    @property
    def need_align(self) -> bool:
        """
        判断是否需要对齐
        :return:
        """
        return self.arch not in [Arch.AMD64, Arch.I386]

    @property
    def binary_data(self) -> bytearray:
        if self._raw_binary_data is None:
            self._raw_binary_data = bytearray(
                open(self.abs_binary_path, 'rb').read())
        return self._raw_binary_data

    @binary_data.setter
    def binary_data(self, data: bytearray) -> None:
        self._raw_binary_data = data

    @property
    def binary_size(self) -> int:
        return len(self.binary_data)

    @abstractmethod
    def rva_to_offset(self, rva: int) -> int:
        pass

    @abstractmethod
    def add_segment(self, addr: int = 0, length: int = 0x1000,
                    prot: int = 7) -> int:
        pass

    @staticmethod
    def align(rva: int, alignment=0x1000) -> int:
        return (rva + (alignment - 1)) - (rva + (alignment - 1)) % alignment

    def patch_byte(self, rva: int, byte: Union[str, bytes, bytearray],
                   label: str = None) -> bool:
        try:
            self._patch_byte(rva, byte)
        except PatchException as ex:
            log.fail(ex)
            return False
        self._label(rva, label)
        log.success("Patch {} bytes @ {}".format(hex(len(byte)), hex(rva)))
        return True

    def patch_asm(self, vaddr: int, asm: str, label: str = None) -> bool:
        byte_code, inst_cnt = self._asm(asm, vaddr)
        if not inst_cnt:
            return False
        try:
            self._patch_byte(vaddr, byte_code)
        except PatchException as ex:
            log.fail(ex)
            return False
        self._label(vaddr, label)
        log.success("Patch {} asm @ {}".format(hex(inst_cnt), hex(vaddr)))
        return True

    def add_byte(self, byte: str or bytes or bytearray,
                 label: str = None) -> int:
        try:
            target_vaddr = self._add_byte(byte)
        except AddException as ex:
            log.fail(ex)
            return 0
        if not target_vaddr:
            log.fail("Add {} bytes @ {} failed".format(hex(len(byte)),
                                                       hex(target_vaddr)))
            return 0
        self._label(target_vaddr, label)
        log.success(
            "Add {} bytes @ {}".format(hex(len(byte)), hex(target_vaddr)))
        return target_vaddr

    def add_asm(self, asm: str, label: str = None) -> int:
        try:
            target_vaddr = self._add_asm(asm)
        except AddException as ex:
            log.fail(ex)
            return 0
        if not target_vaddr:
            log.fail("Add asm @ {} failed".format(hex(target_vaddr)))
            return 0
        self._label(target_vaddr, label)
        log.success("Add asm @ {}".format(hex(target_vaddr)))
        return target_vaddr

    def label(self, vaddr: int, label_name: str) -> bool:
        if self._label(vaddr, label_name):
            log.success("name {} with {}".format(hex(vaddr), label_name))
            return True
        log.fail("name {} with {} failed".format(hex(vaddr), label_name))
        return False

    def save(self, filename: str = None) -> bool:
        """
        保存patch后的binary
        :param filename: 保存文件名（默认值为 <源文件名>.patched<.后缀>）
        :return:
        """
        if not filename:
            bin_name = self.binary_name
            bin_postfix = os.path.splitext(bin_name)[-1].lower()
            bin_true_name = ''.join(os.path.splitext(bin_name)[:-1])
            filename = "{}.patched{}".format(bin_true_name, bin_postfix)

        with open(filename, 'wb') as f:
            f.write(self.binary_data)

        os.chmod(filename, 0o755)
        log.success("Binary saved @ {}".format(log.underline(
            os.path.abspath(filename)
        )))

        return True
