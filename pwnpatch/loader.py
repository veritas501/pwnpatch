"""
pwnpatch 基础类
"""
import os
import lief
import keystone as ks
import capstone as cs
import struct
import subprocess
import platform
from pwnpatch.log_utils import log
from pwnpatch.enums import *
from pwnpatch.exceptions import *


class Loader:
    def __init__(self, filename: str):
        # 初始化路径，文件名
        self.rel_binary_path = filename
        self.abs_binary_path = os.path.abspath(self.rel_binary_path)
        self.abs_dir, self.binary_name = os.path.split(self.abs_binary_path)

        # 用lief库加载解析binary
        self._lief_load_binary(self.abs_binary_path)

    def _lief_load_binary(self, binary: str or bytearray or bytes) -> None:
        # 加载binary
        if isinstance(binary, str):
            self.binary = lief.parse(binary)
            self.binary_data = bytearray(open(binary, "rb").read())
        else:
            self.binary = lief.parse(binary)
            self.binary_data = bytearray(binary)
        # binary信息
        self.format = {
            lief.EXE_FORMATS.ELF: EXE.ELF,
            lief.EXE_FORMATS.PE: EXE.PE,
        }.get(self.binary.format)
        if not self.format:
            raise UnsupportedBinaryException("Binary format {} is not support".format(self.binary.format))
        self.endian = Endian.NONE
        self.arch = Arch.NONE
        self.bit_size = 0
        if self.is_elf():
            # arch info
            self.endian = {
                lief.ELF.ELF_DATA.LSB: Endian.LSB,
                lief.ELF.ELF_DATA.MSB: Endian.MSB,
            }.get(self.binary.header.identity_data)
            self.arch = {
                lief.ELF.ARCH.i386: Arch.I386,
                lief.ELF.ARCH.x86_64: Arch.AMD64,
                lief.ELF.ARCH.ARM: Arch.ARM,
                lief.ELF.ARCH.AARCH64: Arch.ARM64,
                lief.ELF.ARCH.MIPS: Arch.MIPS,
            }.get(self.binary.header.machine_type)
            self.bit_size = {
                lief.ELF.ELF_CLASS.CLASS64: 64,
                lief.ELF.ELF_CLASS.CLASS32: 32,
            }.get(self.binary.header.identity_class)
            # header segment
            self.phoff = self.binary.header.program_header_offset
            self.phnum = self.binary.header.numberof_segments
            self.phentsize = self.binary.header.program_header_size
        elif self.is_pe():
            # arch info
            self.arch = {
                lief.PE.MACHINE_TYPES.I386: Arch.I386,
                lief.PE.MACHINE_TYPES.AMD64: Arch.AMD64,
                lief.PE.MACHINE_TYPES.ARM: Arch.ARM,
                lief.PE.MACHINE_TYPES.ARM64: Arch.ARM64,
            }.get(self.binary.header.machine)
            self.endian = Endian.LSB
            self.bit_size = {
                Arch.I386: 32,
                Arch.AMD64: 64,
                Arch.ARM: 32,
                Arch.ARM64: 64,
            }.get(self.arch)
            self.imagebase = self.binary.optional_header.imagebase
        else:
            raise UnsupportedBinaryException("Unsupported binary")
        if not (self.endian and self.arch and self.bit_size):
            raise UnsupportedBinaryException("This binary is not support yet, endian:{} arch:{} elf_class:{}".format(
                self.binary.header.identity_data,
                self.binary.header.machine_type,
                self.binary.header.identity_class
            ))

        # init keystone
        self.ks_arch = ks.KS_ARCH_X86
        self.ks_mode = ks.KS_MODE_LITTLE_ENDIAN if self.endian == Endian.LSB else ks.KS_MODE_BIG_ENDIAN
        if self.arch == Arch.AMD64:
            self.ks_arch = ks.KS_ARCH_X86
            self.ks_mode |= ks.KS_MODE_64
        elif self.arch == Arch.I386:
            self.ks_arch = ks.KS_ARCH_X86
            self.ks_mode |= ks.KS_MODE_32
        elif self.arch == Arch.MIPS:
            self.ks_arch = ks.KS_ARCH_MIPS
            self.ks_mode |= ks.KS_MODE_32 if self.bit_size == 32 else ks.KS_MODE_64
        elif self.arch == Arch.ARM64:
            self.ks_arch = ks.KS_ARCH_ARM64
        elif self.arch == Arch.ARM:
            self.ks_arch = ks.KS_ARCH_ARM
            self.ks_mode |= ks.KS_MODE_ARM
        else:
            raise UnsupportedBinaryException("Unsupported binary")
        self.ks = ks.Ks(self.ks_arch, self.ks_mode)

        # init capstone
        self.cs_arch = cs.CS_ARCH_X86
        self.cs_mode = cs.CS_MODE_LITTLE_ENDIAN if self.endian == Endian.LSB else cs.CS_MODE_BIG_ENDIAN
        if self.arch == Arch.AMD64:
            self.cs_arch = cs.CS_ARCH_X86
            self.cs_mode |= cs.CS_MODE_64
        elif self.arch == Arch.I386:
            self.cs_arch = cs.CS_ARCH_X86
            self.cs_mode |= cs.CS_MODE_32
        elif self.arch == Arch.MIPS:
            self.cs_arch = cs.CS_ARCH_MIPS
            self.cs_mode |= cs.CS_MODE_32 if self.bit_size == 32 else cs.CS_MODE_64
        elif self.arch == Arch.ARM64:
            self.cs_arch = cs.CS_ARCH_ARM64
        elif self.arch == Arch.ARM:
            self.cs_arch = cs.CS_ARCH_ARM
            self.cs_mode |= cs.CS_MODE_ARM
        else:
            raise UnsupportedBinaryException("Unsupported binary")
        self.cs = cs.Cs(self.cs_arch, self.cs_mode)

    def lief_reload_binary(self) -> None:
        """
        重新加载binary，由于对binary中某些关键结构体的修改会
        导致lief中原本的数据结构信息过时，因此需要手动调用这个函数重新加载
        :return:
        """
        self._lief_load_binary(self.binary_data)

    def is_elf(self) -> bool:
        """
        判断是否为elf文件
        :return:
        """
        return self.format == EXE.ELF

    def is_pe(self) -> bool:
        """
        判断是否为pe文件
        :return:
        """
        return self.format == EXE.PE

    def need_align(self) -> bool:
        """
        判断是否需要对齐
        :return:
        """
        if self.arch in [Arch.AMD64, Arch.I386]:
            return False
        return True

    def cover_binary_data(self, off: int, data: str or bytes or bytearray) -> None:
        if off < 0:
            raise Exception("cover_binary_data offset < 0, offset: {}".format(off))
        if isinstance(data, str):
            data = data.encode("latin-1")
        if off > len(self.binary_data):
            self.binary_data += b'\x00' * (off - len(self.binary_data))
        self.binary_data[off:off + len(data)] = bytearray(data)

    def fetch_binary_data(self, off: int, size: int) -> bytearray:
        if off < 0:
            raise Exception("fetch_binary_data offset < 0, offset: {}".format(off))
        if off + size > len(self.binary_data):
            raise Exception("fetch_binary_data offset+size too big, val: {}, max_size: {}".format(
                off + size, len(self.binary_data)))
        return self.binary_data[off:off + size]

    def out_binary(self) -> bytearray:
        """
        返回binary_data
        :return:
        """
        return self.binary_data

    def binary_size(self) -> int:
        return len(self.binary_data)
