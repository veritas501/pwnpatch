import os
import platform
import subprocess
import lief
from pwnpatch.loader import Loader
from pwnpatch.log_utils import log
from pwnpatch.exceptions import *
from pwnpatch.enums import *


class PatcherCommon:
    def __init__(self, loader: Loader):
        self.ldr = loader
        # 解析符号
        self.symbols = {}
        # code cave
        self.code_cave = []

    def patch_byte(self, vaddr: int, byte: str or bytes or bytearray, label: str = None) -> bool:
        try:
            self._patch_byte(vaddr, byte)
        except PatchException as ex:
            log.fail(ex)
            return False
        self._label(vaddr, label)
        log.success("Patch {} bytes @ {}".format(hex(len(byte)), hex(vaddr)))
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

    def patch_c(self, vaddr: int, c_code: str, label: str = None) -> bool:
        try:
            compiled_bytes = self._call_scc(c_code)
        except SccException as ex:
            log.fail(ex)
            return False
        if not compiled_bytes:
            log.fail("call scc to generate binary code failed")
            return False
        try:
            self._patch_byte(vaddr, compiled_bytes)
        except PatchException as ex:
            log.fail(ex)
            return False
        self._label(vaddr, label)
        log.success("Patch c code @ {}".format(hex(vaddr)))
        return True

    def label(self, vaddr: int, label_name: str) -> bool:
        if self._label(vaddr, label_name):
            log.success("name {} with {}".format(hex(vaddr), label_name))
            return True
        log.fail("name {} with {} failed".format(hex(vaddr), label_name))
        return False

    def save(self, filename: str = None) -> bool:
        if not filename:
            bin_name = self.ldr.binary_name
            bin_postfix = os.path.splitext(bin_name)[-1].lower()
            bin_true_name = ''.join(os.path.splitext(bin_name)[:-1])
            filename = "{}.patched{}".format(bin_true_name, bin_postfix)
        open(filename, "wb").write(self.ldr.binary_data)
        os.chmod(filename, 0o755)
        log.success("Binary saved @ {}".format(log.underline(
            os.path.abspath(filename)
        )))
        return True

    def add_byte(self, byte: str or bytes or bytearray, label: str = None) -> int:
        try:
            target_vaddr = self._add_byte(byte)
        except AddException as ex:
            log.fail(ex)
            return 0
        if not target_vaddr:
            log.fail("Add {} bytes @ {} failed".format(hex(len(byte)), hex(target_vaddr)))
            return 0
        self._label(target_vaddr, label)
        log.success("Add {} bytes @ {}".format(hex(len(byte)), hex(target_vaddr)))
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

    def add_c(self, c_code: str, label: str = None) -> int:
        try:
            compiled_bytes = self._call_scc(c_code)
            target_vaddr = self._add_byte(compiled_bytes)
        except SccException as ex:
            log.fail(ex)
            return 0
        except AddException as ex:
            log.fail(ex)
            return 0
        self._label(target_vaddr, label)
        log.success("Add c_code @ {}".format(hex(target_vaddr)))
        return target_vaddr

    def _align_page(self, vaddr, pagesize=0x1000):
        return (vaddr + (pagesize - 1)) - (vaddr + (pagesize - 1)) % pagesize

    def _va_to_offset(self, va: int) -> int:
        if self.ldr.is_elf():
            return self.ldr.binary.virtual_address_to_offset(va)
        elif self.ldr.is_pe():
            return self.ldr.binary.va_to_offset(va)

    def _add_segment(self, addr: int = 0, length: int = 0x1000, prot: int = 7):
        # PLEASE OVERRIDE
        return 0

    def _patch_byte(self, vaddr: int, byte: str or bytes or bytearray):
        # 检查地址align
        if self.ldr.need_align() and vaddr % 4 != 0:
            # 因为patch的地址是用户传递的，因此这里只能warn一下
            log.warn("address {} is not 4 bytes aligned".format(hex(vaddr)))
        # 检查是否有对应的vaddr
        try:
            start_faddr = self._va_to_offset(vaddr)
            end_faddr = self._va_to_offset(vaddr + len(byte) - 1)
        except lief.exception:
            # patch too long
            raise PatchException("Patch {} bytes @ {} is too long".format(hex(len(byte)), hex(vaddr)))
        self._cover_binary_data(start_faddr, byte)

    def _add_byte(self, byte: str or bytes or bytearray) -> int:
        need_length = len(byte)
        target_vaddr = 0
        for i in range(len(self.code_cave)):
            add_vaddr, add_length = self.code_cave[i]
            # 判断align
            if self.ldr.need_align():
                if add_vaddr % 4:
                    add_length -= 4 - add_vaddr % 4
                    add_vaddr += 4 - add_vaddr % 4
            if add_length >= need_length:
                target_vaddr = add_vaddr
                self.code_cave[i] = [add_vaddr + need_length, add_length - need_length]
                break
        if not target_vaddr:
            # 现有code cave不够大
            seg_length = self._align_page(need_length)
            new_seg = self._add_segment(0, seg_length, 7)
            if new_seg:
                # 添加新段，并添加到code cave
                self.code_cave.append([new_seg, seg_length])
                # 递归调用
                return self._add_byte(byte)
            else:
                raise AddException("Generate new memory failed")
        start_faddr = self._va_to_offset(target_vaddr)
        self._cover_binary_data(start_faddr, byte)
        return target_vaddr

    def _add_asm(self, asm: str) -> int:
        target_vaddr = 0
        need_length = 0
        byte_code = bytes()
        for i in range(len(self.code_cave)):
            add_vaddr, add_length = self.code_cave[i]
            # 判断align
            if self.ldr.need_align():
                if add_vaddr % 4:
                    add_length -= 4 - add_vaddr % 4
                    add_vaddr += 4 - add_vaddr % 4
            # asm需要先预定位置才能判断长度
            byte_code, inst_cnt = self._asm(asm, add_vaddr)
            if not inst_cnt:
                return 0
            need_length = len(byte_code)
            if add_length >= need_length:
                target_vaddr = add_vaddr
                self.code_cave[i] = [add_vaddr + need_length, add_length - need_length]
                break
        if not target_vaddr:
            # 现有code cave不够大
            if not need_length:
                # 没有target_vaddr，因此拿image base顶一下算出大概的need_length
                byte_code, inst_cnt = self._asm(asm, self.ldr.binary.imagebase)
                if not inst_cnt:
                    return 0
                need_length = len(byte_code)
            seg_length = self._align_page(need_length)
            new_seg = self._add_segment(0, seg_length, 7)
            if new_seg:
                # 添加新段，并添加到code cave
                self.code_cave.append([new_seg, seg_length])
                # 递归调用
                return self._add_asm(asm)
            else:
                raise AddException("Generate new memory failed")
        start_faddr = self._va_to_offset(target_vaddr)
        self._cover_binary_data(start_faddr, byte_code)
        return target_vaddr

    def _asm(self, asm: str, vma: int) -> (bytes, int):
        """
        将汇编代码转换为机器码
        :param asm: 汇编代码
        :param vma: 虚拟地址
        :return: (机器码，机器码长度)
        """
        try:
            asm_formatted = asm.format(**self.symbols)
        except KeyError as ex:
            log.fail("Can't find symbol {}".format(ex))
            return bytes(), 0
        return self.ldr.ks.asm(asm_formatted, vma, True)

    def _label(self, vaddr: int, label_name: str) -> bool:
        """
        给指定地址起别名
        :param vaddr: 虚拟地址
        :param label_name: 名字，后续在asm中可以以{name}的方式引用此地址
        :return:
        """
        if not label_name:
            return False
        self.symbols[label_name] = vaddr
        return True

    def _call_scc(self, c_code: str) -> bytes:
        """
        调用scc工具将c代码转换成机器码
        :param c_code:
        :return:
        """
        machine_platform = platform.system()
        scc_path = {
            "Linux": "scc/scc_linux",
            "Windows": "scc/scc_win.exe",
            "Darwin": "scc/scc_mac",
        }.get(machine_platform)
        if not scc_path:
            raise SccException("unsupported os platform for scc")
        scc_path = os.path.join(os.path.split(os.path.realpath(__file__))[0], scc_path)
        binary_format = {
            EXE.ELF: "linux",
            EXE.PE: "windows",
        }.get(self.ldr.format)
        if not binary_format:
            raise SccException("unsupported binary format")
        arch = {
            Arch.I386: "x86",
            Arch.AMD64: "x64",
            Arch.ARM: "arm",
            Arch.ARM64: "aarch64",
            Arch.MIPS: "mipsel",
        }.get(self.ldr.arch)
        if self.ldr.arch == Arch.ARM and self.ldr.endian == Endian.MSB:
            arch = "armeb"
        if self.ldr.arch == Arch.MIPS and self.ldr.endian == Endian.MSB:
            arch = "mips"
        if not arch:
            raise SccException("scc not support this binary architecture")
        child_process = subprocess.Popen(
            [scc_path, "--pie", "-Os", "--allow-return", "--stdout", "--stdin",
             "--platform", binary_format, "--arch", arch,
             "-m32" if self.ldr.bit_size == 32 else "-m64"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        byte_code = child_process.communicate(c_code.encode('latin-1'))[0]
        if len(byte_code) == 0:
            raise SccException("ssc get empty code")
        return byte_code

    def _cover_binary_data(self, off: int, data: str or bytes or bytearray) -> None:
        self.ldr.cover_binary_data(off, data)

    def _fetch_binary_data(self, off: int, size: int) -> bytearray:
        return self.ldr.fetch_binary_data(off, size)
