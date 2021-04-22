from pwnpatch.loader import Loader
from pwnpatch.pwnpatch_common import PatcherCommon
from pwnpatch.log_utils import log
from pwnpatch.exceptions import *
import lief


class PatcherPE(PatcherCommon):
    def __init__(self, loader: Loader):
        super().__init__(loader)
        # init code cave
        self._init_code_cave()

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
        # TODO
        raise TODOException("TODO")

    def hook_asm(self, vaddr: int, asm: str, label: str = None) -> bool:
        """
        在指定地址插入asm作为hook代码
        :param vaddr: 虚拟地址
        :param asm: 汇编代码
        :param label: 此hook的名字，后续在asm中可以以{name}的方式引用这个hook的地址
        :return:
        """
        # TODO
        raise TODOException("TODO")

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

    def _init_code_cave(self):
        # 使用.text段后面的空穴
        for i, section in enumerate(self.ldr.binary.sections):
            if section.name == '.text' and \
                    section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                len_data = section.sizeof_raw_data
                v_size = section.virtual_size
                if len_data > v_size:
                    self.code_cave.append([self.ldr.imagebase + section.virtual_address + v_size, len_data - v_size])
                    # 如果不修改lief section信息的virtual_size，则后续va_to_offset地址会转换出错
                    self.ldr.binary.sections[i].virtual_size = len_data

    def _add_segment(self, addr: int = 0, length: int = 0x1000, prot: int = 7) -> int:
        # TODO pe add segment
        raise TODOException("TODO pe add segment")
