from typing import Union

from pwnpatch import enums
from pwnpatch.exceptions import *
from pwnpatch.patcher import *


class PatcherFactory:
    @classmethod
    def is_pefile(cls, filename: str) -> bool:
        with open(filename, "rb") as f:
            magic = f.read(2)
            return magic == b"MZ"

    @classmethod
    def is_elf(cls, filename: str) -> bool:
        with open(filename, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"

    @classmethod
    def get_binary_type(cls, filename: str):
        if cls.is_pefile(filename):
            return enums.EXE.PE
        elif cls.is_elf(filename):
            return enums.EXE.ELF
        raise UnsupportedBinaryException("Not a PE or ELF file")

    @classmethod
    def get_patcher(cls, filename: str) -> Union[ElfPatcher, PePatcher]:
        exe_type = cls.get_binary_type(filename)
        if exe_type == enums.EXE.PE:
            return PePatcher(filename)
        elif exe_type == enums.EXE.ELF:
            return ElfPatcher(filename)
        raise UnsupportedBinaryException("unknown exe type")
