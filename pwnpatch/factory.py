from typing import Union

from pwnpatch import enums
from pwnpatch import exceptions
from pwnpatch import patcher


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
        raise exceptions.UnsupportedBinaryException("Not a PE or ELF file")

    @classmethod
    def get_patcher(
        cls, filename: str, minimal_edit: bool
    ) -> Union[patcher.ElfPatcher, patcher.PePatcher]:
        exe_type = cls.get_binary_type(filename)
        if exe_type == enums.EXE.PE:
            return patcher.PePatcher(filename, minimal_edit=minimal_edit)
        elif exe_type == enums.EXE.ELF:
            return patcher.ElfPatcher(filename, minimal_edit=minimal_edit)
        raise exceptions.UnsupportedBinaryException("unknown exe type")
