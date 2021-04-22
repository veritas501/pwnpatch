#!/usr/bin/env python3
# Author: veritas501

from pwnpatch.loader import Loader
from pwnpatch.pwnpatch_elf import PatcherELF
from pwnpatch.pwnpatch_pe import PatcherPE


def patcher(filename: str):
    loader = Loader(filename)
    if loader.is_elf():
        return PatcherELF(loader)
    elif loader.is_pe():
        return PatcherPE(loader)
    else:
        return None
