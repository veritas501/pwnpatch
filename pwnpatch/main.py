from typing import Union

from pwnpatch.factory import PatcherFactory
from pwnpatch.patcher import *

VERSION = "v1.0"


def get_patcher(filename: str) -> Union[ElfPatcher, PePatcher]:
    return PatcherFactory.get_patcher(filename)
