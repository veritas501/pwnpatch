from typing import Union

from pwnpatch.factory import PatcherFactory
from pwnpatch import patcher

VERSION = "v1.0.1"


def get_patcher(
    filename: str, minimal_edit=False
) -> Union[patcher.ElfPatcher, patcher.PePatcher]:
    """get patcher object

    Args:
        filename (str): filename to patch
        minimal_edit (bool, optional): enable minimal edit mode. Defaults to False.

    Returns:
        patcher class
    """
    return PatcherFactory.get_patcher(filename, minimal_edit)
