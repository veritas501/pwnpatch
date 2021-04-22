"""
用于存放用到的enums
"""
from enum import Enum


class Endian(Enum):
    NONE = 0
    LSB = 1
    MSB = 2


class Arch(Enum):
    NONE = 0
    I386 = 1
    AMD64 = 2
    ARM = 3
    ARM64 = 4
    MIPS = 5


class EXE(Enum):
    NONE = 0
    ELF = 1
    PE = 2
