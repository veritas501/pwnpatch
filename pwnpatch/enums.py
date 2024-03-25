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


class BitSize(Enum):
    NONE = 0
    X32 = 32
    X64 = 64


class EXE(Enum):
    NONE = 0
    ELF = 1
    PE = 2


class SegProt(Enum):
    NONE = 0
    X = 1
    W = 2
    R = 4
    RWX = 7
    RX = 5
    RW = 6
    WX = 3
