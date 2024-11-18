class UnsupportedBinaryException(Exception):
    """
    不支持此格式的二进制
    """

    pass


class TODOException(Exception):
    """
    还不支持这个功能
    """

    pass


class PatchException(Exception):
    """
    Patch的报错
    """

    pass


class AddException(Exception):
    """
    Add的报错
    """

    pass


class SccException(Exception):
    """
    调用scc工具时发生的异常
    """

    pass
