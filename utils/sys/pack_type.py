import enum


class PackType(enum.Enum):
    # 实体包，有原始包文件
    REAL = 1
    # 虚拟包，没有包文件
    VIRTUAL = 2
