import enum


class FileType(enum.Enum):
    # 原始包
    PACK = 1
    # 系统镜像文件
    SYS_IMAGE = 2
    # FS 文件系统镜像文件
    FS_IMAGE = 3
    # 可执行文件
    EXEC_FILE = 4
    # 普通文件
    NORMAL_FILE = 5
    # 压缩文件
    ZIP_FLE = 6
    # 其他类型文件，比如未知文件，或不关心类型的文件
    OTHER_FILE = 7
