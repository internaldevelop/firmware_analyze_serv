

class FileType:
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
    ZIP_FILE = 6
    # 其他类型文件，比如未知文件，或不关心类型的文件
    OTHER_FILE = 7

    @staticmethod
    def get_alias(file_type):
        alias_list = {
            str(FileType.PACK): '固件包文件',
            str(FileType.SYS_IMAGE): '系统镜像',
            str(FileType.FS_IMAGE): '文件系统镜像',
            str(FileType.EXEC_FILE): '可执行文件',
            str(FileType.NORMAL_FILE): '普通文件',
            str(FileType.ZIP_FILE): '压缩文件',
            str(FileType.OTHER_FILE): '其他类型文件',
        }
        return alias_list[str(file_type)]

    @staticmethod
    def name_list():
        return ['PACK', 'SYS_IMAGE', 'FS_IMAGE', 'EXEC_FILE', 'NORMAL_FILE', 'ZIP_FILE', 'OTHER_FILE', ]

    @staticmethod
    def value_list():
        return [FileType.PACK, FileType.SYS_IMAGE, FileType.FS_IMAGE, FileType.EXEC_FILE, FileType.NORMAL_FILE,
                FileType.ZIP_FILE, FileType.OTHER_FILE, ]

    # def
