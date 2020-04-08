

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
    # 固件二进制文件
    FW_BIN = 7

    # =========================================================
    # 对 FS_IMAGE 提取出来的文件做文件类型细分，不能识别的文件设置成 NORMAL_FILE 或 OTHER_FILE
    WORD_FILE = 101
    EXCEL_FILE = 102
    PPT_FILE = 103
    OTHER_OFFICE_FILE = 104

    PDF_FILE = 120

    PNG_FILE = 130
    BMP_FILE = 131
    JPG_FILE = 132
    TIFF_FILE = 133
    GIF_FILE = 134

    # =========================================================
    # 其他类型文件，比如未知文件，或不关心类型的文件
    OTHER_FILE = 9999

    @staticmethod
    def get_alias(file_type):
        alias_list = {
            str(FileType.PACK): '固件包文件',
            str(FileType.SYS_IMAGE): '系统镜像',
            str(FileType.FS_IMAGE): '文件系统镜像',
            str(FileType.EXEC_FILE): '可执行文件',
            str(FileType.NORMAL_FILE): '普通文件',
            str(FileType.ZIP_FILE): '压缩文件',
            str(FileType.FW_BIN): '固件二进制文件',

            str(FileType.WORD_FILE): 'WORD文件',
            str(FileType.EXCEL_FILE): 'EXCEL文件',
            str(FileType.PPT_FILE): 'PPT文件',
            str(FileType.OTHER_OFFICE_FILE): 'Office文件',

            str(FileType.PDF_FILE): 'PDF文件',

            str(FileType.PNG_FILE): 'PNG文件',
            str(FileType.BMP_FILE): 'BMP文件',
            str(FileType.JPG_FILE): 'JPEG文件',
            str(FileType.TIFF_FILE): 'TIFF文件',
            str(FileType.GIF_FILE): 'GIF文件',

            str(FileType.OTHER_FILE): '其他类型文件',
        }
        return alias_list[str(file_type)]

    # TODO: 需补充
    @staticmethod
    def name_list():
        return ['PACK', 'SYS_IMAGE', 'FS_IMAGE', 'EXEC_FILE', 'NORMAL_FILE', 'ZIP_FILE', 'OTHER_FILE', ]

    # TODO: 需补充
    @staticmethod
    def value_list():
        return [FileType.PACK, FileType.SYS_IMAGE, FileType.FS_IMAGE, FileType.EXEC_FILE, FileType.NORMAL_FILE,
                FileType.ZIP_FILE, FileType.OTHER_FILE, ]

    # def
