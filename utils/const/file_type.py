
class FileSystemType:
    # 固件文件系统类型
    SQUASHFS = 1
    JFFS2 = 2
    ROMFS = 3
    UBIFS = 4
    YAFFS = 5
    CRAMFS = 6



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

    # 组件源码生成文件
    MAKE_FILE = 8

    # =========================================================
    # 对 FS_IMAGE 提取出来的文件做文件类型细分，不能识别的文件设置成 NORMAL_FILE 或 OTHER_FILE
    WORD_FILE = 101
    EXCEL_FILE = 102
    PPT_FILE = 103
    OTHER_OFFICE_FILE = 104

    PDF_FILE = 120
    RAR_FILE = 121
    Z7Z_FILE = 122
    TAR_FILE = 123
    SH_SCRIPT = 124

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
            str(FileType.RAR_FILE): 'RAR文件',
            str(FileType.Z7Z_FILE): '7Z文件',
            str(FileType.TAR_FILE): 'TAR文件',
            str(FileType.SH_SCRIPT): 'shell脚本',

            str(FileType.PNG_FILE): 'PNG文件',
            str(FileType.BMP_FILE): 'BMP文件',
            str(FileType.JPG_FILE): 'JPEG文件',
            str(FileType.TIFF_FILE): 'TIFF文件',
            str(FileType.GIF_FILE): 'GIF文件',

            str(FileType.OTHER_FILE): '其他类型文件',
        }
        return alias_list[str(file_type)]

    @staticmethod
    def names_list():
        # 也可以采用 vars(FileType) 获得所有的函数、变量的 mappingproxy，再用dict转成字典
        props_list = dir(FileType)
        results = []
        for prop in props_list:
            if prop.isupper():
                results.append(prop)
        return results

    @staticmethod
    def values_list():
        ftypes_list = FileType.names_list()
        results = [eval('FileType.' + key) for key in ftypes_list]
        return results

    @staticmethod
    def kv_list():
        names = FileType.names_list()
        values = FileType.values_list()
        results = dict(zip(names, values))
        # results = [{key: eval('FileType.' + key)} for key in names]
        return results


class CompileStatus:
    # 未编译原始包
    none = 0
    # 编译成功
    success = 1
    # 编译失败
    failed = 99
