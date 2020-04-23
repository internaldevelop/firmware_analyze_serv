from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils

# import magic
import codecs


class FsBase(object):
    # ============================================================
    # 基类函数，定义继承类需包含的函数方法

    def __init__(self, file_path):
        pass

    def list_all(self, exclude_folder=False, exclude_file=False):
        pass

    def node_content(self, inode):
        pass

    def node_props(self, inode):
        pass

    def extract_files(self, extract_func=None):
        pass

    def check_format(self):
        pass

    def open(self, file_path):
        pass

    def close(self):
        pass

    # ============================================================
    # 通用函数，不需要继承类重载

    @staticmethod
    def is_normal_file(name_str):
        # name_str = str(name, encoding="utf-8")
        # 没有后缀的无法判断，直接返回 False
        if name_str.find('.') < 0:
            return False

        ext_list = ['.html', '.png', '.gif', '.js', '.css', '.php', '.svg', '.conf', '.key', '.pem', '.woff',
                    '.sh', '.swf', '.py']
        for ext_name in ext_list:
            start = 0 - len(ext_name)
            if name_str[start:] == ext_name:
                return True
        return False

    # 返回 FileType 和 extra_props = {'arch': arch, 'endianness': endianness}
    @staticmethod
    def verify_exec_bin_file(file_path, content=None):
        if file_path is None:
            if content is None:
                return FileType.OTHER_FILE, None
            file_path = MyFile.write('verify_exec_' + StrUtils.uuid_str(), content, folder=MyPath.temporary())

        # 疑似可执行文件，结合 binwalk 和 angr project 检验是否为可执行文件
        file_type, extra_props = FileTypeJudge.scan_file_type(file_path)
        if file_type == FileType.EXEC_FILE:
            arch, endianness = ExecFile.parse_exec_arch(file_path, prefer=extra_props)
            return file_type, {'arch': arch, 'endianness': endianness}

        return file_type, None

    @staticmethod
    def is_binary_file_1(file_content):
        '''
        根据text文件数据类型判断是否是二进制文件
        :param ff: 文件名（含路径）
        :return: True或False，返回是否是二进制文件
        '''
        TEXT_BOMS = (
            codecs.BOM_UTF16_BE,
            codecs.BOM_UTF16_LE,
            codecs.BOM_UTF32_BE,
            codecs.BOM_UTF32_LE,
            codecs.BOM_UTF8,
        )
        #: BOMs to indicate that a file is a text file even if it contains zero bytes.
        return not any(file_content.startswith(bom) for bom in TEXT_BOMS) and b'\0' in file_content

    @staticmethod
    def is_binwary_file_2(file_content):
        # '''
        # 根据magic文件的魔术判断是否是二进制文件
        # :param ff: 文件名（含路径）
        # :return: True或False，返回是否是二进制文件
        # '''
        # mime_kw = 'x-executable|x-sharedlib|octet-stream|x-object'  ###可执行文件、链接库、动态流、对象
        # try:
        #     magic_mime = magic.from_file(ff, mime=True)
        #     magic_hit = re.search(mime_kw, magic_mime, re.I)
        #     if magic_hit:
        #         return True
        #     else:
        #         return False
        # except Exception, e:
        #     return False
        pass

    # 判断文件是否是elf文件
    @staticmethod
    def is_ELFfile(file_content):
        # if not os.path.exists(filepath):
        #     logger.info('file path {} doesnot exits'.format(filepath))
        #     return False
        # # 文件可能被损坏，捕捉异常
        try:
            # FileStates = os.stat(filepath)
            # FileMode = FileStates[stat.ST_MODE]
            # if not stat.S_ISREG(FileMode) or stat.S_ISLNK(FileMode):  # 如果文件既不是普通文件也不是链接文件
            #     return False
            header = (bytearray(file_content)[1:4]).decode(encoding="utf-8")
            # logger.info("header is {}".format(header))
            if header in ["ELF"]:
                # print header
                return True
        except UnicodeDecodeError as e:
            # logger.info("is_ELFfile UnicodeDecodeError {}".format(filepath))
            # logger.info(str(e))
            pass

        return False

