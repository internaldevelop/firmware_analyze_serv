from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils


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



