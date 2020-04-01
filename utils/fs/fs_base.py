

# 基类函数，定义继承类需包含的函数方法
class FsBase(object):
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

