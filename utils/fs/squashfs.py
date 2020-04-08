import os

from PySquashfsImage import SquashFsImage

from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_path import MyPath


class SquashFS(FsBase):
    """
    参考：# https://github.com/matteomattei/PySquashfsImage
    """
    def __init__(self, file_path):
        self.image = None
        # 加载 squash-fs 的镜像文件，如果非 squash-fs 格式，则 image 为 None
        self.open(file_path)

    def list_all(self, exclude_folder=False, exclude_file=False):
        # 无效镜像，返回空列表
        if self.image is None:
            return []

        nodes = []
        for inode in self.image.root.findAll():
            if len(inode.getName()) == 0:
                # 忽略根节点
                continue
            elif exclude_folder and inode.isFolder():
                # 排除目录时，忽略目录节点
                continue
            elif exclude_file and not inode.isFolder():
                # 排除文件时，忽略文件节点
                continue
            else:
                nodes.append(inode)
                # print(inode.getName())
                # print(inode.getPath())

        return nodes

    def node_content(self, inode):
        # getFileContent 只能读取文件内容，不能读目录
        # return inode.getFileContent()

        # 读取节点内容（包括目录和文件）
        return inode.getContent()

    def node_props(self, inode):
        # 获取节点名称，节点路径和目录属性
        return inode.getName(), inode.getPath(), inode.isFolder()

    @staticmethod
    def _is_normal_file(name):
        name_str = str(name, encoding="utf-8")
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

    @staticmethod
    def _file_type(name, mode, content, verify_exec=True):
        # 过滤文件类型
        if SquashFS._is_normal_file(name):
            return FileType.NORMAL_FILE, None

        # 需从 node 中提取文件属性，区分普通文件和可执行文件
        # mode: 33188 =100644 33261 = 100755
        if mode & 0o111:
            # 不做校验时，直接返回可执行文件类型，但没有 arch 等信息
            if not verify_exec:
                return FileType.EXEC_FILE, None

            # 疑似可执行文件，再结合 binwalk 和 angr project 检验是否为可执行文件
            file_path = SquashFS._temp_save_data_to_file(content)
            file_type, extra_data = FileTypeJudge.scan_file_type(file_path)
            if file_type == FileType.EXEC_FILE:
                arch, endianness = ExecFile.parse_exec_arch(file_path, prefer=extra_data)
                extra_data = {'arch': arch, 'endianness': endianness}
            else:
                extra_data = None

            return file_type, extra_data
        else:
            return FileType.NORMAL_FILE, None

    @staticmethod
    def _temp_save_data_to_file(data):
        file_name = 'squashfs_temp_file'
        file_path = os.path.join(MyPath.temporary(), file_name)
        with open(file_path, 'wb') as file:
            file.write(data)

        return file_path

    def extract_files(self, extract_func=None):
        # 导出文件内容，忽略目录，导出方式由 extract_func 来进行
        nodes = self.list_all(exclude_folder=True)
        for inode in nodes:
            name, path, folder = self.node_props(inode)
            content = self.node_content(inode)

            file_type, extra_data = SquashFS._file_type(name, inode.inode.mode, content)

            # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
            # 属性和数据内容交由 extract_func 回调函数处理
            if extract_func is not None:
                extract_func(name, path, file_type, content, extra_data=extra_data)

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            # 加载并解析镜像
            self.image = SquashFsImage(file_path)
        except OSError as e:
            # 格式错误时，镜像对象设置为无效
            self.image = None

    def close(self):
        # 操作完 SquashFS 实例后，一定要调用 close
        if self.image is not None:
            self.image.close()
            self.image = None

    def __del__(self):
        self.close()
