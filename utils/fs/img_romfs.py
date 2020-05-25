import os

from PyRomfsImage.PyRomfsImage import Romfs

from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath


class IMG_RomFS(FsBase):
    def __init__(self, file_path):
        self.image = None
        # 加载 squash-fs 的镜像文件，如果非 squash-fs 格式，则 image 为 None
        self.open(file_path)

    def list_all(self, exclude_folder=False, exclude_file=False):
        # 无效镜像，返回空列表
        if self.image is None:
            return []

        nodes = []
        for inode in self.image.getRoot().findAll():
            nodes.append(inode)
            # if len(inode.getName()) == 0:
            #     # 忽略根节点
            #     continue
            # elif exclude_folder and inode.isFolder():
            #     # 排除目录时，忽略目录节点
            #     continue
            # elif exclude_file and not inode.isFolder():
            #     # 排除文件时，忽略文件节点
            #     continue
            # else:
            #     nodes.append(inode)
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
    def _file_type(name, mode, content, verify_exec=False):
        # 过滤文件类型
        if FsBase.is_normal_file(name):
            return FileType.NORMAL_FILE, None

        # 需从 node 中提取文件属性，区分普通文件和可执行文件
        # mode: 33188 =100644 33261 = 100755
        if mode & 0o111:
            # 不做校验时，直接返回可执行文件类型，但没有 arch 等信息
            if not verify_exec:
                return FileType.EXEC_FILE, None
            else:
                # return FsBase.verify_exec_bin_file(None, content=content)
                if any((FsBase.is_binary_file_1(content), FsBase.is_binwary_file_2(content), FsBase.is_ELFfile(content))):
                    return FileType.EXEC_FILE, None
                else:
                    return FileType.NORMAL_FILE, None
        else:
            return FileType.NORMAL_FILE, None

    def extract_files(self, extract_func=None):
        # 导出文件内容，忽略目录，导出方式由 extract_func 来进行
        # nodes = self.list_all(exclude_folder=True)
        root = self.image.getRoot()
        index = 0
        for inode in root.findAll():
            index += 1
            content = root.read(inode)
            inode_dir = str(inode).replace("b'", '')
            name = os.path.basename(inode_dir).replace("'", '')
            path = inode_dir.replace("'", '')
            mode = 0o111

            file_type, extra_props = IMG_RomFS._file_type(name, mode, content, True)

            # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
            # 属性和数据内容交由 extract_func 回调函数处理
            if extract_func is not None:
                total_count = len(root.findAll())
                extract_func(name, path, file_type, content, index, total_count, extra_props=extra_props)
        # 全部处理完毕后，返回 True 表示正常处理完成。
        return True

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            # 加载并解析镜像
            self.image = Romfs()
            self.image.open(file_path)
        except OSError as e:
            # 格式错误时，镜像对象设置为无效
            self.image = None

    def close(self):
        # 操作完 SquashFS 实例后，一定要调用 close
        if self.image is not None:
            # self.image.close()
            self.image = None

    def __del__(self):
        self.close()