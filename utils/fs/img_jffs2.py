import os
# from PySquashfsImage import SquashFsImage

# from jefferson import jffs2_lzma, rtime
from .jffs2 import JFFS2
from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath

JFFS2_NODETYPE_DIRENT = 0xE001
JFFS2_NODETYPE_INODE = 0xE002

DT_DIR = 4
DT_REG = 8

JFFS2_COMPR_NONE = 0x00
JFFS2_COMPR_ZERO = 0x01
JFFS2_COMPR_RTIME = 0x02
JFFS2_COMPR_RUBINMIPS = 0x03
JFFS2_COMPR_COPY = 0x04
JFFS2_COMPR_DYNRUBIN = 0x05
JFFS2_COMPR_ZLIB = 0x06
JFFS2_COMPR_LZO = 0x07


class IMG_JFFS2(FsBase):
    """
    参考：# https://github.com/luizluca/jffs2
    """
    def __init__(self, file_path):
        self.image = None
        # 加载JFFS2镜像文件，如果非 JFFS2 格式，则 image 为 None
        self.open(file_path)

    def list_all(self, exclude_folder=False, exclude_file=False):
        # 无效镜像，返回空列表
        if self.image is None:
            return []

        nodes = []
        for inode in self.image.inodes:
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
            #     # print(inode.getName())
            #     # print(inode.getPath())

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
        self.image.scan()
        total_count = len(self.image.dirents)

        for index in self.image.dirents:
            dirent = self.image.dirents[index]
            name, ntype = self.image.resolve_dirent(index)
            # mode = self.image.fd.mode
            mode = 0o111

            if ntype == DT_REG:
                # image.dump_file(os.path.join(target, name), i)
                content = self.image.get_file_content(name, index)
                file_type, extra_props = IMG_JFFS2._file_type(name, mode, content, True)

                # 属性和数据内容交由 extract_func 回调函数处理
                if extract_func is not None:
                    path = os.path.splitext(name)
                    ret = extract_func(name, path, file_type, content, index, total_count, extra_props=extra_props)
                    if not ret:
                        return False
            # elif ntype == DT_DIR:
            #     try:
            #         # mkdir_p(os.path.join(target, name))
            #         print("mkdir")
            #     except OSError as e:
            #         print(e)

        # 全部处理完毕后，返回 True 表示正常处理完成。
        return True

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            # 加载并解析镜像
            self.image = JFFS2(file_path)

        except OSError as e:
            print(e)
            # 格式错误时，镜像对象设置为无效
            self.image = None

    def close(self):
        # 操作完 SquashFS 实例后，一定要调用 close
        if self.image is not None:
            # self.image.close()
            self.image = None

    def __del__(self):
        self.close()



