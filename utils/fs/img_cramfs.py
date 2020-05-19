import os
import subprocess

from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath


class IMG_CramFS(FsBase):
    """
    """
    def __init__(self, file_path):
        self.image = None
        self.file_extract_dir = None  #CRAMFS解压缩根目录
        # 加载 cram-fs 的镜像文件，如果非 cram-fs 格式，则 image 为 None
        self.open(file_path)

    def list_all(self, exclude_folder=False, exclude_file=False):
        # 无效镜像，返回空列表
        # if self.image is None:
        #     return []

        nodes = []
        # itotal_files = 0
        for root, dirs, files in os.walk(self.file_extract_dir):
            # root 表示当前正在访问的文件夹路径
            # dirs 表示该文件夹下的子目录名list
            # files 表示该文件夹下的文件list
            # 遍历文件
            for f in files:
                # itotal_files += 1
                print(os.path.join(root, f))
                nodes.append(os.path.join(root, f))

            # 遍历所有的文件夹
            for d in dirs:
                print(os.path.join(root, d))

        return nodes

    def node_content(self, inode):
        # getFileContent 只能读取文件内容，不能读目录
        # return inode.getFileContent()
        contents = MyFile.read(inode)

        # 读取节点内容（包括目录和文件）
        return contents

    def node_props(self, inode):
        # 获取节点名称，节点路径和目录属性
        path, name = os.path.split(inode)
        isfolder = os.path.isdir(inode)
        return name, path, isfolder

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
                return FsBase.verify_exec_bin_file(None, content=content)
        else:
            return FileType.NORMAL_FILE, None

    def extract_files(self, extract_func=None):
        # 导出文件内容，忽略目录，导出方式由 extract_func 来进行
        nodes = self.list_all(exclude_folder=True)
        total_count = len(nodes)
        mode = 0o111

        for index, inode in enumerate(nodes):
            name, path, folder = self.node_props(inode)
            content = self.node_content(inode)

            file_type, extra_props = IMG_CramFS._file_type(name, mode, content, True)

            # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
            # 属性和数据内容交由 extract_func 回调函数处理
            if extract_func is not None:
                ret = extract_func(name, path, file_type, content, index, total_count, extra_props=extra_props)
                if not ret:
                    return False
        # 全部处理完毕后，返回 True 表示正常处理完成。
        return True

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            folder = MyPath.temporary()
            self.file_extract_dir = os.path.join(folder, "cramfs")
            print(self.file_extract_dir)

            # cramfsck only for linux
            cmds = "cramfsck -x " + self.file_extract_dir + " " + file_path
            print(cmds)
            ret = subprocess.call(cmds, shell=True)

        except OSError as e:
            # 格式错误时，镜像对象设置为无效
            self.image = None
            print("cramfsck error", e)

    def close(self):
        # 操作完 SquashFS 实例后，一定要调用 close
        if self.image is not None:
            self.image.close()
            self.image = None

    def __del__(self):
        self.close()
