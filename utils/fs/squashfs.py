from PySquashfsImage import SquashFsImage

from utils.fs.fs_base import FsBase


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

    def extract_files(self, extract_func=None):
        # 导出文件内容，忽略目录，导出方式由 extract_func 来进行
        if extract_func is None:
            return

        # 忽略目录
        nodes = self.list_all(exclude_folder=True)
        for inode in nodes:
            name, path, folder = self.node_props(inode)
            content = self.node_content(inode)
            # 属性和数据内容交由 extract_func 回调函数处理
            extract_func(name, path, content)

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
