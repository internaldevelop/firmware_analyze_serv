import os
from .yaffs2 import *

from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath


class IMG_YAFFS(FsBase):
    def __init__(self, file_path):
        self.image = None
        # 加载 YAFFS 的镜像文件，如果非 YAFFS-fs 格式，则 image 为 None
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
        parse_yaffs(self.image)

        # 忽略目录文件
        # # Create directories first, so that files can be written to them
        # for (entry_id, file_path) in Compat.iterator(fs.file_paths):
        #     entry = fs.file_entries[entry_id]
        #     if file_path and int(entry.yaffs_obj_type) == fs.YAFFS_OBJECT_TYPE_DIRECTORY:
        #         # Check the file name for possible path traversal attacks
        #         if b'..' in file_path:
        #             sys.stderr.write(
        #                 "Warning: Refusing to create directory '%s': possible path traversal\n" % file_path)
        #             continue
        #
        #         try:
        #             file_path = os.path.join(outdir, file_path)
        #             os.makedirs(file_path)
        #             fs._set_mode_owner(file_path, entry)
        #             dir_count += 1
        #         except Exception as e:
        #             sys.stderr.write("WARNING: Failed to create directory '%s': %s\n" % (file_path, str(e)))

        # Create files, including special device files
        total_count = len(self.image.file_paths)
        index = 0

        for (entry_id, file_path) in Compat.iterator(self.image.file_paths):
            if file_path:
                # Check the file name for possible path traversal attacks
                if b'..' in file_path:
                    sys.stderr.write("Warning: Refusing to create file '%s': possible path traversal\n" % file_path)
                    continue

                # file_path = os.path.join(outdir, file_path)
                entry = self.image.file_entries[entry_id]

                if int(entry.yaffs_obj_type) == self.image.YAFFS_OBJECT_TYPE_FILE:
                    try:
                        index += 1
                        name = str(file_path, encoding="utf-8")
                        path = str(file_path, encoding="utf-8")
                        content = self.image.file_entries[entry_id].file_data

                        file_type, extra_props = IMG_YAFFS._file_type(name, entry.yst_mode, content)

                        # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
                        # 属性和数据内容交由 extract_func 回调函数处理
                        if extract_func is not None:
                            ret = extract_func(name, path, file_type, content, index, total_count,
                                               extra_props=extra_props)
                            if not ret:
                                return False
                    except Exception as e:
                        sys.stderr.write("WARNING: Failed to create file '%s': %s\n" % (file_path, str(e)))
                # elif int(entry.yaffs_obj_type) == self.image.YAFFS_OBJECT_TYPE_SPECIAL:
                #     try:
                #         os.mknod(file_path, entry.yst_mode, entry.yst_rdev)
                #         file_count += 1
                #     except Exception as e:
                #         sys.stderr.write("Failed to create special device file '%s': %s\n" % (file_path, str(e)))

        # 忽略链接文件
        # # Create hard/sym links
        # for (entry_id, file_path) in Compat.iterator(fs.file_paths):
        #     entry = fs.file_entries[entry_id]
        #
        #     if file_path:
        #         # Check the file name for possible path traversal attacks
        #         if b'..' in file_path:
        #             sys.stderr.write(
        #                 "Warning: Refusing to create link file '%s': possible path traversal\n" % file_path)
        #             continue
        #
        #         dst = os.path.join(outdir, file_path)
        #
        #         if int(entry.yaffs_obj_type) == fs.YAFFS_OBJECT_TYPE_SYMLINK:
        #             src = entry.alias
        #             try:
        #                 os.symlink(src, dst)
        #                 link_count += 1
        #             except Exception as e:
        #                 sys.stderr.write("WARNING: Failed to create symlink '%s' -> '%s': %s\n" % (dst, src, str(e)))
        #         elif int(entry.yaffs_obj_type) == fs.YAFFS_OBJECT_TYPE_HARDLINK:
        #             src = os.path.join(outdir, fs.file_paths[entry.equiv_id])
        #             try:
        #                 os.link(src, dst)
        #                 link_count += 1
        #             except Exception as e:
        #                 sys.stderr.write("WARNING: Failed to create hard link '%s' -> '%s': %s\n" % (dst, src, str(e)))

        return True

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            # 加载并解析镜像
            preserve_mode = None
            preserve_owner = None
            debug = None
            # fs = None

            # in_file = "testyaffs2.img"
            with open(file_path, 'rb') as fp:
                data = fp.read()

            # First 10K of data should be more than enough to detect the YAFFS settings
            config = YAFFSConfig(auto=True,
                                 sample_data=data[0:10240],
                                 preserve_mode=preserve_mode,
                                 preserve_owner=preserve_owner,
                                 debug=debug)

            # Try auto-detected / manual / default settings first.
            # If those work without errors, then assume they are correct.
            self.image = YAFFSExtractor(data, config)


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
