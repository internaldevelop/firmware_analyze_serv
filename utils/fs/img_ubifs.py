import os

from ubireader import settings
from ubireader.ubi import ubi
from ubireader.ubi.defines import UBI_EC_HDR_MAGIC
from ubireader.ubifs import ubifs
from ubireader.ubifs.output import extract_files
from ubireader.ubi_io import ubi_file, leb_virtual_file
from ubireader.utils import guess_filetype, guess_start_offset, guess_leb_size, guess_peb_size

from ubireader.ubifs.defines import *
from ubireader.ubifs import walk
from ubireader.ubifs.misc import decompress
from ubireader.debug import error, log, verbose_log

from utils.fs.fs_base import FsBase
from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath


class IMG_UBI(FsBase):
    def __init__(self, file_path):
        self.image = None
        self.filetype = None
        # 加载 squash-fs 的镜像文件，如果非 squash-fs 格式，则 image 为 None
        self.open(file_path)

    def list_all(self, exclude_folder=False, exclude_file=False):
        # 无效镜像，返回空列表
        if self.image is None:
            return []

        nodes = []
        # try:
        #     inodes = {}
        #     bad_blocks = []
        #
        #     walk.index(self.image, self.image.master_node.root_lnum, self.image.master_node.root_offs, inodes, bad_blocks)
        #     if len(inodes) < 2:
        #         raise Exception('No inodes found')
        #
        #     for dent in inodes[1]['dent']:
        #         nodes.append(dent.name)
        #         # IMG_UBI.extract_dents(ubifs, inodes, dent, "", False)
        #
        #     if len(bad_blocks):
        #         error(extract_files, 'Warning',
        #               'Data may be missing or corrupted, bad blocks, LEB [%s]' % ','.join(map(str, bad_blocks)))
        #
        # except Exception as e:
        #     # error(extract_files, 'Error', '%s' % e)
        #     print('extract_files %s' % e)

        return nodes

    def node_content(self, inode):
        # getFileContent 只能读取文件内容，不能读目录
        # return inode.getFileContent()

        # 读取节点内容（包括目录和文件）
        try:
            buf = b''
            if 'data' in inode:
                compr_type = 0
                sorted_data = sorted(inode['data'], key=lambda x: x.key['khash'])
                last_khash = sorted_data[0].key['khash'] - 1

                for data in sorted_data:

                    # If data nodes are missing in sequence, fill in blanks
                    # with \x00 * UBIFS_BLOCK_SIZE
                    if data.key['khash'] - last_khash != 1:
                        while 1 != (data.key['khash'] - last_khash):
                            buf += b'\x00' * UBIFS_BLOCK_SIZE
                            last_khash += 1

                    compr_type = data.compr_type
                    ubifs.file.seek(data.offset)
                    d = ubifs.file.read(data.compr_len)
                    buf += decompress(compr_type, data.size, d)
                    last_khash = data.key['khash']
                    # verbose_log(_process_reg_file,
                    #             'ino num: %s, compression: %s, path: %s' % (inode['ino'].key['ino_num'], compr_type, path))

        except Exception as e:
            print('_process_reg_file inode num:%s :%s' % (inode['ino'].key['ino_num'], e))

            # Pad end of file with \x00 if needed.
        if inode['ino'].size > len(buf):
            buf += b'\x00' * (inode['ino'].size - len(buf))

        return buf #inode.getContent()

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
        IMG_UBI.my_extract_files(self.image, extract_func)
        # nodes = self.list_all(exclude_folder=True)
        # for inode in nodes:
        #     name, path, folder = self.node_props(inode)
        #     content = self.node_content(inode)
        #
        #     file_type, extra_props = IMG_UBI._file_type(name, inode.inode.mode, content)
        #
        #     # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
        #     # 属性和数据内容交由 extract_func 回调函数处理
        #     if extract_func is not None:
        #         extract_func(name, path, file_type, content, extra_props=extra_props)

    def check_format(self):
        # 检测加载的镜像，是否为有效的 squash-fs 格式
        return self.image is not None

    def open(self, file_path):
        try:
            # 加载并解析镜像
            perms = False
            end_offset = None
            start_offset = 0

            filetype = guess_filetype(file_path, start_offset)
            if not filetype:
                print('Could not determine file type.')
            if filetype == UBI_EC_HDR_MAGIC:
                block_size = guess_peb_size(file_path)
            elif filetype == UBIFS_NODE_MAGIC:
                block_size = guess_leb_size(file_path)

            # Create file object.
            ufile_obj = ubi_file(file_path, block_size, start_offset, end_offset)
            self.filetype = filetype
            # outpath = "ubifs-root"
            if filetype == UBI_EC_HDR_MAGIC:
                # Create UBI object
                ubi_obj = ubi(ufile_obj)

                # Loop through found images in file.
                for image in ubi_obj.images:

                    # Create path for specific image
                    # In case multiple images in data
                    img_outpath = str(image.image_seq)

                    # Loop through volumes in each image.
                    for volume in image.volumes:

                        # Get blocks associated with this volume.
                        vol_blocks = image.volumes[volume].get_blocks(ubi_obj.blocks)

                        # Create volume data output path.
                        vol_outpath = os.path.join(img_outpath, volume)

                        # Create volume output path directory.
                        # create_output_dir(vol_outpath)

                        # Skip volume if empty.
                        if not len(vol_blocks):
                            continue

                        # Create LEB backed virtual file with volume blocks.
                        # Necessary to prevent having to load entire UBI image
                        # into memory.
                        lebv_file = leb_virtual_file(ubi_obj, vol_blocks)

                        # Extract files from UBI image.
                        ubifs_obj = ubifs(lebv_file)
                        print('Extracting files to: %s' % vol_outpath)
                        extract_files(ubifs_obj, vol_outpath, perms)


            elif filetype == UBIFS_NODE_MAGIC:
                # Create UBIFS object
                ubifs_obj = ubifs(ufile_obj)

                # Create directory for files.
                # create_output_dir(outpath)

                # Extract files from UBIFS image.
                # print('Extracting files to: %s' % outpath)
                # extract_files(ubifs_obj, outpath, perms)
                # my_extract_files(ubifs_obj)

            else:
                print('Something went wrong to get here.')

            self.image = ubifs_obj

        except OSError as e:
            # 格式错误时，镜像对象设置为无效
            self.image = None

    def close(self):
        if self.image is not None:
            # self.image.close()
            self.image = None
            self.filetype = None

    def __del__(self):
        self.close()

    @staticmethod
    def my_extract_files(ubifs, extract_func):
        try:
            inodes = {}
            bad_blocks = []

            walk.index(ubifs, ubifs.master_node.root_lnum, ubifs.master_node.root_offs, inodes, bad_blocks)
            if len(inodes) < 2:
                raise Exception('No inodes found')

            index = 0
            for dent in inodes[1]['dent']:
                index = IMG_UBI.extract_dents(ubifs, inodes, dent, index, "", False, extract_func)
                index += 1

            if len(bad_blocks):
                error(extract_files, 'Warning', 'Data may be missing or corrupted, bad blocks, LEB [%s]' % ','.join(map(str, bad_blocks)))

        except Exception as e:
            error(extract_files, 'Error', '%s' % e)

    @staticmethod
    def extract_dents(ubifs, inodes, dent_node, index, path='', perms=False, extract_func=None):
        if dent_node.inum not in inodes:
            # error(extract_dents, 'Error', 'inum: %s not found in inodes' % (dent_node.inum))
            return

        inode = inodes[dent_node.inum]
        dent_path = os.path.join(path, dent_node.name)
        total_count = len(inodes)
        if dent_node.type == UBIFS_ITYPE_DIR:
            if 'dent' in inode:
                for dnode in inode['dent']:
                    index = IMG_UBI.extract_dents(ubifs, inodes, dnode, index, dent_path, perms, extract_func)
                    index += 1

            # _set_file_timestamps(dent_path, inode)

        elif dent_node.type == UBIFS_ITYPE_REG:
            try:
                if inode['ino'].nlink > 1:
                    if 'hlink' not in inode:
                        inode['hlink'] = dent_path
                        content = IMG_UBI._process_reg_file(ubifs, inode, dent_path)
                        # _write_reg_file(dent_path, buf)
                    else:
                        os.link(inode['hlink'], dent_path)
                        # log(extract_dents, 'Make Link: %s > %s' % (dent_path, inode['hlink']))
                else:
                    content = IMG_UBI._process_reg_file(ubifs, inode, dent_path)
                    print(dent_path)
                    print(os.path.basename(dent_path))

                name = os.path.basename(dent_path)
                path = dent_path
                file_type, extra_props = IMG_UBI._file_type(name, inode['ino'].mode, content)

                # print(('EXEC_FILE({})' if file_type == 4 else 'NORMAL_FILE({})').format(inode.inode.mode))
                # 属性和数据内容交由 extract_func 回调函数处理
                if extract_func is not None:
                    extract_func(name, path, file_type, content, index, total_count, extra_props=extra_props)
                    print(index, total_count)

            except Exception as e:
                # error(extract_dents, 'Warn', 'FILE Fail: %s' % e)
                print('FILE Fail: %s' % e)

        elif dent_node.type == UBIFS_ITYPE_LNK:
            try:
                # probably will need to decompress ino data if > UBIFS_MIN_COMPR_LEN
                os.symlink('%s' % inode['ino'].data.decode('utf-8'), dent_path)
                # log(extract_dents, 'Make Symlink: %s > %s' % (dent_path, inode['ino'].data))

            except Exception as e:
                print('SYMLINK Fail: %s' % e)

        elif dent_node.type in [UBIFS_ITYPE_BLK, UBIFS_ITYPE_CHR]:
            try:
                dev = struct.unpack('<II', inode['ino'].data)[0]
                if True:
                    os.mknod(dent_path, inode['ino'].mode, dev)
                    # log(extract_dents, 'Make Device Node: %s' % (dent_path))
            except Exception as e:
                print('DEV Fail: %s' % e)

        elif dent_node.type == UBIFS_ITYPE_FIFO:
            try:
                os.mkfifo(dent_path, inode['ino'].mode)
                # log(extract_dents, 'Make FIFO: %s' % (path))


            except Exception as e:
                print('FIFO Fail: %s : %s' % (dent_path, e))

        elif dent_node.type == UBIFS_ITYPE_SOCK:
            try:
                if settings.use_dummy_socket_file:
                    print("pass")
                    # _write_reg_file(dent_path, '')
                    # if perms:
                    #     _set_file_perms(dent_path, inode)
            except Exception as e:
                print('SOCK Fail: %s : %s' % (dent_path, e))
        return index

    @staticmethod
    def _process_reg_file(ubifs, inode, path):
        try:
            buf = b''
            if 'data' in inode:
                compr_type = 0
                sorted_data = sorted(inode['data'], key=lambda x: x.key['khash'])
                last_khash = sorted_data[0].key['khash'] - 1

                for data in sorted_data:

                    # If data nodes are missing in sequence, fill in blanks
                    # with \x00 * UBIFS_BLOCK_SIZE
                    if data.key['khash'] - last_khash != 1:
                        while 1 != (data.key['khash'] - last_khash):
                            buf += b'\x00' * UBIFS_BLOCK_SIZE
                            last_khash += 1

                    compr_type = data.compr_type
                    ubifs.file.seek(data.offset)
                    d = ubifs.file.read(data.compr_len)
                    buf += decompress(compr_type, data.size, d)
                    last_khash = data.key['khash']
                    # verbose_log(_process_reg_file,
                    #             'ino num: %s, compression: %s, path: %s' % (inode['ino'].key['ino_num'], compr_type, path))

        except Exception as e:
            print('_process_reg_file inode num:%s :%s' % (inode['ino'].key['ino_num'], e))

        # Pad end of file with \x00 if needed.
        if inode['ino'].size > len(buf):
            buf += b'\x00' * (inode['ino'].size - len(buf))

        return buf
