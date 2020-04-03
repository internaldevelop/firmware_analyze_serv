from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.squashfs import SquashFS
from utils.gadget.strutil import StrUtils
from utils.const.file_type import FileType
import os


class FsImage:
    def __init__(self, pack_id):
        self.pack_id = pack_id
        self.image = None

        # 查找指定包的 FS 镜像文件
        file_docs = FwFileDO.search_files_of_pack(pack_id, FileType.FS_IMAGE)
        if len(file_docs) == 0:
            return
        # 只取第一个镜像文件
        image_file = file_docs[0]

        # 导出镜像文件到临时目录
        root_path = os.getcwd()
        temp_folder = os.path.join(root_path, 'files', 'temporary')
        self.image_file_path = FwFilesStorage.export(image_file['file_id'], temp_folder)

        # 尝试 SquashFS 解析，并验证
        self.image = SquashFS(self.image_file_path)
        if self.image.check_format():
            pass

    def extract(self):
        if self.image is None:
            return
        self.image.extract_files(extract_func=self.save_proc)

    def save_proc(self, name, path, file_type, content):
        name = str(name)
        file_id = StrUtils.uuid_str()

        # 保存文件参数
        FwFileDO.save_file_item(self.pack_id, file_id, name, file_type, file_path=path)
        # 保存文件内容
        FwFilesStorage.save(file_id, name, path, file_type, content)

    def enum_files(self):
        if self.image is None:
            return
        self.image.extract_files()

