from utils.db.mongodb.fw_file import FwFile
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.squashfs import SquashFS
from utils.gadget.strutil import StrUtils


class FsImage:
    def __init__(self, pack_file_id):
        self.image_file_id = pack_file_id
        self.image_file_path, fs_arch = FwFile.id_to_file(pack_file_id)

        # 尝试 SquashFS 解析，并验证
        self.image = SquashFS(self.image_file_path)
        if self.image.check_format():
            pass

    def extract(self):
        if self.image is None:
            return
        self.image.extract_files(self.save)

    def save(self, name, path, folder, content):
        name = str(name)
        file_id = StrUtils.uuid_str()
        # 保存文件参数
        FwFile.save_file_item(self.image_file_id, file_id, name, path=path)
        # 保存文件内容
        FwFilesStorage.save(file_id, name, path, 'Unknown', content)

