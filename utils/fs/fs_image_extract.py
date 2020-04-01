from utils.db.mongodb.fw_file import FwFile
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.squashfs import SquashFS
from utils.gadget.strutil import StrUtils


class FsImageExtract:
    def __init__(self, image_file_id):
        self.image_file_id = image_file_id
        self.image_file_path, fs_arch = FwFile.id_to_file(image_file_id)

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
        FwFile.save_file_item(self.image_file_id, file_id, name, path, folder)
        FwFilesStorage.save(file_id, name, path, 'Unknown', content)

