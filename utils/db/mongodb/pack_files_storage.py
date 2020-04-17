from gridfs import GridFS

import utils.sys.config
from utils.gadget.general import SysUtils

# 固件包存储桶集合
pack_files_storage = GridFS(utils.sys.config.g_firmware_db_full, collection='pack_files_storage')


class PackFilesStorage:
    @staticmethod
    def save(file_id, file_name, file_type, contents):
        # 更新包文件内容到 GridFS 存储桶中
        pack_files_storage.put(contents, content_type=file_type, filename=file_id, aliases=[file_name])

    @staticmethod
    def fetch(file_id):
        grid_out = pack_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        return item

    @staticmethod
    def delete(file_id):
        file_item = pack_files_storage.find_one({'filename': file_id})
        if file_item is None:
            return False
        pack_files_storage.delete(file_item._id)
        return True

    @staticmethod
    def delete_many(file_id_list):
        for file_id in file_id_list:
            PackFilesStorage.delete(file_id)
