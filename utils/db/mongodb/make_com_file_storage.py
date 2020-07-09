from gridfs import GridFS

import utils.sys.config
from utils.gadget.general import SysUtils

# 组件编译生成后的文件存储桶集合
make_com_files_storage = GridFS(utils.sys.config.g_firmware_db_full, collection='component_make_files_storage')


class MakeCOMFilesStorage:
    @staticmethod
    def save(file_id, file_name, file_path, content_type, contents):
        # 更新文件内容到 GridFS 存储桶中
        make_com_files_storage.put(contents, content_type=content_type, filename=file_id,
                             aliases=[file_name, file_path])
        # fw_files_storage.put(content.encode(encoding="utf-8"), content_type=content_type, filename=file_id,
        #                      aliases=[file_name, file_path])

    @staticmethod
    def fetch(file_id):
        grid_out = make_com_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        return item

    @staticmethod
    def delete(file_id):
        file_item = make_com_files_storage.find_one({'filename': file_id})
        if file_item is None:
            return False
        make_com_files_storage.delete(file_item._id)
        return True

    @staticmethod
    def delete_many(file_id_list):
        for file_id in file_id_list:
            MakeCOMFilesStorage.delete(file_id)
