import os
import utils.sys.config

from utils.gadget.general import SysUtils

# 解包出来的文件 内容集合（存储桶）
fw_files_storage = utils.sys.config.g_fw_files_storage


class FwFilesStorage:
    @staticmethod
    def save(file_id, file_name, file_path, content_type, content):
        # 更新POC到 GridFS 存储桶中
        fw_files_storage.put(content, content_type=content_type, filename=file_id,
                             aliases=[file_name, file_path])
        # fw_files_storage.put(content.encode(encoding="utf-8"), content_type=content_type, filename=file_id,
        #                      aliases=[file_name, file_path])

    @staticmethod
    def fetch(file_id):
        grid_out = fw_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        return item

