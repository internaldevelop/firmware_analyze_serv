import os
import utils.sys.config

from utils.gadget.general import SysUtils

# 解包出来的文件 内容集合（存储桶）
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath

fw_files_storage = utils.sys.config.g_fw_files_storage


class FwFilesStorage:
    @staticmethod
    def save(file_id, file_name, file_path, content_type, contents):
        # 更新文件内容到 GridFS 存储桶中
        fw_files_storage.put(contents, content_type=content_type, filename=file_id,
                             aliases=[file_name, file_path])
        # fw_files_storage.put(content.encode(encoding="utf-8"), content_type=content_type, filename=file_id,
        #                      aliases=[file_name, file_path])

    @staticmethod
    def fetch(file_id):
        grid_out = fw_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        return item

    @staticmethod
    def export(file_id):
        # 在存储桶中读取文件记录
        grid_out = fw_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        if item is None:
            return None

        # 文件导出到临时目录
        folder_path = MyPath.temporary()
        file_path = os.path.join(folder_path, item['filename'])

        # 如果文件已存在，则跳过文件创建和写数据的操作
        if MyFile.exist(file_path):
            return file_path

        # 读取文件数据
        data = grid_out.read()
        # 创建文件并写入数据
        with open(file_path, 'wb') as file:
            file.write(data)

        return file_path

    @staticmethod
    def delete(file_id):
        file_item = fw_files_storage.find_one({'filename': file_id})
        if file_item is None:
            return False
        fw_files_storage.delete(file_item._id)
        return True

    @staticmethod
    def delete_many(file_id_list):
        for file_id in file_id_list:
            FwFilesStorage.delete(file_id)

