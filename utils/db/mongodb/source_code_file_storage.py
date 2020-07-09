import os

from gridfs import GridFS

import utils.sys.config

from utils.gadget.general import SysUtils

# 解包出来的文件 内容集合（存储桶）
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath

# 组件源码文件存储桶集合
source_code_files_storage = GridFS(utils.sys.config.g_firmware_db_full, collection='source_code_files_storage')


class SourceCodeFilesStorage:
    @staticmethod
    def save(file_id, file_name, file_path, content_type, contents):
        # 更新文件内容到 GridFS 存储桶中
        source_code_files_storage.put(contents, content_type=content_type, filename=file_id,
                             aliases=[file_name, file_path])
        # fw_files_storage.put(content.encode(encoding="utf-8"), content_type=content_type, filename=file_id,
        #                      aliases=[file_name, file_path])

    @staticmethod
    def fetch(file_id):
        grid_out = source_code_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        return item

    @staticmethod
    def export(file_id, file_name=None, folder=None, override=False):
        # 在存储桶中读取文件记录
        grid_out = source_code_files_storage.find_one({'filename': file_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        if item is None:
            return None

        # 设置文件路径，默认文件导出到临时目录
        if file_name is None:
            file_name = item['filename']
        if folder is None:
            folder = MyPath.temporary()
        SysUtils.check_filepath(folder)

        file_path = os.path.join(folder, file_name)

        # 不设置覆写时，如果文件已存在，则跳过文件创建和写数据的操作
        if not override and MyFile.exist(file_path):
            return file_path

        # 读取文件数据
        data = grid_out.read()
        # 创建文件并写入数据
        with open(file_path, 'wb') as file:
            file.write(data)

        return file_path

    @staticmethod
    def delete(file_id):
        file_item = source_code_files_storage.find_one({'filename': file_id})
        if file_item is None:
            return False
            source_code_files_storage.delete(file_item._id)
        return True

    @staticmethod
    def delete_many(file_id_list):
        for file_id in file_id_list:
            SourceCodeFilesStorage.delete(file_id)

    @staticmethod
    def update_content_type(file_id, content_type):
        # 没有找到单一更新的方式，暂时不考虑的存储桶的仅更新
        file_item = SourceCodeFilesStorage.fetch(file_id)
        if file_item is None:
            return False
        return False

