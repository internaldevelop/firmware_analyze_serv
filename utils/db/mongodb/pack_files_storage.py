import utils.sys.config
from utils.gadget.general import SysUtils
from utils.sys.file_source import FileSource
from utils.sys.file_type import FileType
from utils.sys.pack_type import PackType


# 解包出来的文件 信息集合
pack_files_storage = utils.sys.config.g_pack_files_storage


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
