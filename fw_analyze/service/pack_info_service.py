from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.pack_file import PackFileDO


class PackInfoService:
    def __init__(self, pack_id, pack_info=None):
        self.pack_id = pack_id
        if pack_info is None:
            pack_info = PackFileDO.fetch_pack(pack_id)
        self.pack_info = pack_info

    """ 获取固件包解包后所有的文件统计信息 """
    def get_unpack_files_stat(self):
        pack_id = self.pack_id
        file_type_list = FileType.value_list()

        unpack_files = {}
        for file_type in file_type_list:
            # 不统计固件包的文件数量
            if file_type == FileType.PACK:
                continue

            # 获取文件类型的别名
            alias = FileType.get_alias(file_type)

            # 统计指定类型文件的数量
            count = FwFileDO.count_files(pack_id, file_type)
            unpack_files[str(file_type)] = {'alias': alias, 'count': count}

        fw_files = {
            'unpack_files': unpack_files
        }
        return fw_files

    """ 获取固件包的任务运行信息 """
    def get_task_info(self):
        # TODO: 待任务设计完成后，再填充任务信息
        task_info = {
            'task_info': '待任务设计完成后，再填充任务信息'
        }
        return task_info

    """ 获取固件包的所有概要信息 """
    def pack_summary(self):
        # 解包文件统计数据
        unpack_files_stat = self.get_unpack_files_stat()
        self.pack_info = dict(self.pack_info, **unpack_files_stat)

        # 任务信息
        task_info = self.get_task_info()
        self.pack_info = dict(self.pack_info, **task_info)

        return self.pack_info
