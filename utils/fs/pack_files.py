from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.fs_base import FsBase
from utils.task.my_task import MyTask
from utils.task.task_type import TaskType


class PackFiles:
    def __init__(self, pack_id):
        self.pack_id = pack_id

    @staticmethod
    def start_exec_bin_verify_task(pack_id):
        pack_files = PackFiles(pack_id)
        extra_info = {'pack_id': pack_id, 'task_type': TaskType.VERIFY_EXEC_BIN,
                      'task_name': '验证二进制文件',
                      'task_desc': '验证固件包中所有的可执行二进制文件，并检查CPU架构。'}
        task = MyTask(pack_files.verify_all_exec_bin_files, (pack_id,), extra_info=extra_info)
        return task.get_task_id()

    def _save_task_percentage(self, task_id, count, total):
        percent = count * 100.0 / total
        MyTask.save_task_percentage(task_id, percent, min_step=3.0)

    def verify_all_exec_bin_files(self, pack_id, task_id):
        # 获取本固件包所有的二进制可执行文件记录
        bin_files_list = FwFileDO.search_files_of_pack(pack_id, FileType.EXEC_FILE)

        # 枚举每个文件，读出其文件数据，校验
        total_count = len(bin_files_list)
        for index, file_item in enumerate(bin_files_list):
            # 检查任务状态
            if MyTask.is_task_stopped(task_id):
                break

            # 保存任务执行百分比
            self._save_task_percentage(task_id, index, total_count)

            # 注意：此处一定要设置覆写，否则判定的是旧文件数据，造成判定结果错误
            file_path = FwFilesStorage.export(file_item['file_id'], file_name=task_id, override=True)
            file_type, extra_props = FsBase.verify_exec_bin_file(file_path)

            # 修改文件的类型属性，或增加可执行二进制文件的CPU架构
            # 暂时不更新存储桶中的“内容类型”
            FwFileDO.update_verified_file_type(file_item['file_id'], file_type, extra_props=extra_props)

        # 保存任务完成状态
        MyTask.save_exec_info(task_id, 100.0)
