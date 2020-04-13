import os
import time

from utils.const.file_type import FileType
from utils.const.pack_type import PackType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.tasks_dao import TasksDAO
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.task.my_task import MyTask
from utils.task.task_status import TaskStatus
from utils.task.task_type import TaskType


class PackProcessService:
    """ 添加单个可执行文件，会产生一个虚拟固件包（没有包文件），用于该文件有可关联的固件包 """
    @staticmethod
    def add_single_exec(file_name, file_data):
        # 新的 pack ID
        pack_id = StrUtils.uuid_str()
        # 保存虚拟包记录
        PackFileDO.save(pack_id, '', name=file_name, pack_type=PackType.VIRTUAL, file_type=FileType.PACK)

        # 新的 pack 文件 UUID
        exec_file_id = StrUtils.uuid_str()
        # 保存文件记录
        FwFileDO.save_file_item(pack_id, exec_file_id, file_name, FileType.EXEC_FILE)

        # 在存储桶中保存文件数据
        # 保存文件内容
        FwFilesStorage.save(exec_file_id, file_name, file_name, FileType.EXEC_FILE, file_data)

        return pack_id, exec_file_id

    """ 移除固件包 """
    def remove_pack(self, pack_id, task_id):
        # 获取该固件包关联的所有文件 ID
        files_list = FwFileDO.get_files_of_pack(pack_id)
        file_id_list = [file_item['file_id'] for file_item in files_list]

        # 第一步，总进度条的 0-80%
        # 移除存储桶中，该固件包关联的所有文件
        total_count = len(file_id_list)
        for index, file_id in enumerate(file_id_list):
            if MyTask.is_task_stopped(task_id):
                return
            self._save_task_percentage(task_id, index, total_count, 80.0)
            FwFilesStorage.delete(file_id)

            # print('delete {} of {}'.format(index, total_count))
            # time.sleep(2)
        # FwFilesStorage.delete_many(file_id_list)

        # 第二步，总进度条的 80-85%
        # 移除存储桶中，固件包自身文件
        MyTask.save_task_percentage(task_id, 80.0)
        pack_item = PackFileDO.fetch_pack(pack_id)
        pack_file_id = pack_item['file_id']
        PackFilesStorage.delete(pack_file_id)

        # 第三步，总进度条的 85-95%
        # 移除该固件包关联的所有文件记录
        MyTask.save_task_percentage(task_id, 85.0)
        FwFileDO.delete_many_of_pack(pack_id)

        # 第四步，总进度条的 95-100%
        # 移除该固件包自身记录
        MyTask.save_task_percentage(task_id, 95.0)
        PackFileDO.delete(pack_id)

        # 完成任务
        MyTask.save_task_percentage(task_id, 100.0)

    def _save_task_percentage(self, task_id, count, total, max_percent):
        percent = count * max_percent / total
        MyTask.save_task_percentage(task_id, percent, min_step=2.0)

    # @staticmethod
    # def remove_all_packs():
    #     packs_list = PackFileDO.all_packs()
    #     pack_id_list = [pack_item['pack_id'] for pack_item in packs_list]
    #     for pack_id in pack_id_list:
    #         PackProcessService.remove_pack(pack_id)

    @staticmethod
    def remove_all_packs_by_type(pack_type):
        packs_list = PackFileDO.all_packs_type(pack_type)
        if len(packs_list) == 0:
            # 返回空任务列表
            return []

        # 固件包 ID 列表
        pack_id_list = [pack_item['pack_id'] for pack_item in packs_list]
        tasks_list = []
        for pack_id in pack_id_list:
            # 停止所有当前包的运行任务
            PackProcessService.stop_running_tasks_of_pack(pack_id)

            # 启动移除固件包的任务
            task_id = PackProcessService.start_remove_packs_task(pack_id)
            tasks_list.append(task_id)

        # 返回所有任务的列表
        return tasks_list

    @staticmethod
    def start_remove_packs_task(pack_id):
        pack_proc_serv = PackProcessService()
        extra_info = {'pack_id': pack_id, 'task_type': TaskType.REMOVE_FW_PACKS,
                      'task_name': '清空固件包',
                      'task_desc': '清空指定固件包(ID: {})下的所有文件项，并删除其文件内容。'.format(pack_id)}
        task = MyTask(pack_proc_serv.remove_pack, (pack_id,), extra_info=extra_info)
        return task.get_task_id()

    @staticmethod
    def stop_running_tasks_of_pack(pack_id):
        tasks_list = TasksDAO.search_by_pack(pack_id)
        for task_info in tasks_list:
            task_status = task_info['task_status']
            # 没有执行完成的任务状态，用缓存中任务信息代替
            if task_status == TaskStatus.START or task_status == TaskStatus.RUNNING:
                MyTask.stop_task(task_info['task_id'])


