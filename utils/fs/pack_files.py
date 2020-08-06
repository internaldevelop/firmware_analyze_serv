from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from fw_analyze.service.cfg_analyze_service import CfgAnalyzeService
from utils.const.file_type import FileType
from utils.db.mongodb.file_cache_dao import FileCacheDAO
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.fs_base import FsBase
from utils.task.my_task import MyTask
from utils.task.task_type import TaskType


class PackFiles:
    def __init__(self, pack_id):
        self.pack_id = pack_id
        self.task_id = None

    @staticmethod
    def start_exec_bin_verify_task(pack_id, image_file_name=None):
        pack_files = PackFiles(pack_id)
        extra_info = {'pack_id': pack_id, 'task_type': TaskType.VERIFY_EXEC_BIN,
                      'task_name': '验证二进制文件',
                      'task_desc': '验证固件包中所有的可执行二进制文件，并检查CPU架构。'}
        task = MyTask(pack_files.verify_all_exec_bin_files, (pack_id, image_file_name,), extra_info=extra_info)

        # 任务关联文件名
        MyTask.save_exec_info_name(task.get_task_id(), image_file_name)
        return task.get_task_id()

    @staticmethod
    def start_exec_bin_cfg_analyze_task(pack_id, image_file_name):
        pack_files = PackFiles(pack_id)
        extra_info = {'pack_id': pack_id, 'task_type': TaskType.CFG_ANALYZE,
                      'task_name': '控制流分析',
                      'task_desc': '进行控制流分析，保存 CFG graph 和函数列表。'}
        task = MyTask(pack_files.cfg_all_exec_bin_files, (pack_id,), extra_info=extra_info)

        MyTask.save_exec_info_name(task.get_task_id(), image_file_name)
        return task.get_task_id()

    def _save_task_percentage(self, task_id, count, total):
        percent = count * 100.0 / total
        MyTask.save_task_percentage(task_id, percent, min_step=3.0)

    def verify_all_exec_bin_files(self, pack_id, image_file_name, task_id):
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

        # 完成验证二进制文件，启动任务cfg_analyze
        PackFiles.start_exec_bin_cfg_analyze_task(self.pack_id, image_file_name)

    def cfg_all_exec_bin_files(self, pack_id, task_id):
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
            file_id = file_item['file_id']
            file_path = FwFilesStorage.export(file_item['file_id'], file_name=task_id, override=True)

            is_cfg = CfgAnalyzeService.has_cfg_analyze(file_id)
            if not is_cfg:

                try:
                    # 通过 project 快速解析文件
                    angr_proj = AngrProj(file_id, progress_callback=self.run_percent_cb, task_id=task_id,
                                         cfg_mode='cfg_fast')

                    # 从 project 中提取函数列表
                    functions = FunctionParse.functions_extract(angr_proj.proj)

                    # 保存 函数列表到数据库
                    FileCacheDAO.save_functions(file_id, functions)

                    arch = str(angr_proj.proj.arch)
                    # 设置文件已完成 CFG 分析的标记
                    FwFileDO.set_cfg_analyzed(file_id, 1, arch)
                    PackFileDO.updateArch(pack_id, arch)

                except Exception as e:
                    print(e)

        # 保存任务完成状态
        MyTask.save_exec_info(task_id, 100.0)


    def run_percent_cb(self, percentage, **kwargs):
        if self.task_id is None:
            return

        task_id = self.task_id

        # 调试信息打印
        # info = 'Func-list({}): {}%'.format(task_id, percentage)
        # print(info)
        # print(self.task_id)

        # 只在运行百分比变化时才更新任务状态
        MyTask.save_task_percentage(task_id, percentage)