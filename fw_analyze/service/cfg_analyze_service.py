from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from fw_analyze.progress.cfg_progress import CfgProgress
from utils.db.mongodb.cfg_dao import CfgAnalyzeResultDAO
from utils.db.mongodb.file_cache_dao import FileCacheDAO
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.logs import LogRecords
from utils.task.my_task import MyTask
from utils.task.task_type import TaskType
import time
from utils.const.file_type import FileType

class CfgAnalyzeService:
    def __init__(self, file_id):
        self.file_id = file_id
        self.task_id = None
        pass

    @staticmethod
    def auto_cfg_task():
        cfg_analyze = CfgAnalyzeService('')
        extra_info = {'task_type': TaskType.CFG_ANALYZE,
                      'task_name': '控制流分析',
                      'task_desc': '进行控制流分析，保存 CFG graph 和函数列表。'}
        task = MyTask(cfg_analyze.analyze_cfg_proc_auto,  extra_info=extra_info)
        # task = MyTask(cfg_analyze.analyze_cfg_proc_auto,)
        return task.get_task_id()

    @staticmethod
    def start_cfg_task(file_id):
        cfg_analyze = CfgAnalyzeService(file_id)
        extra_info = {'file_id': file_id, 'task_type': TaskType.CFG_ANALYZE,
                      'task_name': '控制流分析',
                      'task_desc': '进行控制流分析，保存 CFG graph 和函数列表。'}
        task = MyTask(cfg_analyze.analyze_cfg_proc, (file_id,), extra_info=extra_info)
        return task.get_task_id()

    def analyze_cfg_proc_auto(self, task_id):
        # 查询所有文件
        list_file_id = FwFileDO._db_get_all_file(FileType.EXEC_FILE)
        for file in list_file_id:
            # print(file)
            file_id = file['file_id']

            is_cfg = CfgAnalyzeService.has_cfg_analyze(file_id)
            if not is_cfg:
                # 启动分析任务
                self.task_id = task_id
                self.file_id = file_id

                try:

                    # 通过 project 快速解析文件
                    angr_proj = AngrProj(file_id, progress_callback=self.run_percent_cb, task_id=task_id,
                                         cfg_mode='cfg_fast')
                    # angr_proj = AngrProj(file_id, progress_callback=self.run_percent_cb, cfg_mode='cfg_fast')

                    # 从 project 中提取函数列表
                    functions = FunctionParse.functions_extract(angr_proj.proj)

                    # 保存 函数列表到数据库
                    FileCacheDAO.save_functions(file_id, functions)

                    print(str(angr_proj.proj.arch))
                    arch = str(angr_proj.proj.arch)
                    # 设置文件已完成 CFG 分析的标记
                    FwFileDO.set_cfg_analyzed(file_id, 1, arch)
                    PackFileDO.updateArch(arch)

                    time.sleep(1)
                except Exception as e:
                    print(e)

    def analyze_cfg_proc(self, file_id, task_id):
        self.task_id = task_id

        # 通过 project 快速解析文件
        angr_proj = AngrProj(file_id, progress_callback=self.run_percent_cb, task_id=task_id, cfg_mode='cfg_fast')

        # 从 project 中提取函数列表
        functions = FunctionParse.functions_extract(angr_proj.proj)

        # 保存 函数列表到数据库
        FileCacheDAO.save_functions(file_id, functions)

        print(str(angr_proj.proj.arch))
        arch = str(angr_proj.proj.arch)
        # 设置文件已完成 CFG 分析的标记
        FwFileDO.set_cfg_analyzed(file_id, 1, arch)
        PackFileDO.updateArch(arch)

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

    @staticmethod
    def has_cfg_analyze(file_id):
        try:
            item = FwFileDO.find(file_id)
            item['cfg_analyze'] == 1
        except Exception as e:
            # print(e)
            return False

        return True
