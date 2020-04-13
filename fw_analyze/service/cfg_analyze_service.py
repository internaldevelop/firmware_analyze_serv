from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from fw_analyze.progress.cfg_progress import CfgProgress
from utils.db.mongodb.cfg import CfgAnalyzeResultDO
from utils.db.mongodb.functions import FunctionsResultDO
from utils.task.my_task import MyTask
from utils.task.task_type import TaskType


class CfgAnalyzeService:
    def __init__(self, file_id):
        self.file_id = file_id
        self.task_id = None
        pass

    @staticmethod
    def start_cfg_task(file_id):
        cfg_analyze = CfgAnalyzeService(file_id)
        extra_info = {'file_id': file_id, 'task_type': TaskType.CFG_ANALYZE,
                      'task_name': '控制流分析',
                      'task_desc': '进行控制流分析，保存 CFG graph 和函数列表。'}
        task = MyTask(cfg_analyze.analyze_cfg_proc, (file_id,), extra_info=extra_info)
        return task.get_task_id()

    def analyze_cfg_proc(self, file_id, task_id):
        self.task_id = task_id

        # 通过 project 快速解析文件
        angr_proj = AngrProj(file_id, progress_callback=self.run_percent_cb, task_id=task_id,
                             cfg_mode='cfg_fast')

        # ser = angr_proj.proj.serialize()
        # proj = angr_proj.proj.parse(ser)

        # 序列化 cfg
        cfg_result = angr_proj.cfg.model.serialize()

        # 保存 cfg 分析结果到数据库
        CfgAnalyzeResultDO.save(file_id, task_id, cfg_result)

        # 从 project 中提取函数列表
        functions = FunctionParse.functions_extract(angr_proj.proj)

        # 保存 函数列表到数据库
        FunctionsResultDO.save(file_id, task_id, functions)

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
