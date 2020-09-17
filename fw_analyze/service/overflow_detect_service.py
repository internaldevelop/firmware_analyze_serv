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
from angr_helper.overflow_detect import Overflow_Detect


class OverflowDetectService:
    def __init__(self, file_id):
        self.file_id = file_id
        self.task_id = None
        pass

    @staticmethod
    def has_detect_overflow(file_id):
        try:
            item = FwFileDO.find(file_id)
            if item['file_detect_overflow'] == 1:
                return True
        except Exception as e:
            # print(e)
            return False

        return False

    @staticmethod
    def start_detect_task(file_id):
        detect = OverflowDetectService(file_id)
        extra_info = {'file_id': file_id, 'task_type': TaskType.DETECT_OVERFLOW,
                      'task_name': '检测漏洞溢出',
                      'task_desc': '检测漏洞溢出，保存 缓冲区 整数 命令注入溢出输入数据。'}
        task = MyTask(detect.detect_overflow_proc, (file_id,), extra_info=extra_info)
        return task.get_task_id()

    def detect_overflow_proc(self, file_id, task_id):
        overflow = Overflow_Detect(file_id)
        res = overflow.detect()