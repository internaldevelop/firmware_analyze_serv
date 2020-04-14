from fw_analyze.service.cfg_analyze_service import CfgAnalyzeService
from utils.http.http_request import req_post_param
from utils.http.response import sys_app_ok_p
from utils.task.my_task import MyTask
from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from fw_analyze.progress.cfg_progress import CfgProgress
from utils.db.mongodb.logs import LogRecords


def analyze_cfg(request):
    # 从请求中取参数：文件 ID
    file_id = req_post_param(request, 'file_id')

    # 启动分析任务
    task_id = CfgAnalyzeService.start_cfg_task(file_id)

    # 保存操作日志
    LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析CFG',
                    desc='对二进制文件做调用流程图分析')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))
