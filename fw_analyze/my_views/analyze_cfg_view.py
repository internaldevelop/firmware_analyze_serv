from common.utils.http_request import req_get_param, req_post_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from common.task import MyTask
from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from angr_helper.old_fw_func_parse import FwFuncParse
from fw_analyze.progress.cfg_progress import CfgProgress
import base64
from fw_analyze.db.cfg import CfgAnalyzeResult
from fw_analyze.db.functions import FunctionsResult
from common.db.logs import LogRecords

# def _req_params(request):
#     file_id = req_get_param(request, 'file_id')
#     func_addr_hex = req_get_param(request, 'func_addr')
#     func_addr = int(func_addr_hex, 16)
#     return file_id, func_addr


def _init_task_info(task_id):
    # 初始化缓存的任务信息
    return MyTask.init_exec_status(task_id)


def analyze_cfg(request):
    # 从请求中取参数：文件 ID
    file_id = req_post_param(request, 'file_id')

    # 启动分析任务
    task = MyTask(_proc_analyze_cfg, (file_id, ))
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析CFG',
                    desc='对二进制文件做调用流程图分析')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def _proc_analyze_cfg(file_id, task_id):
    cfg_progress = CfgProgress(task_id=task_id)

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id, progress_callback=cfg_progress.run_percent_cb, task_id=task_id, cfg_mode='cfg_fast')

    # 序列化 cfg
    cfg_result = angr_proj.cfg.model.serialize()

    # 保存 cfg 分析结果到数据库
    CfgAnalyzeResult.save(file_id, task_id, cfg_result)

    # 从 project 中提取函数列表
    functions = FunctionParse.functions_extract(angr_proj.proj)

    # 保存 函数列表到数据库
    FunctionsResult.save(file_id, task_id, functions)
