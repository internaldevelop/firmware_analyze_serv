from common.utils.http_request import req_get_param, req_post_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from fw_analyze.db.cfg import CfgAnalyzeResult
from fw_analyze.db.functions import FunctionsResult
from common.error_code import Error
from angr_helper.function_parse import FunctionParse


def cfg_file_list(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 查找函数列表分析结果
    task_id, functions = FunctionsResult.find(file_id)
    if functions is None:
        app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    # 加载分析结果
    func_parse = FunctionParse(file_id, functions)

    # 取函数列表
    func_list = func_parse.get_function_list()
    return sys_app_ok_p({'functions_count': len(functions), 'functions': func_list})
