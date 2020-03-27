from common.utils.http_request import req_get_param, req_post_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from fw_analyze.db.cfg import CfgAnalyzeResult
from common.error_code import Error
from angr_helper.function_parse import FunctionParse


def cfg_file_list(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 查找 cfg 的分析结果
    task_id, cfg_result = CfgAnalyzeResult.find(file_id)
    if cfg_result is None:
        app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    # 加载 cfg 的分析结果
    func_parse = FunctionParse(file_id, cfg_result)

    # 取函数列表
    functions = func_parse.get_function_list()
    return sys_app_ok_p(functions)
