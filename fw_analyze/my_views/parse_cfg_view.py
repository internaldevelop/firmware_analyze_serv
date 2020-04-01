from utils.http.http_request import req_get_param
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_ok, sys_app_err_p
from fw_analyze.db.functions import FunctionsResult
from utils.sys.error_code import Error
from angr_helper.function_parse import FunctionParse
from angr_helper.angr_proj import AngrProj
from fw_analyze.db.cfg import CfgAnalyzeResult
import base64


def cfg_file_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    # 查找函数列表分析结果
    task_id, functions = FunctionsResult.find(file_id)
    if functions is None:
        app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    # # 加载分析结果
    # func_parse = FunctionParse(file_id, functions)
    #
    # # 取函数列表
    # func_list = func_parse.get_function_list()
    return sys_app_ok_p({'functions_count': len(functions), 'functions': functions})


def call_graph_a(request):
    # 从请求中取参数：文件 ID
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    # 获取 call_graph 图形数据
    func_parse = FunctionParse(file_id, func_addr)
    graph_data = func_parse.call_graph()

    # 保存执行完成后的状态和结果集
    b64_graph = base64.b64encode(graph_data).decode()

    return sys_app_ok_p({'file_id': file_id, 'func_addr': func_addr, 'call_graph': b64_graph})


def call_graph_b(request):
    # 从请求中取参数：文件 ID
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    # 创建一个空 project 对象
    angr_proj = AngrProj(file_id, cfg_mode='None')

    # 读取 CFG
    task_id, cfg_ser = CfgAnalyzeResult.find(file_id)
    if cfg_ser is None:
        return sys_app_err_p('FW_FILE_NO_CFG_ANALYZE', {'file_id': file_id})

    # 在 angr project 中解析 CFG
    angr_proj.parse_cfg(cfg_ser)

    # 获取 call_graph 图形数据
    graph_data = FunctionParse.call_graph_mode2(angr_proj, func_addr)

    # 保存执行完成后的状态和结果集
    b64_graph = base64.b64encode(graph_data).decode()

    return sys_app_ok_p({'task_id': task_id, 'call_graph': b64_graph})


def function_info(request):
    # 从请求中取参数：文件 ID
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    # 获取指定函数的信息
    func_parse = FunctionParse(file_id, func_addr)
    func_infos = func_parse.function_infos()

    return sys_app_ok_p(func_infos)
