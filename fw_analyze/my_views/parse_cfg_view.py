from utils.db.mongodb.cfg_dao import CfgAnalyzeResultDAO
from utils.db.mongodb.logs import LogRecords
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_err_p
from utils.sys.error_code import Error
from angr_helper.function_parse import FunctionParse
from angr_helper.angr_proj import AngrProj
import base64


def cfg_func_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    # 查找函数列表分析结果
    functions = CfgAnalyzeResultDAO.get_functions(file_id)
    if len(functions) == 0:
        app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    # 保存操作日志
    LogRecords.save('', category='query', action='查询函数列表',
                    desc='查询指定固件文件在代码分析中产生的函数列表')

    return sys_app_ok_p({'functions_count': len(functions), 'functions': functions})


def call_graph_a(request):
    # 从请求中取参数：文件 ID
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    # 获取 call_graph 图形数据
    func_parse = FunctionParse(file_id, func_addr)
    graph_data = func_parse.call_graph()

    # 保存执行完成后的状态和结果集
    b64_graph = base64.b64encode(graph_data).decode()

    # 保存操作日志
    LogRecords.save('', category='query', action='生成函数调用图',
                    desc='生成指定函数的调用关系图')

    return sys_app_ok_p({'file_id': file_id, 'func_addr': func_addr, 'call_graph': b64_graph})


def function_info(request):
    # 从请求中取参数：文件 ID
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    # 获取指定函数的信息
    func_parse = FunctionParse(file_id, func_addr)
    func_infos = func_parse.function_infos()

    # 保存操作日志
    LogRecords.save('', category='query', action='查询函数分析信息',
                    desc='查询代码分析后的函数信息')

    return sys_app_ok_p(func_infos)
