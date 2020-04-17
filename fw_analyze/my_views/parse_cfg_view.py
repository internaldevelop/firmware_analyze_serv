from fw_analyze.service.files_service import FilesService
from fw_analyze.service.functions_service import FunctionsService
from fw_analyze.service.vars_service import VarsService
from utils.db.mongodb.cfg_dao import CfgAnalyzeResultDAO
from utils.db.mongodb.logs import LogRecords
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_err_p, sys_app_err
from utils.sys.error_code import Error
from angr_helper.function_parse import FunctionParse
from angr_helper.angr_proj import AngrProj
import base64


def cfg_func_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    functions = FilesService.functions_list(file_id)
    # 查找函数列表分析结果
    # functions = CfgAnalyzeResultDAO.get_functions(file_id)
    if len(functions) == 0:
        return sys_app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    # 保存操作日志
    LogRecords.save('', category='query', action='查询函数列表',
                    desc='查询指定固件文件（ID=%s）在代码分析中产生的函数列表' % file_id)

    return sys_app_ok_p({'functions_count': len(functions), 'functions': functions})


def call_graph_a(request):
    # 从请求中取参数：文件 ID、函数地址、画图模式
    file_id, func_addr, simple = ReqParams.many(request, ['file_id', 'func_addr.hex', 'simple.int'])

    # 获取 call_graph 图形数据
    func_parse = FunctionParse(file_id, func_addr)
    graph_data = func_parse.cg_graph(simple != 1)

    # 保存操作日志
    LogRecords.save('', category='query', action='生成函数调用图',
                    desc='生成指定函数的调用关系图，文件ID=%s，函数地址=0x%x' % (file_id, func_addr))

    return sys_app_ok_p({'file_id': file_id, 'func_addr': func_addr, 'call_graph': graph_data})


def function_info(request):
    # 从请求中取参数：文件 ID、函数地址
    file_id, func_addr, extra_info = ReqParams.many(request, ['file_id', 'func_addr.hex', 'extra_info'])

    # 获取指定函数的汇编、中间码等代码信息
    codes_dict = FunctionsService.func_codes(file_id, func_addr)
    infos_dict = codes_dict

    if extra_info is not None:
        # 取出首尾空格后分割成列表（用逗号分隔）
        extra_list = extra_info.strip().split(',')
        if 'props' in extra_list:
            # 如指定 props 则附加函数属性信息
            props_dict = FunctionsService.func_props(file_id, func_addr)
            infos_dict['props'] = props_dict
        if 'vars' in extra_list:
            # 如指定 props 则附加函数变量信息
            vars_dict = VarsService.extract_vars(file_id, func_addr)
            infos_dict['vars'] = vars_dict

    # 保存操作日志
    LogRecords.save('', category='query', action='查询函数分析信息',
                    desc='查询代码分析后的函数信息，文件ID=%s，函数地址=0x%x' % (file_id, func_addr))

    return sys_app_ok_p(infos_dict)


def function_props(request):
    # 从请求中取参数：文件 ID、函数地址
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])
    func_props = FunctionsService.func_props(file_id, func_addr)
    return sys_app_ok_p(func_props)


def control_flow_graph(request):
    # 从请求中取参数：文件 ID、函数地址、画图模式
    file_id, func_addr, simple = ReqParams.many(request, ['file_id', 'func_addr.hex', 'simple.int'])

    # 绘制 control_flow_graph (CFG) 图形
    func_parse = FunctionParse(file_id, func_addr)
    graph_data = func_parse.cfg_graph(simple != 1)

    # 保存操作日志
    LogRecords.save('', category='query', action='生成控制流程图',
                    desc='生成指定函数的控制流程图，文件ID=%s，函数地址=0x%x' % (file_id, func_addr))

    return sys_app_ok_p({'file_id': file_id, 'func_addr': func_addr, 'cfg_graph': graph_data})


def control_dependence_graph(request):
    # 从请求中取参数：文件 ID、函数地址、画图模式
    file_id, func_addr, simple = ReqParams.many(request, ['file_id', 'func_addr.hex', 'simple.int'])

    # 绘制 control_dependence_graph (CDG) 图形
    func_parse = FunctionParse(file_id, func_addr)
    graph_data = func_parse.cdg_graph()

    # 保存操作日志
    LogRecords.save('', category='query', action='生成控制依赖图',
                    desc='生成指定函数的控制依赖图，文件ID=%s，函数地址=0x%x' % (file_id, func_addr))

    return sys_app_ok_p({'file_id': file_id, 'func_addr': func_addr, 'cdg_graph': graph_data})
