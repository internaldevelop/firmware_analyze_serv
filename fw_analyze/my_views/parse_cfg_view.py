from fw_analyze.service.cfg_analyze_service import CfgAnalyzeService
from fw_analyze.service.overflow_detect_service import OverflowDetectService
from fw_analyze.service.files_service import FilesService
from fw_analyze.service.functions_service import FunctionsService
from fw_analyze.service.vars_service import VarsService
from utils.db.mongodb.cfg_dao import CfgAnalyzeResultDAO
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.logs import LogRecords
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_err_p, sys_app_err
from utils.sys.error_code import Error
from angr_helper.function_parse import FunctionParse
from angr_helper.fw_vulner_analyze import FwVulnerAnalyze
from angr_helper.overflow_detect import Overflow_Detect
from angr_helper.angr_proj import AngrProj
import base64

from utils.task.my_task import MyTask

import utils.sys.config
func_vulner_col = utils.sys.config.g_firmware_db_full["function_vulner_dict"]
func_taint_col = utils.sys.config.g_firmware_db_full["function_taint_dict"]


def cfg_func_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    # 查找函数列表分析结果
    # 查询文件 CFG 分析的标记
    is_cfg = CfgAnalyzeService.has_cfg_analyze(file_id)
    if not is_cfg:
        # 启动分析任务
        task_id = CfgAnalyzeService.start_cfg_task(file_id)
        # 保存操作日志
        LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析CFG',
                        desc='对二进制文件做调用流程图分析')

        # 返回响应：任务初始化的信息
        return sys_app_ok_p(MyTask.fetch_exec_info(task_id))

    # 启动分析任务
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

    infos_dict['vulnerabe'] = {'flag': '0', 'desc': '非脆弱性函数'}  # 0:非脆弱性函数 1:脆弱性函数
    infos_dict['taint'] = {'flag': '0', 'desc': '非污点函数'}  # 0:非污点函数 1:非污点函数
    func_name = infos_dict.get('function_name')

    if func_name is not None:
        vulner_info = func_vulner_col.find_one({'func_name': {'$regex': func_name}})

        if vulner_info is not None:
            infos_dict['vulnerabe'] = {'flag': '1', 'desc': '脆弱性函数'}  # 0:非脆弱性函数 1:脆弱性函数

        taint_info = func_taint_col.find_one({'func_name': {'$regex': func_name}})

        if taint_info is not None:
            infos_dict['taint'] = {'flag': '1', 'desc': '污点函数'}  #  0:非污点函数 1:非污点函数

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


def detect_vulner(request):
    file_id = ReqParams.one(request, 'file_id')
    # pack_id = ReqParams.one(request, 'pack_id')
    # fw_vul_analyze = FwVulnerAnalyze(file_id)
    # res = fw_vul_analyze.vuler_analyze()
    # return sys_app_ok_p({'res': res})

    # 查询文件 detect 分析的标记
    is_detect = OverflowDetectService.has_detect_overflow(file_id)
    if not is_detect:
        # 启动detect任务
        task_id = OverflowDetectService.start_detect_task(file_id)
        # 保存操作日志
        LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析OVERFLOW',
                        desc='对二进制文件做溢出漏洞分析')

        # 返回响应：任务初始化的信息
        return sys_app_ok_p(MyTask.fetch_exec_info(task_id))

    file_item = FwFileDO.find(file_id)
    buffer_overflow = file_item.get('buffer_overflow')
    integer_overflow = file_item.get('integer_overflow')
    cmd_injection_overflow = file_item.get('cmd_injection_overflow')
    # return sys_app_ok_p({'缓冲区溢出': buffer_overflow, '整数溢出': integer_overflow, '命令注入溢出': cmd_injection_overflow})

    overflow_list = []
    overflow_list.append({"name": "缓冲区溢出", "value": buffer_overflow})
    overflow_list.append({"name": "整数溢出", "value": integer_overflow})
    overflow_list.append({"name": "命令注入溢出", "value": cmd_injection_overflow})

    return sys_app_ok_p({'overflow': overflow_list})

    # fw_vul_analyze = Overflow_Detect(file_id)
    # res = fw_vul_analyze.detect()
    # return sys_app_ok_p({'res': res})


# 获取脆弱性函数列表
def vulner_func_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    # 查找函数列表分析结果
    # 查询文件 CFG 分析的标记
    is_cfg = CfgAnalyzeService.has_cfg_analyze(file_id)
    if not is_cfg:
        # 启动分析任务
        task_id = CfgAnalyzeService.start_cfg_task(file_id)
        # 保存操作日志
        LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析CFG',
                        desc='对二进制文件做调用流程图分析')

        # 返回响应：任务初始化的信息
        return sys_app_ok_p(MyTask.fetch_exec_info(task_id))

    # 启动分析任务
    functions = FilesService.functions_list(file_id)
    if len(functions) == 0:
        return sys_app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    vulnerabe_func_list = []

    vulner_funcs = []

    vulner_list = func_vulner_col.find()

    for vulner_info in vulner_list:
        vulner_funcs.append(vulner_info.get('func_name'))
    for func_info in functions:
        func_name = func_info.get('name')
        for vulner_func_info in vulner_funcs:
            if vulner_func_info == func_name:
                vulnerabe_func_list.append(vulner_func_info)

    # 保存操作日志
    LogRecords.save('', category='query', action='查询脆弱性函数列表', desc='查询指定固件文件（ID=%s）在代码分析中产生的函数列表' % file_id)

    return sys_app_ok_p({'vulnerabe_num': len(vulnerabe_func_list), 'vulnerabe_func_list': vulnerabe_func_list})


# 获取污点函数列表
def taint_func_list(request):
    # 从请求中取参数：文件 ID
    file_id = ReqParams.one(request, 'file_id')

    # 查找函数列表分析结果
    # 查询文件 CFG 分析的标记
    is_cfg = CfgAnalyzeService.has_cfg_analyze(file_id)
    if not is_cfg:
        # 启动分析任务
        task_id = CfgAnalyzeService.start_cfg_task(file_id)
        # 保存操作日志
        LogRecords.save({'task_id': task_id, 'file_id': file_id}, category='analysis', action='分析CFG',
                        desc='对二进制文件做调用流程图分析')

        # 返回响应：任务初始化的信息
        return sys_app_ok_p(MyTask.fetch_exec_info(task_id))

    # 启动分析任务
    functions = FilesService.functions_list(file_id)
    if len(functions) == 0:
        return sys_app_err(Error.FW_FILE_NO_CFG_ANALYZE)

    taint_func_list = []

    taint_funcs = []

    taint_list = func_taint_col.find()

    for taint_info in taint_list:
        taint_funcs.append(taint_info.get('func_name'))
    for func_info in functions:
        func_name = func_info.get('name')
        for taint_func_info in taint_funcs:
            if taint_func_info == func_name:
                taint_func_list.append(taint_func_info)

    # 保存操作日志
    LogRecords.save('', category='query', action='查询污点函数列表', desc='查询指定固件文件（ID=%s）在代码分析中产生的函数列表' % file_id)

    return sys_app_ok_p({'taint_num': len(taint_func_list), 'taint_func_list': taint_func_list})