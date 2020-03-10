from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from angr_helper.angr_proj import AngrProj
from angr_helper.fw_func_parse import FwFuncParse


def _req_params(request):
    file_id = req_get_param(request, 'file_id')
    func_addr_hex = req_get_param(request, 'func_addr')
    func_addr = int(func_addr_hex, 16)
    return file_id, func_addr


def fw_functions_list(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id)

    # 获取代码中的函数列表
    func_parse = FwFuncParse(angr_proj)
    functions = func_parse.func_list()

    return sys_app_ok_p({'functions_count': len(functions), 'functions': functions})


def func_successors(request):
    # 从请求中取参数：文件 ID，函数地址
    file_id, func_addr = _req_params(request)

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id)

    # 获取函数的后继调用
    func_parse = FwFuncParse(angr_proj)
    successors = func_parse.func_successors(func_addr)

    return sys_app_ok_p({'successors_count': len(successors), 'successors': successors})


def func_asm(request):
    # 从请求中取参数：文件 ID，函数地址
    file_id, func_addr = _req_params(request)

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id)

    # 读取函数的汇编代码
    func_parse = FwFuncParse(angr_proj)
    asm = func_parse.func_asm(func_addr)
    print(asm)

    return sys_app_ok_p(str(asm))


def func_vex(request):
    # 从请求中取参数：文件 ID，函数地址
    file_id, func_addr = _req_params(request)

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id)

    # 读取函数的中间代码
    func_parse = FwFuncParse(angr_proj)
    vex = func_parse.func_vex(func_addr)
    print(vex)

    return sys_app_ok_p(str(vex))
