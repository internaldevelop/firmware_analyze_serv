from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from common.task import MyTask
from angr_helper.angr_proj import AngrProj
from angr_helper.fw_func_parse import FwFuncParse
import base64


def _req_params(request):
    file_id = req_get_param(request, 'file_id')
    func_addr_hex = req_get_param(request, 'func_addr')
    func_addr = int(func_addr_hex, 16)
    return file_id, func_addr


def _init_task_info(task_id):
    # 初始化缓存的任务信息
    MyTask.init_exec_status(task_id)

    # 返回任务信息
    task_info = MyTask.fetch_exec_info(task_id)
    return task_info


def async_fw_functions_list(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 启动分析任务
    task = MyTask(_proc_fw_functions_list, (file_id, ))
    task_id = task.get_task_id()

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def async_function_info(request):
    # 从请求中取参数：文件 ID，函数地址
    file_id, func_addr = _req_params(request)

    # 启动分析任务
    task = MyTask(_proc_func_info, (file_id, func_addr, ))
    task_id = task.get_task_id()

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def async_function_call_graph(request):
    # 从请求中取参数：文件 ID，函数地址
    file_id, func_addr = _req_params(request)

    # 启动分析任务
    task = MyTask(_proc_func_call_graph, (file_id, func_addr, ))
    task_id = task.get_task_id()

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def _proc_func_call_graph(file_id, func_addr, task_id):
    # 生成 project 对象，但不做 cfg_fast 解析
    angr_proj = AngrProj(file_id, cfg_mode='cfg_emu', progress_callback=run_percent_cb, task_id=task_id)

    # 解析并生成调用流程图的数据
    func_parse = FwFuncParse(angr_proj)
    graph = func_parse.call_graph(func_addr)

    # 保存执行完成后的状态和结果集
    b64_graph = base64.b64encode(graph).decode()
    MyTask.save_exec_info(task_id, 100.0, {'call_graph': b64_graph})


def _proc_fw_functions_list(file_id, task_id):
    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id, progress_callback=run_percent_cb, task_id=task_id)

    # 获取代码中的函数列表
    func_parse = FwFuncParse(angr_proj)
    functions = func_parse.func_list()

    # 保存执行完成后的状态和结果集
    MyTask.save_exec_info(task_id, 100.0, {'functions_count': len(functions), 'functions': functions})


def _proc_func_info(file_id, func_addr, task_id):
    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id, progress_callback=run_percent_cb, task_id=task_id)

    # 生成函数解析对象
    func_parse = FwFuncParse(angr_proj)

    # 读取函数的汇编代码
    asm = func_parse.func_asm(func_addr)
    # print(asm)

    # 读取函数的中间代码
    vex = func_parse.func_vex(func_addr)
    # print(vex)

    # 获取函数的后继调用
    successors = func_parse.func_successors(func_addr)
    # print(successors)

    # 保存执行完成后的状态和结果集
    MyTask.save_exec_info(task_id, 100.0, {'asm': str(asm),
                                           'vex': str(vex),
                                           'successors_count': len(successors),
                                           'successors': successors})

    return


def translate_percent(percentage):
    if percentage < 10.0:
        return 0.0
    elif 10.0 <= percentage < 20.0:
        return 20.0
    elif 20.0 <= percentage < 30.0:
        return 40.0
    elif 30.0 <= percentage < 40.0:
        return 60.0
    elif 40.0 <= percentage < 100.0:
        return 80.0


def run_percent_cb(percentage, **kwargs):

    # 由于大于50%进程后没有 project 可以获取，需要做进度百分比转换
    if 'cfg' in kwargs:
        # 从动态参数中获取 project 中保存的任务 ID
        task_id = kwargs['cfg'].project.my_task_id

        # 调试信息打印
        info = 'Func-list({}): {}%'.format(task_id, percentage)
        print(info)

        # 只在运行百分比变化时才更新任务状态
        new_percentage = translate_percent(percentage)
        exec_info = MyTask.fetch_exec_info(task_id)
        old_percentage = exec_info['percentage']
        if new_percentage != old_percentage:
            MyTask.save_exec_info(task_id, new_percentage)

    else:
        # 调试信息打印
        info = 'Func-list({}): {}%'.format('??', percentage)
        print(info)
        print(kwargs)


def get_task_result(request):
    # 从请求中取参数：文件 ID
    task_id = req_get_param(request, 'task_id')

    # 从缓存中读取任务执行信息
    task_info = MyTask.fetch_exec_info(task_id)

    return sys_app_ok_p(task_info)

