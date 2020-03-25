from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from common.task import MyTask
from angr_helper.angr_proj import AngrProj
from angr_helper.fw_func_parse import FwFuncParse


def async_fw_functions_list(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 启动分析任务
    task = MyTask(_proc_fw_functions_list, (file_id, ))
    task_id = task.get_task_id()

    # 初始化缓存的任务信息
    MyTask.init_exec_status(task_id)

    # 返回任务信息
    task_info = MyTask.fetch_exec_info(task_id)
    return sys_app_ok_p(task_info)


def _proc_fw_functions_list(file_id, task_id):
    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id, progress_callback=run_percent_cb, task_id=task_id)

    # 获取代码中的函数列表
    func_parse = FwFuncParse(angr_proj)
    functions = func_parse.func_list()

    # 保存执行完成后的状态和结果集
    MyTask.save_exec_info(task_id, 100.0, {'functions_count': len(functions), 'functions': functions})


def translate_percent(percentage):
    if percentage < 10.0:
        return 0.0
    elif 10.0 <= percentage < 20.0:
        return 20.0
    elif 20.0 <= percentage < 30.0:
        return 40.0
    elif 30.0 <= percentage < 40.0:
        return 60.0
    elif 40.0 <= percentage < 50.0:
        return 80.0


def run_percent_cb(percentage, **kwargs):

    # 由于大于50%进程后没有 project 可以获取，需要做进度百分比转换
    if 'cfg' in kwargs:
        # 从动态参数中获取 project 中保存的任务 ID
        task_id = kwargs['cfg'].project.my_task_id

        # 调试信息打印
        info = 'Func-list({}): {}%'.format(task_id, percentage)
        print(info)

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

