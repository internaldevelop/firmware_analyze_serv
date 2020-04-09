from utils.http.http_request import req_get_param
from utils.http.response import sys_app_ok_p
from utils.task.my_task import MyTask
from utils.db.mongodb.logs import LogRecords


def get_task_result(request):
    # 从请求中取参数：文件 ID
    task_id = req_get_param(request, 'task_id')

    # 从缓存中读取任务执行信息
    task_info = MyTask.fetch_exec_info(task_id)

    # 保存操作日志
    LogRecords.save({'task_id': task_id, 'task_info': task_info}, category='query_task', action='任务状态',
                    desc='读取任务当前执行状态及结果信息')

    return sys_app_ok_p(task_info)
