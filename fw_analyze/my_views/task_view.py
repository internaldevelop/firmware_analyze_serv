from utils.db.mongodb.tasks_dao import TasksDAO
from utils.http.http_request import req_get_param
from utils.http.response import sys_app_ok_p
from utils.task.my_task import MyTask
from utils.db.mongodb.logs import LogRecords
from utils.task.task_status import TaskStatus


def get_task_result(request):
    # 从请求中取参数：任务 ID
    task_id = req_get_param(request, 'task_id')

    # 从缓存中读取任务执行信息
    task_info = MyTask.fetch_exec_info(task_id)

    # 保存操作日志
    LogRecords.save(task_info, category='query_task', action='查询任务状态',
                    desc='读取任务（ID=%s）当前执行状态及结果信息' % task_id)

    return sys_app_ok_p(task_info)


# 读取全部任务状态
def get_all_task_result(request):
    # 读取数据库任务集合
    task_id_list = TasksDAO.all_tasks()
    # task_info_list = []
    # # 从缓存中读取任务执行信息
    # for task in task_id_list:
    #     print(task['task_id'])
    #     task_info = MyTask.fetch_exec_info(task['task_id'])
    #     task_id_list.append(task_info)

    # 保存操作日志
    LogRecords.save(task_id_list, category='query', action='查询全部任务状态')

    return sys_app_ok_p(task_id_list)


def stop_task(request):
    # 从请求中取参数：任务 ID
    task_id = req_get_param(request, 'task_id')

    task_info = MyTask.stop_task(task_id)

    # 保存操作日志
    LogRecords.save(task_info, category='task', action='停止任务',
                    desc='停止指定的任务（ID=%s）' % task_id)

    return sys_app_ok_p(task_info)


def search_tasks_by_pack(request):
    # 从请求中取参数：包 ID
    pack_id = req_get_param(request, 'pack_id')
    if pack_id is None:
        return sys_app_ok_p([])

    tasks_list = TasksDAO.search_by_pack(pack_id)
    task_info_list = []
    for task_info in tasks_list:
        # 没有执行完成的任务状态，用缓存中任务信息代替
        if task_info['task_status'] != TaskStatus.COMPLETE:
            task_info = MyTask.fetch_exec_info(task_info['task_id'])
        task_info_list.append(task_info)

    # 保存查询日志
    LogRecords.save(task_info_list, category='query_task', action='查询固件包任务',
                    desc='查询指定的固件包（ID=%s）所有的任务信息' % pack_id)

    return sys_app_ok_p(task_info_list)


def search_tasks_by_file(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')
    if file_id is None:
        return sys_app_ok_p([])

    tasks_list = TasksDAO.search_by_file(file_id)

    # 保存查询日志
    LogRecords.save(tasks_list, category='query_task', action='查询文件任务',
                    desc='查询指定的文件（ID=%s）所有的任务信息' % file_id)

    return sys_app_ok_p(tasks_list)

