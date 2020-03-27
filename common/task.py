import uuid
# import threading
from multiprocessing import Process
from common.redis import MyRedis

# 定义 redis 中键值的 category
task_cat = 'task'


class MyTask:
    def __init__(self, exec=None, args=()):
        self._exec = None

        # 跨进程共享参数
        # self._fw_path = str(settings.FW_PATH)
        # args += (self._fw_path,)
        # self._sys_code = str(settings.SYS_CODE)
        # args += (self._sys_code,)
        if exec is None:
            self._task_id = None
            self._process = None
        else:
            self._task_id = str(uuid.uuid4())
            args += (self._task_id, )
            self._process = Process(target=exec, args=args)
            self._process.start()

    def get_task_id(self):
        return self._task_id

    # def get_g_fw_path(self):
    #     return self._fw_path
    #
    # def get_g_sys_code(self):
    #     return self._sys_code

    @staticmethod
    def init_exec_status(task_id):
        init_status = {'task_id': task_id, 'exec_status': 'running', 'percentage': 0.0, 'result': {}}
        MyRedis.set(task_id, init_status, category=task_cat)

    @staticmethod
    def save_exec_info(task_id, percent, result={}, notify=True):
        # 从缓存中读取该任务的记录
        exec_info = MyRedis.get(task_id, category=task_cat)

        # 缓存没有记录时创建一条初始状态记录
        if exec_info is None:
            MyTask.init_exec_status(task_id)
            exec_info = MyRedis.get(task_id, category=task_cat)

        # 设置百分比和运行状态
        exec_info['percentage'] = percent
        if percent == 100.0:
            exec_info['exec_status'] = 'complete'

        # 结果集不为空时，用新的结果集替换
        if len(result) > 0:
            exec_info['result'] = result

        # 缓存该任务的记录
        MyRedis.set(task_id, exec_info, category=task_cat)

        # 发送执行状态的更新消息
        if notify:
            MyTask.notify_task_exec_info(exec_info)

    @staticmethod
    def fetch_exec_info(task_id, remove=False):
        # 从缓存中读取该任务的记录
        exec_info = MyRedis.get(task_id, category=task_cat)

        # 如设置移除参数，删除该记录
        if remove:
            MyRedis.delete(task_id, category=task_cat)

        return exec_info

    @staticmethod
    def notify_task_exec_info(exec_info):
        # 从缓存中读取指定任务的当前执行信息
        # exec_info = MyTask.fetch_exec_info(task_id)

        # notify

        return
