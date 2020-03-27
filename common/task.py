import uuid
# import threading
from multiprocessing import Process
from common.redis import MyRedis
from common.utils.general import SysUtils

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
        init_status = {'task_id': task_id,
                       'start_time': SysUtils.get_now_time_str(),
                       'exec_status': 'running',
                       'percentage': 0.0,
                       'result': {}}
        MyRedis.set(task_id, init_status, category=task_cat)

    @staticmethod
    def _calc_exec_time(exec_info):
        percent = exec_info['percentage']
        # 无意义的百分比，不做处理
        if percent <= 0:
            return

        # 计算已进行的时间（秒为单位，含小数）
        start_time = SysUtils.parse_time_str(exec_info['start_time'])
        delta_time = SysUtils.elapsed_time_ms(start_time) / 1000.0

        # 任务完成时，剩余时间为0
        if percent >= 100.0:
            remain_time = 0.0
        else:
            remain_time = delta_time / percent * 100 - delta_time
        print(remain_time)

        # 设置剩余时间
        exec_info['remain_time'] = remain_time
        return

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

        # 计算执行时间（预计剩余时间）
        MyTask._calc_exec_time(exec_info)

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
