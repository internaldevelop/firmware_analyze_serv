# import threading
from multiprocessing import Process
from utils.cache.redis import MyRedis
from utils.db.mongodb.tasks_dao import TasksDAO
from utils.gadget.general import SysUtils
from utils.gadget.strutil import StrUtils
from utils.db.mongodb.logs import LogRecords

# 定义 redis 中键值的 category
from utils.http.task_feedback import task_feedback
from utils.task.task_status import TaskStatus

task_cat = 'task'


class MyTask:
    # args 为传给 target 的参数，extra_info 为任务的附加信息
    def __init__(self, exec=None, args=(), extra_info={}):
        # exec 为回调函数，即 Process 的 target
        if exec is None:
            return

        # 设置任务基本参数
        self._exec = exec
        self._task_id = StrUtils.uuid_str()
        self._extra_info = extra_info

        # 增加参数，并创建新进程对象
        args += (self._task_id,)
        self._process = Process(target=exec, args=args)
        # 设置为守护进程。主进程退出后，子进程会跟随其同时退出，不受保护，主进程退出时不考虑子进程的运行状态
        # self._process.daemon = True

        # 初始化任务状态，并启动进程
        self.init_exec_status()
        self._process.start()

    def get_task_id(self):
        return self._task_id

    def init_exec_status(self):
        # 初始化缓存的任务信息
        task_info = {'task_id': self._task_id,
                     'start_time': SysUtils.get_now_time_str(),
                     'task_status': TaskStatus.RUNNING,
                     'percentage': 0.0,
                     'progress_history': [],
                     'result': {}}
        task_info = dict(task_info, **self._extra_info)
        # 缓存该任务信息
        MyRedis.set(self._task_id, task_info, category=task_cat)

        # 在数据库中保存任务记录
        TasksDAO.save(task_info)

        # 保存任务详情日志
        LogRecords.save(task_info, category='task', action='任务启动', desc='记录任务启动时状态及任务信息')

        # 返回该任务信息
        return task_info

    @staticmethod
    def stop_task(task_id):
        # 从缓存中取出任务信息，同时删除这条缓存
        task_info = MyTask.fetch_exec_info(task_id, remove=True)

        # 只允许终止正在运行的任务
        if task_info['task_status'] != TaskStatus.RUNNING:
            return task_info

        # 设置停止状态和 stop_time
        task_info['task_status'] = TaskStatus.STOPPED
        task_info['stop_time'] = SysUtils.get_now_time_str()

        # 在数据库中保存任务信息
        TasksDAO.save(task_info)

        # 保存任务详情日志
        LogRecords.save(task_info, category='task', action='任务终止', desc='任务被终止')

        return task_info

    @staticmethod
    def is_task_stopped(task_id):
        task_info = MyTask.fetch_exec_info(task_id)
        if task_info is None:
            return True
        elif task_info['task_status'] == TaskStatus.STOPPED:
            return True
        else:
            return False

    @staticmethod
    def _calc_exec_time(task_info):
        percent = task_info['percentage']
        # 无意义的百分比，不做处理
        if percent <= 0:
            return

        # 计算已进行的时间（秒为单位，含小数）
        start_time = SysUtils.parse_time_str(task_info['start_time'])
        delta_time = SysUtils.elapsed_time_ms(start_time) / 1000.0

        # 任务完成时，剩余时间为0
        if percent >= 100.0:
            remain_time = 0.0
        else:
            remain_time = delta_time / percent * 100 - delta_time
        print(remain_time)

        return remain_time

    @staticmethod
    def _save_progress_history(task_info):
        history = task_info['progress_history']

        history.append({
            'percentage': task_info['percentage'],
            'task_status': task_info['task_status'],
            'remain_time': task_info['remain_time'],
            'record_time': task_info['record_time']
        })

        # 只保留5条历史记录
        if len(history) > 5:
            history.pop(0)
        return

    @staticmethod
    def save_exec_info_name(task_id, process_file_name=None):
        # 从缓存或数据库中读取该任务的记录
        task_info = MyTask.fetch_exec_info(task_id)
        # 没有该任务信息记录时，返回失败
        if task_info is None:
            return False
        # 增加当前任务处理的文件名（考虑任务出发点是文件）
        if process_file_name is not None:
            task_info['process_file_name'] = process_file_name
            TasksDAO.save(task_info)

    @staticmethod
    def save_exec_info_pack_id(task_id, pack_id=None):
        # 从缓存或数据库中读取该任务的记录
        task_info = MyTask.fetch_exec_info(task_id)
        # 没有该任务信息记录时，返回失败
        if task_info is None:
            return False
        if pack_id is not None:
            task_info['pack_id'] = pack_id
            TasksDAO.save(task_info)

    @staticmethod
    def save_exec_info(task_id, percent, result=None, notify=True):
        # 从缓存或数据库中读取该任务的记录
        task_info = MyTask.fetch_exec_info(task_id)

        # 没有该任务信息记录时，返回失败
        if task_info is None:
            return False

        # 设置百分比和运行状态
        task_info['percentage'] = percent

        # 结果集不为空时，用新的结果集替换
        if result is not None:
            task_info['result'] = result

        # 计算并记录执行时间（预计剩余时间）
        task_info['remain_time'] = MyTask._calc_exec_time(task_info)
        # 设置当前记录时间
        task_info['record_time'] = SysUtils.get_now_time_str()

        # 保存处理进程的历史记录
        MyTask._save_progress_history(task_info)

        # 调用 websocket task_feedback
        task_feedback(task_id, task_info)

        # 运行100%时，设置任务完成状态，并更新数据库，清理缓存
        if percent == 100.0:
            task_info['task_status'] = TaskStatus.COMPLETE
            TasksDAO.save(task_info)
            MyRedis.delete(task_id, category=task_cat)

            # 保存任务详情日志
            LogRecords.save(task_info, category='task', action='任务完成', desc='任务执行100%，记录任务执行结果信息')
        else:
            # 缓存该任务的记录
            MyRedis.set(task_id, task_info, category=task_cat)

        # 发送执行状态的更新消息
        if notify:
            MyTask.notify_task_exec_info(task_info)

        return True

    @staticmethod
    def fetch_exec_info(task_id, remove=False):
        # 从缓存中读取该任务的记录
        task_info = MyRedis.get(task_id, category=task_cat)

        # 如设置移除参数，删除该记录
        if remove and task_info is not None:
            MyRedis.delete(task_id, category=task_cat)

        # 缓存中没有任务信息，则从数据库中读取
        if task_info is None:
            task_info = TasksDAO.find(task_id)

        return task_info

    @staticmethod
    def notify_task_exec_info(exec_info):
        # 从缓存中读取指定任务的当前执行信息
        # exec_info = MyTask.fetch_exec_info(task_id)

        # notify

        return

    @staticmethod
    def save_task_percentage(task_id, percentage, min_step=2.0):
        task_info = MyTask.fetch_exec_info(task_id)
        if task_info is None:
            return
        # 步进 2%
        if percentage - task_info['percentage'] > min_step:
            MyTask.save_exec_info(task_id, percentage)


# 传参方式示例

# def abc(x, y, m, n):
#     print(m-n)
#     print(x, y)
#
#
# if __name__ == '__main__':
#     p = Process(target=abc, args=(5, 0), kwargs={"n": 100, "m": 998})  # 关键字参数必须对应相同的关键字名称
#     p.start()
#     print("bla bla")
#     time.sleep(10)
#     print("over")
