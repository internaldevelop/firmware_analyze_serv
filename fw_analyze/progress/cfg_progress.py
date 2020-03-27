from common.task import MyTask


class CfgProgress:
    def __init__(self, task_id='0'):
        self.task_id = task_id

    def translate_percent(self, percentage):
        if percentage == 0.0:
            return 0.0
        elif percentage == 100.0:
            return 100.0
        else:
            return int(percentage / 5) * 5 + 5
        # if percentage < 10.0:
        #     return 0.0
        # elif 10.0 <= percentage < 20.0:
        #     return 20.0
        # elif 20.0 <= percentage < 30.0:
        #     return 40.0
        # elif 30.0 <= percentage < 40.0:
        #     return 60.0
        # elif 40.0 <= percentage < 100.0:
        #     return 80.0

    def run_percent_cb(self, percentage, **kwargs):
        # 由于大于50%进程后没有 project 可以获取，需要做进度百分比转换
        # if 'cfg' in kwargs:
        #     if 'cfg' in kwargs:
        # 从动态参数中获取 project 中保存的任务 ID
        # task_id = kwargs['cfg'].project.my_task_id

        task_id = self.task_id

        # 调试信息打印
        info = 'Func-list({}): {}%'.format(task_id, percentage)
        print(info)
        print(self.task_id)

        # 只在运行百分比变化时才更新任务状态
        new_percentage = self.translate_percent(percentage)
        exec_info = MyTask.fetch_exec_info(task_id)
        old_percentage = exec_info['percentage']
        if new_percentage != old_percentage:
            MyTask.save_exec_info(task_id, new_percentage)

    # else:
    #     # 调试信息打印
    #     info = 'Func-list({}): {}%'.format('??', percentage)
    #     print(info)
    #     print(kwargs)
    #     print(self.task_id)
