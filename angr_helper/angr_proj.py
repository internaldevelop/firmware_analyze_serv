import os
import angr


class AngrProj:

    def __init__(self, file_id,
                 task_id='',
                 progress_callback=None,
                 progress_bar=False):
        # 临时用指定文件测试
        root_path = os.path.dirname(os.path.realpath(__file__))
        root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')

        # 保存参数：进度回调函数
        if progress_callback is None:
            self.progress_cb = self._progress_print
        else:
            self.progress_cb = progress_callback
        # 保存参数：是否打印进度条
        self.inline_progress_bar = progress_bar

        # 保存 文件 ID
        self.file_id = file_id
        # 创建 angr project
        self.proj = angr.Project(os.path.join(samples_path, 'ais3_crackme'), load_options={'auto_load_libs': False})
        self.proj.my_task_id = task_id

        # 采用快速模式创建 cfg
        self.cfg = None
        self.cfg_fast()

    def cfg_fast(self):
        # 快速模式生成 CFG
        # self.cfg = self.proj.analyses.CFGFast()
        self.cfg = self.proj.analyses.CFGFast(show_progressbar=self.inline_progress_bar,
                                              progress_callback=self.progress_cb)

    def _progress_print(self, percentage, **kwargs):
        print('Analysis progress: ' + str(percentage) + '%')

