import os
import angr
from angrutils import hook0


class AngrProj:

    def __init__(self, file_id,
                 task_id='',
                 cfg_mode='cfg_emu',
                 progress_callback=None,
                 progress_bar=False):

        file_path = self._id_to_file(file_id)

        # 保存参数：进度回调函数
        self.progress_cb = self._progress_print if progress_callback is None else progress_callback
        # 保存参数：是否打印进度条
        self.inline_progress_bar = progress_bar

        # 保存 文件 ID
        # self.file_id = file_id
        # 创建 angr project
        self.proj = angr.Project(file_path, load_options={'auto_load_libs': False})
        # 利用 angr project 对象保存 task_id，以便传递到进程回调函数
        self.proj.my_task_id = task_id

        self.cfg = self.call_cfg(cfg_mode=cfg_mode)
        # 采用快速模式创建 cfg
        # self.cfg = self._cfg_fast() if cfg_fast else None

    def _id_to_file(self, file_id):
        # 临时用指定文件测试
        root_path = os.path.dirname(os.path.realpath(__file__))
        root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')
        if file_id == '1':
            file_name = 'ais3_crackme'
        elif file_id == '2':
            file_name = '1.6.26-libjsound.so'
        elif file_id == '3':
            file_name = 'mysql'
        else:
            file_name = 'ais3_crackme'
        return os.path.join(samples_path, file_name)

    def call_cfg(self, cfg_mode='cfg_emu', start_addr=[0x0]):
        if cfg_mode == 'cfg_emu':
            return self._cfg_emulated(start_addr=start_addr)
        elif cfg_mode == 'cfg_fast':
            return self._cfg_fast()
        else:
            return None

    def _cfg_fast(self):
        # 快速模式生成 CFG
        cfg = self.proj.analyses.CFGFast(show_progressbar=self.inline_progress_bar,
                                         progress_callback=self.progress_cb)
        return cfg

    def _cfg_emulated(self, start_addr=[0x0]):
        # 仿真模式生成 CFG
        with hook0(self.proj):
            cfg_emu = self.proj.analyses.CFGEmulated(fail_fast=False, context_sensitivity_level=1,
                                                     starts=start_addr,
                                                     enable_function_hints=False, keep_state=True,
                                                     enable_advanced_backward_slicing=False,
                                                     enable_symbolic_back_traversal=False,
                                                     normalize=True)
        return cfg_emu

        # cfg = self.proj.analyses.CFGFast(show_progressbar=self.inline_progress_bar,
        #                                  progress_callback=self.progress_cb)
        # return cfg

    def _progress_print(self, percentage, **kwargs):
        print('Analysis progress: ' + str(percentage) + '%')
