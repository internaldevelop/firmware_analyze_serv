import os
import angr
from angrutils import hook0
from angr.knowledge_plugins.cfg import CFGModel


class AngrProj:

    def __init__(self, file_id,
                 task_id='',
                 cfg_mode='cfg_emu',
                 progress_callback=None,
                 progress_bar=False):

        file_path, file_arch = AngrProj.id_to_file(file_id)

        # 保存参数：进度回调函数
        self.progress_cb = self._progress_print if progress_callback is None else progress_callback
        # 保存参数：是否打印进度条
        self.inline_progress_bar = progress_bar

        # 保存 文件 ID
        # self.file_id = file_id
        # 创建 angr project
        # self.proj = angr.Project(file_path, load_options={'auto_load_libs': False})
        main_opts = {} if len(file_arch) == 0 else {'backend': 'blob', 'base_addr': 0, 'arch': file_arch}
        # main_opts = {} if len(file_arch) == 0 else {'base_addr': 0, }
        self.proj = angr.Project(file_path, load_options={'auto_load_libs': False, 'main_opts': main_opts, })
        # self.proj = angr.Project(file_path, load_options={'auto_load_libs': False, })

        # 利用 angr project 对象保存 task_id，以便传递到进程回调函数
        self.proj.my_task_id = task_id

        self.cfg = self.call_cfg(cfg_mode=cfg_mode)
        # cfg_model 保存从序列化的 CFG 数据，加载解析后的对象
        self.cfg_model = None

    @staticmethod
    def id_to_file(file_id):
        # 临时用指定文件测试
        root_path = os.path.dirname(os.path.realpath(__file__))
        root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')
        file_list = {
            # 自动检测结果 arch 为 'AMD64'
            '1': {'file_name': 'ais3_crackme', 'file_arch': ''},
            # 自动检测结果 arch 为 'X86'
            '2': {'file_name': '1.6.26-libjsound.so', 'file_arch': ''},
            # 自动检测结果 arch 为 'AMD64'
            '3': {'file_name': 'mysql', 'file_arch': ''},
            '11': {'file_name': '2E0', 'file_arch': 'MIPS32'},
            '12': {'file_name': 'libstdc++.so.6.0.16', 'file_arch': ''},
            '13': {'file_name': '2E0.7z', 'file_arch': 'MIPS32'},
            '14': {'file_name': 'libm-0.9.33.2.so', 'file_arch': ''},
            '15': {'file_name': '1702A0.squashfs', 'file_arch': ''},
            '21': {'file_name': 'opkg', 'file_arch': ''},
        }
        if file_id not in file_list:
            file_name = 'ais3_crackme'
            file_arch = ''
        else:
            file_name = file_list[file_id]['file_name']
            file_arch = file_list[file_id]['file_arch']
        return os.path.join(samples_path, file_name), file_arch

    def call_cfg(self, cfg_mode='cfg_emu', start_addr=[0x0], initial_state=None):
        if cfg_mode == 'cfg_emu':
            return self._cfg_emulated(start_addr=start_addr, initial_state=initial_state)
        elif cfg_mode == 'cfg_fast':
            return self._cfg_fast()
        else:
            return None

    def parse_cfg(self, cfg_ser):
        self.cfg_model = CFGModel.parse(cfg_ser, cfg_manager=self.proj.kb.cfgs)

    def _cfg_fast(self):
        # 快速模式生成 CFG
        cfg = self.proj.analyses.CFGFast(show_progressbar=self.inline_progress_bar,
                                         progress_callback=self.progress_cb)
        return cfg

    def _cfg_emulated(self, start_addr=[0x0], initial_state=None):
        # 仿真模式生成 CFG
        with hook0(self.proj):
            cfg_emu = self.proj.analyses.CFGEmulated(fail_fast=False,
                                                     context_sensitivity_level=1,
                                                     starts=start_addr,
                                                     initial_state=initial_state,
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
