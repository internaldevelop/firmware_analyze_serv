import os
import angr
from angrutils import hook0
from angr.knowledge_plugins.cfg import CFGModel

from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.gadget.my_path import MyPath


class AngrProj:

    def __init__(self, file_id,
                 task_id='',
                 cfg_mode='cfg_emu',
                 progress_callback=None,
                 progress_bar=False):

        file_path = FwFilesStorage.export(file_id)
        if file_path is None:
            return

        # 保存参数：进度回调函数
        self.progress_cb = self._progress_print if progress_callback is None else progress_callback
        # 保存参数：是否打印进度条
        self.inline_progress_bar = progress_bar

        # 保存 文件 ID
        # self.file_id = file_id
        # self.proj = angr.Project(file_path, load_options={'auto_load_libs': False})
        # main_opts = {} if len(file_arch) == 0 else {'backend': 'blob', 'base_addr': 0, 'arch': file_arch}
        # main_opts = {} if len(file_arch) == 0 else {'base_addr': 0, }
        # main_opts = {}
        # main_opts = {'base_addr': 0x08044000,
        #              'arch': 'ARMCortexM',
        #              'backend': 'blob',
        #              'entry_point': 0x08049509}

        # arch, endianness = self._get_arch(file_id)
        # main_opts = {
        #         'backend': 'blob',
        #         'base_addr': 0x10000,
        #         'entry_point': 0x10000,
        #         'arch': arch,
        #         # 'arch': 'ARM',
        #         # 'arch': 'MIPS32',
        #         'offset': 0,
        #     }
        main_opts = {}
        # 创建 angr project
        self.proj = angr.Project(file_path, load_options={'auto_load_libs': False, 'main_opts': main_opts, })
        # self.proj = angr.Project(file_path, load_options={'auto_load_libs': False, })
        # boyscout = self.proj.analyses.BoyScout()
        # self.proj.arch.instruction_endness = 'Iend_LE'

        # 利用 angr project 对象保存 task_id，以便传递到进程回调函数
        self.proj.my_task_id = task_id

        self.cfg = self.call_cfg(cfg_mode=cfg_mode)
        # cfg_model 保存从序列化的 CFG 数据，加载解析后的对象
        self.cfg_model = None

    def _get_arch(self, file_id):
        file_item = FwFileDO.find(file_id)
        # if file_item['extra_props'] is None or file_item['extra_props']['arch'] is None:
        if file_item.get('extra_props') is None:
            return 'ARM', None
        else:
            return file_item['extra_props'].get('arch'), file_item['extra_props'].get('endianness')

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
