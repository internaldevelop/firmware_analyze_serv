import os
import angr


class AngrProj:

    def __init__(self, file_id):
        # 临时用指定文件测试
        root_path = os.path.dirname(os.path.realpath(__file__))
        root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')

        # 保存 文件 ID
        self.file_id = file_id
        # 创建 angr project
        self.proj = angr.Project(os.path.join(samples_path, 'ais3_crackme'), load_options={'auto_load_libs': False})

        # 采用快速模式创建 cfg
        self.cfg = None
        self.cfg_fast()

    def cfg_fast(self):
        # 快速模式生成 CFG
        self.cfg = self.proj.analyses.CFGFast()
