from angr_helper.angr_proj import AngrProj
from angr.knowledge_plugins.cfg import CFGModel


class FunctionParse:
    def __init__(self, file_id, cfg_result):
        self.angr_proj = AngrProj(file_id, cfg_mode='None')
        cfg_model = CFGModel.parse(cfg_result, cfg_manager=self.angr_proj.proj.kb.cfgs)
        self.functions = []

    def get_function_list(self):
        self.functions.clear()

        # 取函数列表
        functions = self.angr_proj.proj.kb.functions.items()
        for addr, func in functions:
            # 记录函数地址和函数名称
            self.functions.append({'name': func.name, 'addr': hex(addr)})
            # print(hex(addr), func.name)
        return self.functions
