from angr_helper.angr_proj import AngrProj
from angr.knowledge_plugins.cfg import CFGModel


class FunctionParse:
    def __init__(self, file_id, functions):
        self.func_list = FunctionParse.functions_parse(functions)

    @staticmethod
    def functions_extract(project):
        functions = []
        func_items = project.kb.functions.items()
        for addr, func in func_items:
            # 记录函数地址和函数名称
            functions.append({'name': func.name, 'addr': hex(addr)})
        return functions

    @staticmethod
    def functions_parse(functions):
        # 留作以后从复杂结构提取函数列表
        return functions

    def get_function_list(self):
        return self.func_list
