import angr
from angr.knowledge_plugins.variables import VariableType

from angr_helper.function_parse import FunctionParse
from utils.db.mongodb.func_cache_dao import FuncCacheDAO
from utils.db.mongodb.fw_files_storage import FwFilesStorage


class VarsRecovery:
    def __init__(self, file_id, func_addr):
        try:
            self.func_parse = FunctionParse(file_id, func_addr)
        except AttributeError as attr_err:
            return

    def vars(self, fast_mode=True):
        try:
            project = self.func_parse.angr_proj.proj
            cfg = self.func_parse.cfg
        except AttributeError as attr_err:
            return VarsRecovery._compose_vars_dict([], [])

        # 变量恢复
        variable_manager = self._get_variable_manager(fast_mode)

        # 内存变量列表
        vars_and_offset = self._find_vars(variable_manager, VariableType.MEMORY)
        memory_vars = VarsRecovery.extract_memory_vars(vars_and_offset)
        # 寄存器变量列表
        vars_and_offset = self._find_vars(variable_manager, VariableType.REGISTER)
        register_vars = VarsRecovery.extract_register_vars(vars_and_offset)

        return VarsRecovery._compose_vars_dict(memory_vars, register_vars)

    @staticmethod
    def _compose_vars_dict(memory_vars, register_vars):
        return {'memory_vars': {'name': '内存变量', 'count': len(memory_vars), 'vars': memory_vars},
                'register_vars': {'name': '寄存器变量', 'count': len(register_vars), 'vars': register_vars}}

    def _get_variable_manager(self, fast_mode):
        project = self.func_parse.angr_proj.proj
        func = self.func_parse.func

        # 创建一个临时的 KnowledgeBase 实例
        tmp_kb = angr.KnowledgeBase(project)

        if fast_mode:
            # 快速模式变量恢复
            vr = project.analyses.VariableRecoveryFast(func, kb=tmp_kb)
        else:
            # 普通模式变量恢复
            vr = project.analyses.VariableRecovery(func, kb=tmp_kb)

        return vr.variable_manager[func.addr]

    def _find_vars(self, variable_manager, var_sort):
        func = self.func_parse.func
        vars_and_offset = variable_manager.find_variables_by_insn(func.addr, var_sort)
        return vars_and_offset

    @staticmethod
    def extract_memory_vars(vars_and_offset):
        vars_list = []
        for the_var, _ in vars_and_offset:
            print(the_var.name)
            vars_list.append({'name': the_var.name, 'ident': the_var.ident, 'region': hex(the_var.region),
                              'base': the_var.base, 'offset': the_var.offset, 'addr': the_var.addr,
                              'bits': the_var.bits, 'size': the_var.size,
                              })
        return vars_list

    @staticmethod
    def extract_register_vars(vars_and_offset):
        vars_list = []
        for the_var, _ in vars_and_offset:
            print(the_var.name)
            # TODO: reg 即 reg_offset，angr 中查询以下代码，转换成寄存器名称
            # reg_offset, size = arch.registers[key]
            vars_list.append({'name': the_var.name, 'ident': the_var.ident, 'region': hex(the_var.region),
                              'reg': the_var.reg, 'size': the_var.size,
                              })
        return vars_list
