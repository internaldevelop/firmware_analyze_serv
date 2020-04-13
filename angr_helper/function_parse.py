from angrutils import hook0, plot_cg, plot_cfg

from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from angr_helper.angr_proj import AngrProj
import os


class FunctionParse:
    def __init__(self, file_id, func_addr):
        # 创建一个空 project 对象
        self.angr_proj = AngrProj(file_id, cfg_mode='None')

        # 初始化状态机
        start_state = self.angr_proj.proj.factory.blank_state(addr=func_addr)
        start_state.stack_push(0x0)

        self.angr_proj.cfg = self.angr_proj.call_cfg(start_addr=[func_addr])

        self.file_id = file_id
        self.func_addr = func_addr

    @staticmethod
    def functions_extract(project):
        functions = []
        func_items = project.kb.functions.items()
        for addr, func in func_items:
            # 记录函数地址和函数名称
            functions.append({'name': func.name, 'addr': hex(addr)})
        return functions

    #
    # @staticmethod
    # def functions_parse(functions):
    #     # 留作以后从复杂结构提取函数列表
    #     return functions
    #
    # def get_function_list(self):
    #     return self.func_list

    def call_graph(self, verbose=True):
        # # 创建一个空 project 对象
        # angr_proj = AngrProj(file_id, cfg_mode='None')
        #
        # # 初始化状态机
        # start_state = angr_proj.proj.factory.blank_state(addr=func_addr)
        # start_state.stack_push(0x0)
        #
        # # 仿真模式解析代码
        # cfg = angr_proj.call_cfg(start_addr=[func_addr], initial_state=start_state)

        # 将函数关系图生成到一个随机文件名的 png 中
        graph_file = os.path.join(MyPath.temporary(), StrUtils.uuid_str())
        # graph_file = StrUtils.uuid_str()
        plot_cg(self.angr_proj.proj.kb, graph_file, format="png", verbose=verbose)

        # 读取文件
        try:
            with open(graph_file + '.png', 'rb') as fp:
                return fp.read()
        except (OSError, IOError):
            return None

    @staticmethod
    def call_graph_mode2(angr_proj, func_addr, verbose=True):
        # 初始化状态机
        start_state = angr_proj.proj.factory.blank_state(addr=func_addr)
        start_state.stack_push(0x0)

        # 将函数关系图生成到一个随机文件名的 png 中
        graph_file = StrUtils.uuid_str()
        plot_cg(angr_proj.proj.kb, graph_file, format="png", verbose=verbose)
        # plot_cfg(angr_proj.cfg_model, graph_file, format="png", asminst=True)

        # 读取文件
        try:
            with open(graph_file + '.png', 'rb') as fp:
                return fp.read()
        except (OSError, IOError):
            return None

    def func_successors(self):
        cfg = self.angr_proj.cfg
        func_addr = self.func_addr

        # 检查指定函数的节点是否存在（即函数地址是否有效）
        node = cfg.model.get_any_node(func_addr)
        if node is None:
            return []

        # 取函数的后继调用的地址列表
        successors = list(cfg.kb.callgraph.successors(func_addr))
        succ_func_list = []
        for succ_addr in successors:
            # 根据地址获取节点
            succ_node = cfg.model.get_any_node(succ_addr)
            # 伪节点，非函数地址，再找下一级
            if succ_node.name is None:
                # 有函数名称为 PathTerminator，不知何故
                succ_node = list(cfg.graph.successors(succ_node))[0]

            succ_func_list.append({'name': succ_node.name, 'addr': hex(succ_node.addr)})

        return succ_func_list

    def function_asm(self):
        func_addr = self.func_addr

        # 获取函数的代码块
        block = self.angr_proj.proj.factory.block(func_addr)

        # 关闭 pretty-print，代码需要保留以作参考
        # print(block.pp())

        # 取 capstone 汇编代码
        # print(block.capstone)
        asm = block.capstone
        return asm

    def function_vex(self):
        func_addr = self.func_addr

        # 获取函数的代码块
        block = self.angr_proj.proj.factory.block(func_addr)

        # 取 VEX IR，相对汇编语言，VEX IR更像是Compiler的中间语言
        # print(block.vex)
        vex = block.vex
        return vex

    def _file_name(self):
        file_name = FwFilesStorage.export(self.file_id)
        return os.path.basename(file_name)

    def function_name(self):
        # 检查指定函数的节点是否存在（即函数地址是否有效）
        node = self.angr_proj.cfg.model.get_any_node(self.func_addr)
        if node is None:
            return ''
        return node.name

    def function_infos(self):
        # 获取函数的后继调用函数
        successors = self.func_successors()

        # 获取函数的汇编码和中间代码
        asm = self.function_asm()
        vex = self.function_vex()

        # 反编译
        try:
            dec = self.decompiler()
        except AttributeError as attr_err:
            dec = ''

        return {
            'file_id': self.file_id,
            'file_name': self._file_name(),
            'function_name': self.function_name(),
            'function_addr': self.func_addr,
            'asm': str(asm),
            'vex': str(vex),
            'successors_count': len(successors),
            'successors': successors,
            'decompiler': dec
        }

    @staticmethod
    def func_name_from_addr(func_addr, proj=None, cfg=None):
        func = FunctionParse.func_by_addr(func_addr, proj, cfg)
        return '' if func is None else func.name

    @staticmethod
    def func_by_addr(func_addr, proj=None, cfg=None):
        func = None
        if proj is not None:
            func = proj.kb.functions.function(func_addr)
        if cfg is not None:
            func = cfg.kb.functions.function(func_addr)
        return func

    def decompiler(self):
        cfg = self.angr_proj.cfg
        func = FunctionParse.func_by_addr(self.func_addr, cfg=cfg)
        if func is None:
            return ''
        else:
            dec = self.angr_proj.proj.analyses.Decompiler(func, cfg=cfg)
            print(dec.codegen.text)
            return dec.codegen.text
