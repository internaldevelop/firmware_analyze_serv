import angr
from angrutils import hook0, plot_cg, plot_cfg, set_plot_style, plot_cdg

from angr_helper.cfg_analyze import CFGAnalyze
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from angr_helper.angr_proj import AngrProj
import os


class FunctionParse:
    def __init__(self, file_id, func_addr):
        # 创建一个空 project 对象
        self.angr_proj = AngrProj(file_id, cfg_mode='None')
        project = self.angr_proj.proj
        if project is None:
            return

        self.cfg = CFGAnalyze.emulated_normal(project, func_addr)
        # 从函数列表中通过函数地址取函数对象
        self.func = FunctionParse.func_by_addr(func_addr, cfg=self.cfg)

        # functions = FunctionParse.functions_extract(project)

        self.file_id = file_id
        self.func_addr = func_addr

    @staticmethod
    def functions_extract(project):
        functions = []
        func_items = project.kb.functions.items()
        for addr, func in func_items:
            func_name = func.name
            if func_name == 'UnresolvableJumpTarget' or func_name == 'UnresolvableCallTarget':
                continue
            # 记录函数地址和函数名称
            functions.append({'name': func_name, 'addr': hex(addr)})
        return functions

    # call graph
    def cg_graph(self, verbose=True):
        cfg = CFGAnalyze.emulated_cg(self.angr_proj.proj, self.func_addr)

        # 将函数调用关系图生成到一个随机文件名的 png 中
        graph_file = os.path.join(MyPath.temporary(), StrUtils.uuid_str())
        # graph_file = StrUtils.uuid_str()
        set_plot_style('kyle')
        plot_cg(self.angr_proj.proj.kb, graph_file, format="png", verbose=verbose)

        # 读取文件内容的b64编码结果并返回
        contents = MyFile.read_and_b64encode(graph_file + '.png')
        return contents

    # control flow graph
    def cfg_graph(self, verbose=True):
        cfg = CFGAnalyze.emulated_normal(self.angr_proj.proj, self.func_addr)
        # 将控制流程图生成到一个随机文件名的 png 中
        graph_file = os.path.join(MyPath.temporary(), StrUtils.uuid_str())
        set_plot_style('kyle')
        plot_cfg(cfg, graph_file, asminst=True, vexinst=False,
                 # func_addr={self.func_addr: True},
                 debug_info=verbose, remove_imports=True, remove_path_terminator=True, color_depth=True)

        # 读取文件内容的b64编码结果并返回
        return MyFile.read_and_b64encode(graph_file + '.png')

    # control dependence graph
    def cdg_graph(self):
        project = self.angr_proj.proj
        cfg = CFGAnalyze.emulated_normal(self.angr_proj.proj, self.func_addr)
        cdg = project.analyses.CDG(cfg=cfg, start=self.func_addr)

        # 将控制依赖图生成到一个随机文件名的 png 中
        graph_file = os.path.join(MyPath.temporary(), StrUtils.uuid_str())
        plot_cdg(cfg, cdg, graph_file, pd_edges=True, cg_edges=True)

        # 读取文件内容的b64编码结果并返回
        return MyFile.read_and_b64encode(graph_file + '.png')

    def func_successors(self):
        cfg = self.cfg
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

    def _get_function_block(self):
        # 获取函数的代码块
        block = self.angr_proj.proj.factory.block(self.func_addr)

        # pretty-print，代码需要保留以作参考
        # print(block.pp())
        return block

    def function_asm(self):
        block = self._get_function_block()

        # 取 capstone 汇编代码
        # print(block.capstone)
        return block.capstone

    def function_vex(self):
        block = self._get_function_block()

        # 取 VEX IR，相对汇编语言，VEX IR更像是Compiler的中间语言
        # print(block.vex)
        return block.vex

    def _file_name(self):
        file_name = FwFilesStorage.export(self.file_id)
        return os.path.basename(file_name)

    def function_name(self):
        if self.func is None:
            return ''
        return self.func.name
        # 检查指定函数的节点是否存在（即函数地址是否有效）
        # node = self.cfg.model.get_any_node(self.func_addr)
        # if node is None:
        #     return ''
        # return node.name

    def function_codes(self):
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

    # calling_convention: SimCCSystemVAMD64
    # alignment
    # code_constants
    # has_return
    # local_runtime_values
    # name
    # arguments
    # num_arguments
    # ret_sites
    # returning
    # size
    def get_props(self):
        func = self.func
        if len(func.ret_sites) > 0:
            ret_addr = hex(func.ret_sites[0].addr)
        else:
            ret_addr = 'None'
        return {'name': func.name,
                'addr': hex(func.addr),
                'size': func.size,
                'calling_convention': func.calling_convention,
                'arguments': func.arguments,
                'num_arguments': func.num_arguments,
                'alignment': func.alignment,
                # 'code_constants': func.code_constants,
                # local_runtime_values 是 set，不能直接进行 JSON 序列化
                # 'local_runtime_values': func.local_runtime_values,
                'has_return': func.has_return,
                # 'ret_sites': func.ret_sites,
                'ret_addr': ret_addr,
                'returning': func.returning,
                }

    def decompiler(self):
        cfg = self.cfg
        func = self.func
        if func is None:
            return ''
        else:
            try:
                dec = self.angr_proj.proj.analyses.Decompiler(func, cfg=cfg)
                # print(dec.codegen.text)
                return dec.codegen.text
            except StopIteration as no_iter:
                return ''
