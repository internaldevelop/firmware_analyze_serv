import uuid
from angrutils import hook0, plot_cg
from utils.gadget.strutil import StrUtils


class FwFuncParse:

    def __init__(self, angr_proj):
        # 取 angr 的 project
        self.functions = []
        self.angr_proj = angr_proj

    def func_list(self):
        self.functions.clear()
        self.angr_proj.call_cfg(cfg_mode='cfg_fast')

        # 取函数列表
        functions = self.angr_proj.proj.kb.functions.items()
        # total_len = len(functions)
        for addr, func in functions:
            # 记录函数地址和函数名称
            self.functions.append({'name': func.name, 'addr': hex(addr)})
            # print(hex(addr), func.name)
        return self.functions

    def _test_successors(self, cfg, node):
        successors = list(cfg.graph.successors(node))
        while successors is not None and len(successors) > 0:
            for succ_node in successors:
                print('Parent: {}({}),\tChild: {}({})'.format(node.name, node.addr, succ_node.name, succ_node.addr))
                self._test_successors(cfg, succ_node)

    def func_successors(self, func_addr):
        # 仿真模式解析代码
        cfg = self.angr_proj.call_cfg(start_addr=[func_addr])
        if cfg is None:
            return []

        # 获取指定函数的节点对象
        node = cfg.model.get_any_node(func_addr)
        if node is None:
            return []

        # 测试用
        # self._test_successors(cfg, node)
        # for function_addr in cfg.kb.functions

        # 取函数的后继调用的地址列表
        successors = list(cfg.kb.callgraph.successors(func_addr))
        succ_func_list = []
        for succ_addr in successors:
            # 根据地址获取节点
            succ_node = cfg.model.get_any_node(succ_addr)
            # 伪节点，非函数地址，再找下一级
            if succ_node.name is None:
                # temp1 = list(cfg.kb.callgraph.successors(succ_node.addr))
                # t1 = cfg.model.get_any_node(temp1[0])
                # temp_node1 = list(cfg.kb.callgraph.successors(succ_node.addr))[0]
                # temp_node2 = list(cfg.graph.successors(succ_node))[0]
                # succ_node = cfg.model.get_any_node(temp_node2.addr)

                # 有函数名称为 PathTerminator，不知何故
                succ_node = list(cfg.graph.successors(succ_node))[0]

            succ_func_list.append({'name': succ_node.name, 'addr': hex(succ_node.addr)})

        return succ_func_list


        # 废弃
        # # 取函数的后继调用
        # successors = list(cfg.graph.successors(node))
        # succ_func_list = []
        # if len(successors) > 0:
        #     # print('\t%d:\t' % len(successors), end='')
        #     for succ_node in successors:
        #         # 伪节点，非函数地址
        #         if succ_node.name is None:
        #             continue
        #         # 或者含加号，需要再找下一级，才是真实的调用函数：
        #         # "Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback+0x11"
        #         if '+' in succ_node.name:
        #             succ_node = list(cfg.graph.successors(succ_node))[0]
        #
        #         succ_func_list.append({'name': succ_node.name, 'addr': hex(succ_node.addr)})
        #         # print(succ_node, '\t', end='')
        #     # print('', end='\n')
        # return succ_func_list

    def func_asm(self, func_addr):
        # 获取函数的代码块
        block = self.angr_proj.proj.factory.block(func_addr)

        # 关闭 pretty-print，代码需要保留以作参考
        # print(block.pp())

        # 取 capstone 汇编代码
        # print(block.capstone)
        asm = block.capstone
        return asm

    def func_vex(self, func_addr):
        # 获取函数的代码块
        block = self.angr_proj.proj.factory.block(func_addr)

        # 取 VEX IR，相对汇编语言，VEX IR更像是Compiler的中间语言
        # print(block.vex)
        vex = block.vex
        return vex

    def call_graph(self, func_addr, verbose=True):
        proj = self.angr_proj.proj
        # 初始化状态机
        start_state = proj.factory.blank_state(addr=func_addr)
        start_state.stack_push(0x0)

        # 仿真模式解析代码
        cfg = self.angr_proj.call_cfg(start_addr=[func_addr])

        # 将函数关系图生成到一个随机文件名的 png 中
        graph_file = StrUtils.uuid_str()
        plot_cg(proj.kb, graph_file, format="png", verbose=verbose)

        # 读取文件
        try:
            with open(graph_file + '.png', 'rb') as fp:
                return fp.read()
        except (OSError, IOError):
            return None

    #
    # Properties
    #

    # @property
    # def count(self):
    #     """
    #     函数列表中所有函数的总和
    #     :return: An integer
    #     """
    #     return len(self.functions)
