import angr


class FwFuncParse:

    def __init__(self, angr_proj):
        # 取 angr 的 project
        self.proj = angr_proj.proj
        self.cfg = angr_proj.cfg

        # 取函数列表
        functions = self.proj.kb.functions.items()
        # total_len = len(functions)
        self.functions = []
        for addr, func in functions:
            # 记录函数地址和函数名称
            self.functions.append({'name': func.name, 'addr': hex(addr)})
            # print(hex(addr), func.name)

    def func_list(self):
        return self.functions

    def func_successors(self, func_addr):
        cfg = self.cfg
        if cfg is None:
            return []

        # 获取指定函数的节点对象
        node = cfg.model.get_any_node(func_addr)
        if node is None:
            return []

        # 取函数的后继调用
        successors = list(cfg.graph.successors(node))
        succ_func_list = []
        if len(successors) > 0:
            # print('\t%d:\t' % len(successors), end='')
            for succ_node in successors:
                succ_func_list.append({'name': succ_node.name, 'addr': hex(succ_node.addr)})
                # print(succ_node, '\t', end='')
            # print('', end='\n')
        return succ_func_list

    def func_asm(self, func_addr):
        # 获取函数的代码块
        block = self.proj.factory.block(func_addr)

        # 关闭 pretty-print，代码需要保留以作参考
        # print(block.pp())

        # 取 capstone 汇编代码
        # print(block.capstone)
        asm = block.capstone
        return asm

    def func_vex(self, func_addr):
        # 获取函数的代码块
        block = self.proj.factory.block(func_addr)

        # 取 VEX IR，相对汇编语言，VEX IR更像是Compiler的中间语言
        # print(block.vex)
        vex = block.vex
        return vex

    #
    # Properties
    #

    @property
    def count(self):
        """
        函数列表中所有函数的总和
        :return: An integer
        """
        return len(self.functions)
