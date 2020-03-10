class FwEntryState:
    def __init__(self, angr_proj):
        # 取 angr 的 project
        self.proj = angr_proj.proj

        # 模块入口的模拟程序状态机
        self.entry_state = entry_state = self.proj.factory.entry_state()
        # print(entry_state)

        # 取状态机的寄存器
        self.regs = entry_state.regs
        # print('寄存器rip：', entry_state.regs.rip, '寄存器rax：', entry_state.regs.rax)

        # 入口点的内存解析成 int 值
        self.entry_addr = entry_state.mem[self.proj.entry].int.resolved
        # print('入口点内存值：', entry_state.mem[self.proj.entry].int.resolved)

        # 取堆信息
        self.heap_base = hex(entry_state.heap.heap_base)
        self.heap_size = hex(entry_state.heap.heap_size)
        # print('堆基址：', hex(entry_state.heap.heap_base))
        # print('堆大小：', hex(entry_state.heap.heap_size))

    def entry_info(self):
        reg_list = self._get_regs(self.regs)
        return {'entry_addr': self.bvv2hex(self.entry_addr), 'regs_count': len(reg_list), 'regs': reg_list,
                'heap_base': self.heap_base, 'heap_size': self.heap_size}
        # return {'entry_addr': self.bvv2hex(self.entry_addr), 'heap_base': self.heap_base,
        #         'heap_size': self.heap_size}

    def bvv2int(self, bvv):
        value = self.entry_state.solver.eval(bvv)
        return value

    def bvv2hex(self, bvv):
        value = self.bvv2int(bvv)
        return hex(value)

    def int2bvv(self, int_value):
        bvv = self.entry_state.solver.BVV(int_value, 64)
        return bvv

    def _get_regs(self, regs):
        reg_list = {}
        props = dir(regs)
        for reg_tag in props:
            bvv = getattr(regs, reg_tag)
            reg_list[reg_tag] = self.bvv2hex(bvv)
        return reg_list
