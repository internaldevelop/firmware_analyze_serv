class FwEntryState:
    def __init__(self, angr_proj):
        # 取 angr 的 project
        self.proj = angr_proj.proj

        # 保存系统架构、是否JAVA程序
        self.arch = self.proj.arch
        self.is_java = self.proj.is_java_project

        # 模块入口的模拟程序状态机
        self.entry_state = entry_state = self.proj.factory.entry_state()
        # print(entry_state)

        # 取状态机的寄存器
        self.regs = entry_state.regs
        # print('寄存器rip：', entry_state.regs.rip, '寄存器rax：', entry_state.regs.rax)

        # 入口点的内存解析成 int 值
        self.entry_addr = entry_state.mem[self.proj.entry].int.resolved
        # print('入口点内存值：', entry_state.mem[self.proj.entry].int.resolved)

        # 取堆信息：堆基址，堆大小，内存映射基址（base of mmap area）
        self.heap_base = hex(entry_state.heap.heap_base)
        self.heap_size = hex(entry_state.heap.heap_size)
        self.mmap_base = hex(entry_state.heap.mmap_base)
        # print('堆基址：', hex(entry_state.heap.heap_base))
        # print('堆大小：', hex(entry_state.heap.heap_size))

    def entry_info(self):
        reg_list = self._get_regs(self.regs)
        return {'entry_addr': self.bvv2hex(self.entry_addr), 'arch': self._get_arch_info(),
                'heap_base': self.heap_base, 'heap_size': self.heap_size, 'mmap_base': self.mmap_base,
                'stack_size': hex(self.arch.stack_size), 'regs_count': len(reg_list), 'regs': reg_list,}

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

    # name:   'AMD64'
    # instruction_endness:   'Iend_BE'
    # linux_name:  'x86_64'
    # stack_size: 134217728
    # vex_arch:  'VexArchAMD64'
    # vex_endness: 'VexEndnessLE'
    # sizeof:  {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    # default_symbolic_registers: ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10',
    #       'r11', 'r12', 'r13', 'r14', 'r15', 'rip']
    # default_register_values:  [('rsp', 576460752303357952, True, 'global'), ('cc_op', 0, False, None),
    #       ('d', 1, False, None), ('fs', 10376293541461622784, True, 'global'), ('sseround', 0, False, None),
    #       ('ftop', 0, False, None), ('fptag', 0, False, None), ('fpround', 0, False, None)]
    # bits: 64
    def _get_arch_info(self):
        arch = self.arch
        return {
            'arch_name': arch.name,
            'bits': arch.bits,
            'linux_name': arch.linux_name,
            'instruction_endness': arch.instruction_endness,
            'vex_arch': arch.vex_arch,
            'vex_endness': arch.vex_endness,
            'size_of_value': arch.sizeof,
            'default_symbolic_registers': arch.default_symbolic_registers,
            # 'default_register_values': arch.default_register_values, # 数值太大了，超过数据库 8 字节整数的限制
        }
