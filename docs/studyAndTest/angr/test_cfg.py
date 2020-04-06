import os
import angr
from angrutils import hook0, plot_cfg
from angr.knowledge_plugins.cfg import CFGNode, CFGModel, MemoryDataSort

root_path = os.path.dirname(os.path.realpath(__file__))
samples_path = os.path.join(root_path, 'samples')


def old_cfg_analyze(proj, name='bin'):
    # main 函数的符号对象
    main_symbol = proj.loader.main_object.get_symbol('main')
    # main 函数的状态机对象
    start_addr = main_symbol.rebased_addr
    start_state = proj.factory.blank_state(addr=start_addr)
    start_state.stack_push(0x0)
    # with hook0(proj):
    #     cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[start_addr], initial_state=start_state,
    #                                     context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
    # cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, force_complete_scan=False, normalize=True)
    cfg = proj.analyses.CFGFast()
    count = 1
    for addr, func in proj.kb.functions.items():
        print(func.name)
        if func.name in ['main', 'verify', 'puts']:
            count += 1
            plot_cfg(cfg, "%s_%s_cfg" % (name, str(count)), asminst=True, vexinst=False, func_addr={addr: True},
                     debug_info=False, remove_imports=True, remove_path_terminator=True)
            # plot_cfg(cfg, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False, func_addr={addr: True},
            #         debug_info=False, remove_imports=True, remove_path_terminator=True)
    return


def cfg_analyze(proj):
    # 模块的架构
    print(proj.arch)

    # 快速模式生成 CFG
    cfg = proj.analyses.CFGFast()
    # 取模块的整张图
    model_graph = cfg.model.graph
    graph = cfg.graph
    # 取节点列表（节点多于函数）
    nodes = graph.nodes
    total_len = len(nodes)
    # 关闭简化输出，代码需要保留以作参考
    # for node in nodes:
    #     print(hex(node.addr), node.name)

    # TODO: VFG 用于变量流转分析
    node = cfg.model.get_any_node(proj.entry)
    vfg = proj.analyses.VFG(start=node.addr)
    # variable_seekr = angr.VariableSeekr(proj, cfg, vfg)

    # 取函数列表
    functions = proj.kb.functions.items()
    total_len = len(functions)
    for addr, func in functions:
        # 打印函数地址和函数名称
        print(hex(addr), func.name)

        # 取函数的后继调用
        # node = cfg.model.get_any_node(addr)
        # if node is not None:
        #     successors = list(cfg.graph.successors(node))
        #     if len(successors) > 0:
        #         print('\t%d:\t' % len(successors), end='')
        #         for succ_node in successors:
        #             print(succ_node, '\t', end='')
        #         print('', end='\n')

        # # 获取函数的代码块
        # block = proj.factory.block(addr)
        # # 关闭简化输出，代码需要保留以作参考
        # # 取汇编代码
        # print(block.pp())
        # # 取 capstone 汇编代码
        # print(block.capstone)
        # # 取 VEX IR，相对汇编语言，VEX IR更像是Compiler的中间语言
        # print(block.vex)

    # 取通用库函数的方法（使用标识 Identifier）
    # proj = angr.Project(os.path.join(samples_path, 'true'))
    # idfer = proj.analyses.Identifier()
    # for addr, symbol in idfer.run():
    #     print(hex(addr), symbol)

    return


def state_analyze(proj):
    # 模块入口的模拟程序状态机
    entry_state = proj.factory.entry_state()
    print(entry_state)

    # 取状态机的寄存器
    print('寄存器rip：', entry_state.regs.rip, '寄存器rax：', entry_state.regs.rax)
    # 入口点的内存解析成 int 值
    print('入口点内存值：', entry_state.mem[proj.entry].int.resolved)
    # 取堆信息
    print('堆基址：', hex(entry_state.heap.heap_base))
    print('堆大小：', hex(entry_state.heap.heap_size))

    # BV 和 int 类型互相转换
    bv = entry_state.solver.BVV(0x1234, 32)
    print('BVV: ', bv)
    print('int: ', entry_state.solver.eval(bv))
    # 另一种转换方式： int ==> BV
    entry_state.mem[0x1000].long = 4
    print('BVV: ', entry_state.mem[0x1000].long.resolved)

    # 用BVV值设置寄存器
    print('rsi before set: ', entry_state.regs.rsi)
    entry_state.regs.rsi = entry_state.solver.BVV(3, 64)
    print('rsi after set: ', entry_state.regs.rsi)

    return


def test_cfg():
    proj = angr.Project(os.path.join(samples_path, '../../../files/samples/ais3_crackme'), load_options={'auto_load_libs': False})

    cfg_analyze(proj)

    state_analyze(proj)


if __name__ == "__main__":
    test_cfg()
