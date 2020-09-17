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


class Overflow_Detect:

    def __init__(self, file_id):
        # 创建一个空 project 对象
        self.angr_proj = AngrProj(file_id, cfg_mode='None')
        project = self.angr_proj.proj
        if project is None:
            return
        self.file_id = file_id

    def detect(self):
        type_name, buffer_overflow = Overflow_Detect.buffer_overflow(self)
        FwFileDO.set_file_detect_overflow(self.file_id, buffer_overflow, None, None)
        return buffer_overflow

    def integer_overflow(self):
        return False

    def command_injection_overflow(self):
        return False

    def buffer_overflow(self):
        print("finding the buffer overflow...")
        # 默认情况下丢弃无约束的路径，需要指定save_unconstrained选项为true，即，保存无约束的状态
        sm = self.angr_proj.proj.factory.simulation_manager(save_unconstrained=True)
        # symbolically execute the binary until an unconstrained path is reached
        while len(sm.unconstrained) == 0:   # 找到未约束状态
            info = sm.step()
            print(sm.active)
            print(info)
            if len(sm.active) == 0:
                return "缓冲区漏洞", ""
        unconstrained_state = sm.unconstrained[0]
        crashing_input = unconstrained_state.posix.dumps(0)
        # cat crash_input.bin | ./CADET_00001.adapted will segfault
        # with open('crash_input.bin', 'wb') as fp:
        #     fp.write(crashing_input)
        print("buffer overflow found!")
        # 找到了缓冲区溢出的地方，打印出溢出输入
        print(crashing_input)
        print(repr(crashing_input))

        return "缓冲区漏洞", repr(crashing_input)

    def buffer_overflow_1(self):
        # 寻找缓冲区溢出，其实就是指令指针IP为一个符号值，它被用户输入的符号值覆盖。这时将返回一个不受约束的状态，因为IP为符号值，有多种可能，符号执行无法确定下一步执行地址，这一状态就是无约束状态。
        #
        # 此时，需要指定save_unconstrained选项为true，即，保存无约束的状态。
        #
        # 启动符号执行，直到到达一个无约束的状态，此时就找到了缓冲区溢出的地方，打印出溢出输入。
        #
        # 寻找彩蛋的时候，我们希望避免不可行路径。默认的情况下，lazy solving是启动的，也就是说此时angr不会自动丢弃不可行路径。所以，需要我们创建一个状态，指定关闭lazy solving选项，然后以这个状态为初始状态启动。
        #
        # 找到打印彩蛋的字符串的位置，输出此时found.posix.dumps的值。

        print("finding the buffer overflow...")
        # 默认情况下丢弃无约束的路径，需要指定save_unconstrained选项为true，即，保存无约束的状态
        sm = self.angr_proj.proj.factory.simulation_manager(save_unconstrained=True)
        exploitable_state = None
        while exploitable_state is None:
            print(sm)
            sm.step()   # Step a stash of states forward and categorize the successors appropriately.
            if len(sm.unconstrained) > 0:   # 找到未约束状态
                # l.info("found some unconstrained states, checking exploitability")
                for u in sm.unconstrained:
                    if Overflow_Detect.fully_symbolic(u, u.regs.pc):   # 判断是否为可利用状态
                        exploitable_state = u   # 获得可利用状态
                        break

            # no exploitable state found, drop them
            sm.drop(stash='unconstrained')  # 删除 unconstrained stash 中的状态
        unconstrained_state = sm.unconstrained[0]
        crashing_input = unconstrained_state.posix.dumps(0)
        return "缓冲区漏洞", repr(crashing_input)

    def fully_symbolic(state, variable): # 判断 state 的 variable 是否为符号化
        # check if a symbolic variable is completely symbolic
        for i in range(state.arch.bits):  # 总共需要判断 arch.bits 位
            if not state.solver.symbolic(variable[i]):  # 判断variable[i]是否为符号化
                return False
        return True

