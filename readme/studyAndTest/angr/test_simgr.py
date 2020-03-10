import os
import angr

root_path = os.path.dirname(os.path.realpath(__file__))
samples_path = os.path.join(root_path, 'samples')


def simgr_ops(proj):
    # 模块入口的模拟程序状态机
    entry_state = proj.factory.entry_state()

    # 以入口状态机为起点生成虚拟管理器
    simgr = proj.factory.simgr(entry_state)
    print(simgr)

    print('步进前，虚拟机激活点：', simgr.active)
    print('步进前，虚拟机rip：', simgr.active[0].regs.rip)
    print('步进前，状态机rip：', entry_state.regs.rip)
    # 虚拟的状态机运行一步（步进）
    simgr.step()
    print('步进后，虚拟机激活点：', simgr.active)
    print('步进后，虚拟机rip：', simgr.active[0].regs.rip)
    print('步进后，状态机rip：', entry_state.regs.rip)

    return


def test_simgr():
    proj = angr.Project(os.path.join(samples_path, 'ais3_crackme'), load_options={'auto_load_libs': False})

    simgr_ops(proj)


if __name__ == "__main__":
    test_simgr()