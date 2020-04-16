from angrutils import hook0

from angr_helper.angr_proj import AngrProj


class CFGAnalyze:
    @staticmethod
    def emulated_cg(project, func_addr):
        with hook0(project):
            return project.analyses.CFGEmulated(fail_fast=False, starts=[func_addr],
                                                context_sensitivity_level=1,
                                                enable_function_hints=False, keep_state=True,
                                                enable_advanced_backward_slicing=False,
                                                enable_symbolic_back_traversal=False,
                                                normalize=True)

    @staticmethod
    def emulated_normal(project, func_addr):
        # 初始化状态机
        start_state = AngrProj.project_start_state(project, func_addr)
        with hook0(project):
            return project.analyses.CFGEmulated(fail_fast=True, starts=[func_addr],
                                                initial_state=start_state,
                                                context_sensitivity_level=2,
                                                keep_state=True, call_depth=100,
                                                normalize=True)
