import os
import angr
import binwalk
from angr.knowledge_plugins.variables import VariableType
from angrutils import hook0, plot_cfg

from angr_helper.function_parse import FunctionParse
from angr_helper.vars_recovery import VarsRecovery
from utils.const.file_type import FileType
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok, sys_app_ok_p, sys_app_err_p


def test_bin_info(request):
    file_name, load_options = ReqParams.many(request, ['file_name', 'load_options.int'])
    file_path = os.path.join(MyPath.samples(), 'bin', file_name)

    # bw_result = binwalk.scan(file_path, signature=True, opcodes=True)
    bw_result = binwalk.scan('--signature', '--opcodes', file_path)
    bw_result = binwalk.scan('--signature', file_path)
    return sys_app_ok_p({})

    if load_options == 1:
        proj = angr.Project(file_path, load_options={
            'main_opts': {
                'backend': 'blob',
                'base_addr': 0x10000,
                'entry_point': 0x10000,
                'arch': 'ARM',
                'offset': 0,
            }
        })
    else:
        # proj = angr.Project(file_path)
        proj = angr.Project(file_path, load_options={'auto_load_libs': False, 'main_opts': {}, })

    boyscout = proj.analyses.BoyScout()

    # proj2 = angr.Project(file_path, arch=angr.SimARM(endness="Iend_BE"),
    #                      load_options={
    #                          'backend': 'blob',
    #                          'base_addr': 0x10000,
    #                          'entry_point': 0x10000,
    #                          'arch': 'ARM',
    #                          'offset': 0,
    #                      })
    # girlscout = proj2.analyses.GirlScout(pickle_intermediate_results=True)
    return sys_app_ok_p({'arch': boyscout.arch, 'endianness': boyscout.endianness})


def test_angr_cfg(request):
    file_name = ReqParams.one(request, 'file_name')


    file_path = os.path.join(MyPath.samples(), file_name)
    project = angr.Project(file_path, load_options={'auto_load_libs': False})
    main_symbol = project.loader.main_object.get_symbol('main')
    start_addr = main_symbol.rebased_addr
    start_state = project.factory.blank_state(addr=start_addr)
    start_state.stack_push(0x0)
    project.factory.full_init_state(add_options={angr.options.STRICT_PAGE_ACCESS, angr.options.ENABLE_NX,
                                         angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.USE_SYSTEM_TIMES})
    cfg = project.analyses.CFG()
    functions = cfg.kb.functions
    return sys_app_ok_p(functions)


def test_angr_functions(request):
    file_name = ReqParams.one(request, 'file_name')
    file_path = os.path.join(MyPath.samples(), file_name)
    # --disasm
    # bw_result = binwalk.scan('--signature', file_path)
    # bw_result = binwalk.scan('--signature', '--opcodes', file_path)
    # bw_result = binwalk.scan('--signature', '--opcodes', '--disasm', file_path)
    # bw_result = binwalk.scan('--signature', '--disasm', file_path)
    # bw_result = binwalk.scan('--signature', '--opcodes', '--disasm', '--verbose', file_path)

    project = angr.Project(file_path, load_options={'auto_load_libs': False})
    # project = angr.Project(file_path, load_options={
    #     'auto_load_libs': False,
    #     'main_opts': {
    #         'backend': 'blob',
    #         'base_addr': 0x10000,
    #         'entry_point': 0x10000,
    #         'arch': 'MIPS32',
    #         'offset': 0,
    #     }
    # })

    cfg = project.analyses.CFGFast(resolve_indirect_jumps=True, force_complete_scan=False, normalize=True,
                                   # context_sensitivity_level=1,
                                   # enable_advanced_backward_slicing=False,
                                   # enable_symbolic_back_traversal=False
                                   )
    items = cfg.kb.functions.items()

    functions = []
    for addr, func in items:
        func_name = func.name
        if func_name == 'UnresolvableJumpTarget' or func_name == 'UnresolvableCallTarget':
            continue
        functions.append({'address': hex(addr), 'name': func.name})

    return sys_app_ok_p({'count': len(functions), 'functions': functions})


def test_angr_plot_graph(request):
    file_id, file_name, func_addr = ReqParams.many(request, ['file_id', 'file_name', 'func_addr.hex'])
    if len(file_id) == 0:
        if len(file_name) == 0:
            return sys_app_err_p('INVALID_REQ_PARAM', 'file_id 或 file_name 必填其一')
        file_path = os.path.join(MyPath.samples(), file_name)
        project = angr.Project(file_path, load_options={'auto_load_libs': False})
        start_state = project.factory.blank_state(addr=func_addr)
        start_state.stack_push(0x0)
        with hook0(project):
            cfg = project.analyses.CFGEmulated(fail_fast=True, starts=[func_addr], initial_state=start_state,
                                         context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
        graph_file = os.path.join(MyPath.temporary(), StrUtils.uuid_str())
        plot_cfg(cfg, graph_file, asminst=True, vexinst=False, func_addr={func_addr: True},
                 debug_info=False, remove_imports=True, remove_path_terminator=True)
    else:
        func_parse = FunctionParse(file_id, func_addr)
        content = func_parse.cfg_graph()

    return sys_app_ok()


# A program slice is a subset of statements that is obtained from the original program,
# usually by removing zero or more statements.
def test_angr_backward_slice(request):
    file_name, func_addr = ReqParams.many(request, ['file_name', 'func_addr.hex'])
    file_path = os.path.join(MyPath.samples(), file_name)

    project = angr.Project(file_path, load_options={"auto_load_libs": False})

    cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
                                       context_sensitivity_level=2)

    cdg = project.analyses.CDG(cfg)

    ddg = project.analyses.DDG(cfg)

    target_node = cfg.get_any_node(func_addr)
    bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[(target_node, -1)])
    # bs.dbg_repr()

    node_has_type = False
    for node in bs.taint_graph.nodes():
        # param taint_type: Type of the taint, might be one of the following: 'reg', 'tmp', 'mem'.
        # print(node.stmt_idx)
        if hasattr(node, 'type'):
            print(node.type)
            node_has_type = True
        # if n.type == taint_type and n.addr == simrun_addr and n.stmt_id == stmt_idx:
        #     taint = n
    print('node type %s found' % ('' if node_has_type else 'not'))

    # VSA_DDG
    # vsa_ddg = project.analyses.VSA_DDG()
    return sys_app_ok()


def test_angr_vars(request):
    file_id, file_name, func_addr = ReqParams.many(request, ['file_id', 'file_name', 'func_addr.hex'])
    file_path = os.path.join(MyPath.samples(), 'armel', file_name)

    vr = VarsRecovery(file_id, func_addr)
    vars_list = vr.vars()
    return sys_app_ok_p(vars_list)

    # # project = angr.Project(file_path, arch=angr.SimARM(endness="Iend_LE"))
    # project = angr.Project(file_path)
    # cfg = project.analyses.CFG(normalize=True)
    #
    # func = cfg.kb.functions.function(addr=func_addr)
    #
    # tmp_kb = angr.KnowledgeBase(project)
    #
    # print("Running VariableRecovery on function %r." % func)
    # # vr = project.analyses.VariableRecoveryFast(func, kb=tmp_kb)
    # vr = project.analyses.VariableRecovery(func, kb=tmp_kb)
    #
    # variable_manager = vr.variable_manager[func.addr]
    #
    # for var_sort in [VariableType.MEMORY, VariableType.REGISTER]:
    #     vars_and_offset = variable_manager.find_variables_by_insn(func.addr, var_sort)
    #     for the_var, _ in vars_and_offset:
    #         print(the_var)
    #         print(the_var.name)

    # return sys_app_ok()

    # idfer = project.analyses.Identifier()
    # functions = []
    # for func in idfer.func_info:
    #     functions.append({'addr': hex(func.addr), 'name': func.name})
    #
    # return sys_app_ok_p({'count': len(functions), 'functions': functions})
