import os
import angr
import binwalk

from utils.const.file_type import FileType
from utils.gadget.my_path import MyPath
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok, sys_app_ok_p


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
    project = angr.Project(file_path, load_options={'auto_load_libs': False})

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

    # idfer = project.analyses.Identifier()
    # functions = []
    # for func in idfer.func_info:
    #     functions.append({'addr': hex(func.addr), 'name': func.name})
    #
    # return sys_app_ok_p({'count': len(functions), 'functions': functions})
