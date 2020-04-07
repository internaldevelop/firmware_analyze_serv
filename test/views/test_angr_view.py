import os
import angr
import binwalk

from utils.gadget.my_path import MyPath
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok, sys_app_ok_p


def test_bin_info(request):
    file_name, load_options = ReqParams.many(request, ['file_name', 'load_options.int'])
    file_path = os.path.join(MyPath.samples(), 'bin', file_name)

    # bw_result = binwalk.scan(file_path, signature=True, opcodes=True)
    bw_result = binwalk.scan('--signature', '--opcodes', file_path)
    # bw_result = binwalk.scan('--signature', file_path)
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
