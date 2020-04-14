import os

from fw_analyze.service.load_default_pack import LoadDefaultPack
from utils.fs.pack_files import PackFiles
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p, sys_app_err


def test_pack_extract_bat(request):
    pack_index = ReqParams.one(request, 'pack_index.int')
    id_list = LoadDefaultPack.load_default_real_packs([pack_index])
    return sys_app_ok_p({'pack_id_list': id_list})


def test_add_single_exec(request):
    file_name = ReqParams.one(request, 'file_name')

    pack_infos = LoadDefaultPack.load_default_virtual_packs(file_name)

    return sys_app_ok_p(pack_infos)


def test_pack_verify_file_type(request):
    pack_id = ReqParams.one(request, 'pack_id')

    task_id = PackFiles.start_exec_bin_verify_task(pack_id)

    return sys_app_ok_p(task_id)

