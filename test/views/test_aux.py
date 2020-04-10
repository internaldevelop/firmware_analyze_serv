from test.service.test_modules_service import TestModulesService
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.sys_config import SystemConfig
from utils.fs.fs_base import FsBase
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.file_type_judge import FileTypeJudge
from utils.gadget.my_file import MyFile
from utils.fs.fs_image import FsImage
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.http.response import sys_app_ok_p, sys_app_ok, sys_app_err
from utils.http.request import ReqParams
import os

from utils.const.file_type import FileType


def test_generate_uuid(request):
    return sys_app_ok_p(StrUtils.uuid_str())


def test_log_switch(request):
    log_configs = SystemConfig.get_cache_log_cfg()
    keys = log_configs.keys()
    for category in keys:
        LogRecords.save('test_log_switch: ' + category, category=category, action='test_log_switch')
    return sys_app_ok()


def test_check_file_type(request):
    category = ReqParams.one(request, 'category')

    if len(category) == 0:
        # 未指定检查类型时，可执行文件和非可执行都检测一遍
        check_exec = check_no_exec = True
    elif category == '1':
        # 指定'1'时，只检测非可执行文件
        check_exec = False
        check_no_exec = True
    elif category == '2':
        # 指定'2'时，只检测可执行文件
        check_exec = True
        check_no_exec = False
    else:
        return sys_app_ok_p('category=1，检测非可执行文件；category=2，检测可执行文件；category为空时，检测全部文件')

    results = []

    if check_no_exec:
        files_list = ['image.bmp', 'image.gif', 'image.jpg', 'image.png', 'image.tif', 'image2.png',
                      'office.docx', 'office.pptx', 'office.xlsx', 'office2.docx', 'office2.xlsx',
                      'pdf.pdf', 'text.js', 'text.py', 'text.txt', 'zip.zip', 'zip2.zip', 'rar.rar',
                      '7z.7z', 'tar.tar'
                      ]

        for file_name in files_list:
            file_path = os.path.join(MyPath.samples(), 'bin', file_name)
            file_type, extra_props = FileTypeJudge.scan_file_type(file_path, quiet=False)
            results.append({'file_name': file_name, 'file_type': file_type, 'type_name': FileType.get_alias(file_type)})

    if check_exec:
        files_list = ['libebt_standard.so', 'bash', 'regedit.exe', 'opkg', 'polkitd', 'true', 'ais3_crackme',
                      'r100', 'AcXtrnal.dll', 'WdNisDrv.sys',
                      ]

        for file_name in files_list:
            file_path = os.path.join(MyPath.samples(), 'bin', file_name)
            file_type, extra_props = FileTypeJudge.scan_file_type(file_path, quiet=False)
            if file_type == FileType.EXEC_FILE:
                arch, endianness = ExecFile.parse_exec_arch(file_path, prefer=extra_props)
            else:
                arch = endianness = ''
            results.append({'file_name': file_name, 'file_type': file_type,
                            'type_name': FileType.get_alias(file_type),
                            'arch': arch, 'endianness': endianness,
                            })
            # break

    return sys_app_ok_p(results)


def test_list_file_types(request):
    names = FileType.names_list()
    values = FileType.values_list()
    kv_set = FileType.kv_list()

    return sys_app_ok_p({'names': names, 'values': values, 'dict': kv_set})


def test_modules(request):
    TestModulesService.test_verify_file_type_and_write_file()
    return sys_app_ok()
