from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.sys_config import SystemConfig
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


def test_file_type(request):
    files_list = ['image.bmp', 'image.gif', 'image.jpg', 'image.png', 'image.tif', 'image2.png',
                  'office.docx', 'office.pptx', 'office.xlsx', 'office2.docx', 'office2.xlsx',
                  'pdf.pdf', 'text.js', 'text.py', 'text.txt', 'zip.zip',
                  ]

    types_list = []
    for file_name in files_list:
        file_path = os.path.join(MyPath.samples(), 'bin', file_name)
        file_type = FileTypeJudge.scan_file_type(file_path, quiet=False)
        types_list.append({'file_name': file_name, 'file_type': file_type, 'type_name': FileType.get_alias(file_type)})

    return sys_app_ok_p(types_list)
