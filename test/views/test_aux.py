from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.sys_config import SystemConfig
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
