import time
import datetime
import os
import utils.sys.config
from django.conf import settings

from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFile
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.file.my_file import MyFile
from utils.gadget.strutil import StrUtils
from utils.http.response import app_ok_p, app_err_p, app_ok, app_err, sys_app_ok_p, sys_app_err_p, sys_app_ok, sys_app_err
from utils.http.http_request import req_get_param_int, req_get_param, req_post_param, req_post_param_int, req_post_param_dict
from utils.gadget.download import Mydownload
from utils.sys.file_type import FileType
from utils.task import MyTask
from utils.websocket.websocket import MyWebsocket
from utils.db.mongodb.mongo_db import MongoDB
from utils.db.mongodb.mongo_pocs import MongoPocs
from utils.gadget.general import SysUtils
from utils.mybinwalk.mybinwalk import MyBinwalk
from utils.squashfs.squashfs import MySquashfs


# firmware 信息集合
firmware_info_coll = utils.sys.config.g_firmware_info_col
# 任务集合
task_info_coll = utils.sys.config.g_task_info_col

# firmware 存储桶
method_fs = utils.sys.config.g_firmware_method_fs


def _init_task_info(task_id):
    # 初始化缓存的任务信息
    MyTask.init_exec_status(task_id)

    # 返回任务信息
    task_info = MyTask.fetch_exec_info(task_id)
    return task_info


# 固件下载
def async_fwdownload(request):

    # 获取下载URL
    fw_download_url = req_get_param(request, 'url')
    print(fw_download_url)

    # 启动下载任务
    task = MyTask(_proc_func_download, (fw_download_url, settings.FW_PATH, ))
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id }, category='download', action='下载固件',
                    desc='存储桶读取固件保存并进行文件抽取')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def _proc_func_download(fw_download_url, g_fw_save_path, task_id):
    # 检查本地保存路径 没有则创建
    SysUtils.check_filepath(g_fw_save_path)

    # 执行下载操作
    ret_download_info, fwfilename ,file_list = Mydownload.fwdownload(fw_download_url, g_fw_save_path, task_id)
    print(ret_download_info, fwfilename)

    # 保存到mongodb
    task_item = save_mongodb(fw_download_url, g_fw_save_path, fwfilename, ret_download_info, task_id)

    # websocket通知页面
    # ws = MyWebsocket()
    # ws.sendmsg(str(task_item))

    # MyWebsocket.sendmsg(str(task_item))


def save_mongodb(fw_download_url, fw_path, fw_filename, download_info, task_id):
    # 新建或保存文件记录
    # 新的 pack ID
    pack_id = StrUtils.uuid_str()
    # 新的 pack 文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取包文件内容
    contents = MyFile.read(fw_path + fw_filename)
    # 保存文件记录
    PackFile.save(pack_id, file_id, name=fw_filename, file_type=FileType.PACK.value)
    # 保存文件内容
    PackFilesStorage.save(file_id, fw_filename, FileType.PACK.value, contents)

    return

    # # 保存固件到mongodb 集合
    # fw_coll = MongoDB(firmware_info_coll)
    # firmware_id = fw_coll.get_suggest_firmware_id(None)
    # item = {
    #     'id': firmware_id,
    #     'fw_file_name': fw_filename,
    #     'application_mode': '',
    #     'fw_manufacturer': '',
    #     'url': fw_download_url
    # }
    # fw_coll.update(firmware_id, item)
    #
    # # 保存到存储桶
    # fw_pocs = MongoPocs(method_fs)
    # with open(fw_path + fw_filename, 'rb') as myimage:
    #     data = myimage.read()
    #     fw_pocs.add(firmware_id, fw_filename, data)
    #

    # task_coll = MongoDB(task_info_coll)
    #
    # # 保存下载任务到mongodb
    # task_item = {
    #     'task_id': task_id,
    #     'type': 'download',
    #     'time': datetime.datetime.now(),
    #     'percentage': '100',
    #     'status': download_info
    # }
    # task_coll.update(task_id, task_item)

    # return task_item


# 1.2 查询固件列表
def list(reuqest):
    # 获取信息总数
    fw_coll = MongoDB(firmware_info_coll)
    total = fw_coll.info_count()

    # 读取固件信息
    docs = fw_coll.query(0, total)
    return sys_app_ok_p({'total': total, 'count': len(docs), 'items': docs})


# 1.3 根据指定ID读取固件  将固件文件进行解压缩操作,提取文件目录到数据库
def async_funcs_fetch(request):
    # 获取固件ID
    firmware_id = req_get_param(request, 'firmware_id')

    # 启动任务 存储桶读取固件内容
    task = MyTask(_proc_fetch, (firmware_id, settings.FW_PATH))
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id, 'file_id': firmware_id}, category='fetch', action='下载固件',
                    desc='存储桶读取固件保存并进行文件抽取')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def _proc_fetch(firmware_id, path, task_id):
    fw_pocs = MongoPocs(method_fs, path)

    # 存储桶读取固件 保存到本地
    filename = fw_pocs.fetch(firmware_id)

    # .zip .trx 解压缩 提取系统文件目录
    fw_filename = _proc_compress(filename, path, task_id)

    # 将解压缩后的固件文件信息存入mongodb firmware_info
    fw_coll = MongoDB(firmware_info_coll)
    # item = {'fw_info': {'filepath': path, 'filename': filename, 'length': length}}
    item = {'fw_info': {'filepath': path, 'filename': fw_filename}}
    fw_coll.update(firmware_id, item)
    return 'ERROR_OK'


def _proc_compress(compress_filename, file_path, task_id):
    # uncompress zip  .zip .trx 解压缩 提取系统文件目录
    list = SysUtils.uncompress(file_path + compress_filename, file_path)
    sub_path = compress_filename.split('.')[0]
    # 提取.BIN文件
    binfile = getfilebytype(list, ".bin")
    extract_bin_files = MyBinwalk.binwalk_file_extract(file_path + binfile)

    # 提取 squashfs 文件
    squashfs_file = getfilebytype(extract_bin_files, ".squashfs")
    MySquashfs.squash_fs_file(squashfs_file, file_path, sub_path)

    # 判断系统文件类型 squashfs、jffs2

    # item['firmware_id'] = firmware_id
    # item['firmware_path'] = self.FW_PATH
    # item['filelist'] = list
    # return item
    return list


def getfilebytype(file_list, type):

    filename = ""
    for file in file_list:
        if type in file:
            return file

    return filename
