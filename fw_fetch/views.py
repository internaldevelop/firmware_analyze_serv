import time
import datetime
import os
import utils.sys.config
from django.conf import settings
from utils.http.response import app_ok_p, app_err_p, app_ok, app_err, sys_app_ok_p, sys_app_err_p, sys_app_ok, sys_app_err
from utils.http.http_request import req_get_param_int, req_get_param, req_post_param, req_post_param_int, req_post_param_dict
from utils.gadget.download import Mydownload
from utils.task import MyTask
from utils.websocket.websocket import MyWebsocket
from utils.db.mongodb.mongo_db import MongoDB
from utils.db.mongodb.mongo_pocs import MongoPocs

# firmware 信息集合
firmware_info_coll = utils.sys.config.g_firmware_info_col
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
    downloadurl = req_get_param(request, 'url')
    print(downloadurl)

    # 启动下载任务
    task = MyTask(_proc_func_download, (downloadurl, settings.FW_PATH, ))
    task_id = task.get_task_id()

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(_init_task_info(task_id))


def _proc_func_download(downloadurl, g_fw_save_path, task_id):
    # 检查本地保存路径
    if os.path.isdir(g_fw_save_path):
        pass
    else:
        os.mkdir(g_fw_save_path)

    # 执行下载操作
    ret_download_info, fwfilename ,file_list = Mydownload.fwdownload(downloadurl, g_fw_save_path, task_id)
    print(ret_download_info, fwfilename)

    # 保存到mongodb
    # fwfilename = "CF-EW71-V2.6.0.zip"
    # ret_download_info = ""
    task_item = save_mongodb(downloadurl, g_fw_save_path, fwfilename, ret_download_info, task_id)

    # websocket通知页面
    # ws = MyWebsocket()
    # ws.sendmsg(str(task_item))

    # MyWebsocket.sendmsg(str(task_item))


def save_mongodb(downloadurl, fwpath, fwfilename, download_info, task_id):

    # 保存固件到mongodb 集合
    fw_coll = MongoDB(firmware_info_coll)
    firmware_id = fw_coll.get_suggest_firmware_id(None)
    item = {
        'id': firmware_id,
        'fw_file_name': fwfilename,
        'application_mode': '',
        'fw_manufacturer': '',
        'url': downloadurl
    }
    fw_coll.update(firmware_id, item)

    # 保存到存储桶
    fw_pocs = MongoPocs(method_fs)
    with open(fwpath + fwfilename, 'rb') as myimage:
        data = myimage.read()
        fw_pocs.add(firmware_id, fwfilename, data)

    task_coll = MongoDB(task_info_coll)
    # 保存下载任务到mongodb
    task_item = {
        'task_id': task_id,
        'type': 'download',
        'time': datetime.datetime.now(),
        'percentage': '100',
        'status': download_info
    }
    task_coll.update(task_id, task_item)

    return task_item


# 1.2 查询固件列表
def list(reuqest):
    # 获取信息总数
    fw_coll = MongoDB(firmware_info_coll)
    total = fw_coll.info_count()

    # 读取固件信息
    docs = fw_coll.query(0, total)
    return sys_app_ok_p({'total': total, 'count': len(docs), 'items': docs})
