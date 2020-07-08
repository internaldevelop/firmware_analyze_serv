from django.shortcuts import render

# Create your views here.
import os

import utils.sys.config
from django.conf import settings

from utils.db.mongodb.com_file import PackCOMFileDO
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.pack_com_file_storage import PackCOMFilesStorage
from utils.fs.fs_image import FsImage
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p
from utils.http.http_request import req_get_param, req_post_param
from utils.gadget.download import Mydownload
from utils.const.file_type import FileType
from utils.http.task_feedback import task_feedback
from utils.task.my_task import MyTask
from utils.db.mongodb.mongo_db import MongoDB
from utils.db.mongodb.mongo_pocs import MongoPocs
from utils.gadget.general import SysUtils

# firmware 信息集合
from utils.task.task_type import TaskType

import shlex
import subprocess

from component.assembly import Assembly
from component.inverted_index import InvertedIndex

assembly = Assembly()
invertedIndex = InvertedIndex()

firmware_info_coll = utils.sys.config.g_firmware_info_col
# 任务集合
task_info_coll = utils.sys.config.g_task_info_col

# firmware 存储桶
method_fs = utils.sys.config.g_firmware_method_fs


def runcmd(cmd, work_path=MyPath.component()):
    # 1.    命令被分号“;”分隔，这些命令会顺序执行下去；
    # 2.    命令被“ && ”分隔，这些命令会顺序执行下去，遇到执行错误的命令停止；
    # 3.    命令被双竖线“ || ”分隔，这些命令会顺序执行下去，遇到执行成功的命令停止，后面的所有命令都将不会执行;
    print(cmd)
    # command = '/bin/sh -c ' + cmd
    command = cmd
    args = shlex.split(command)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_path)
    output = sub_proc.communicate()
    process = output[0].decode('utf-8')
    result = output[1].decode('utf-8')
    print(process)
    print(result)
    return process, result


def testcmd(request):
    process, result = runcmd('pwd')
    process, result = runcmd('ls -l')
    # cmd = ReqParams.one(request, 'url', protocol='GET')
    cmd = 'tar -xzvf ' + 'openssl-1.0.0s.tar.gz'
    # process, result = runcmd(cmd, MyPath.component())
    process, result = runcmd(cmd)

    work_path = MyPath.component() + '/openssl-1.0.0s'

    # cmd = MyPath.component() + '/openssl-1.0.0s/' + 'CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # runcmd(cmd, work_path)
    # cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccCXX=arm-linux-gnueabihf-g++AR=arm-linux-gnueabihf-arRANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # runcmd(cmd, work_path)

    cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    runcmd(cmd, work_path)

    cmd = 'make'
    runcmd(cmd, work_path)

    # print(process)
    # print(result)


#    result = output[1].decode('utf-8')
#    print(result)
    return sys_app_ok_p({})


# 获取组件编译工作目录
def getworkpath(file_name):
    # root, ext = os.path.splitext(file_name)
    dir = file_name.split('.tar.gz')[0]
    return os.path.join(MyPath.component(), dir)


# 组件编译X86
def compile_x86(file_name, task_id):
    work_path = getworkpath(file_name)

    # cmd = './config && make'
    cmd = './config'
    runcmd(cmd, work_path)
    cmd = 'make'
    runcmd(cmd, work_path)


# 组件编译ARM
def compile_arm(file_name, task_id):
    work_path = getworkpath(file_name)
    cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    runcmd(cmd, work_path)
    return


# 组件编译
def compile(request):
    # 获取编译参数
    arch, file_name = ReqParams.many(request, ['arch', 'filename'])

    # 启动编译任务
    extra_info = {'task_type': TaskType.REMOTE_DOWNLOAD,
                  'task_name': '组件编译',
                  'task_desc': '组件编译及入库操作'}
    task = MyTask(_proc_compile_tasks, (arch, file_name), extra_info=extra_info)
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id}, category='compile', action='组件编译',
                    desc='组件编译及入库操作')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


# 启动编译任务
def _proc_compile_tasks(arch, file_name, task_id):

    MyTask.save_exec_info_name(task_id, file_name)
    cmd = 'tar -xzvf ' + file_name
    runcmd(cmd)

    if arch == 'x86':
        compile_x86(file_name, task_id)
    elif arch == 'arm':
        compile_arm(file_name, task_id)

    total_percentage = 100.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "组件源码编译操作完成"})


# 组件源码
def test(request):
    com_download_url = ReqParams.one(request, 'url', protocol='GET')
    # 启动下载任务
    extra_info = {'task_type': TaskType.REMOTE_DOWNLOAD,
                  'task_name': '组件源码下载',
                  'task_desc': '下载组件源码入库存储桶'}
    task = MyTask(_proc_component_tasks, (com_download_url, MyPath.component()), extra_info=extra_info)
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id}, category='download', action='组件源码下载',
                    desc='下载组件源码入库存储桶')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


def _proc_component_tasks(com_download_url, g_fw_save_path, task_id):
    print("download task_id", task_id)
    # 检查本地保存路径 没有则创建
    SysUtils.check_filepath(g_fw_save_path)

    # 1 时间消耗总占比30  执行下载操作
    total_percentage = 30.0
    ret_download_info = com_filename = ""
    file_list = []

    ret_download_info, com_filename, file_list = Mydownload.http_download(com_download_url, g_fw_save_path, task_id, total_percentage)

    print(ret_download_info, com_filename)
    MyTask.save_exec_info_name(task_id, com_filename)

    total_percentage = 100.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "固件下载、提取、入库操作完成"})

    # 7 clear temp files
    return 'ERROR_OK'


# 余弦相似度计算
def cosine_algorithm(request):
    # 获取参数
    file_id1, file_id2 = ReqParams.many(request, ['file_id1', 'file_id2'])
    return assembly.cosine_algorithm(file_id1, file_id2)


# 倒排索引
def inverted(request):
    # 获取参数
    file_id = req_get_param(request, 'file_id')
    return invertedIndex.inverted(file_id)


# 根据倒排索引查询数据
def get_inverted_data(request):
    # 获取参数
    index_con, file_id = ReqParams.many(request, ['index_con', 'file_id'])

    return invertedIndex.get_inverted_data(index_con, file_id)


# 根据倒排索引查询组件文件
def get_inverted_fw_data(request):
    # 获取参数
    index_con = req_get_param(request, 'index_con')
    return invertedIndex.get_inverted_fw_data(index_con)

