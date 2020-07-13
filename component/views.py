from django.shortcuts import render

# Create your views here.
import os
import tempfile
import utils.sys.config
from django.conf import settings

from utils.db.mongodb.pack_com_file import PackCOMFileDO
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
from utils.db.mongodb.source_code_file import SourceCodeFileDO
from utils.db.mongodb.source_code_file_storage import SourceCodeFilesStorage
from utils.db.mongodb.make_com_file import MakeCOMFileDO
from utils.db.mongodb.make_com_file_storage import MakeCOMFilesStorage
from utils.gadget.my_tree import MyTree

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


# 执行shell命令,默认的执行路径: pwd\files\source_code
def runcmd(command, work_path=MyPath.component(), env=None):
    # 1.    命令被分号“;”分隔，这些命令会顺序执行下去；
    # 2.    命令被“ && ”分隔，这些命令会顺序执行下去，遇到执行错误的命令停止；
    # 3.    命令被双竖线“ || ”分隔，这些命令会顺序执行下去，遇到执行成功的命令停止，后面的所有命令都将不会执行;
    print(command)
    # command = '/bin/sh -c ' + cmd
    # command = cmd
    args = shlex.split(command)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_path, env={'CC':'arm-linux-gnueabihf-gcc', 'RANLIB':'arm-linux-gnueabihf-ranlib'})
    output, stderr = sub_proc.communicate()
    exit_code = sub_proc.returncode
    process = output[0].decode('utf-8')
    result = output[1].decode('utf-8')
    print(process)
    print(result)
    return process, result


def testcmd(request):
    # process, result = runcmd('pwd')
    # process, result = runcmd('ls -l')
    # # cmd = ReqParams.one(request, 'url', protocol='GET')
    # cmd = 'tar -xzvf ' + 'openssl-1.0.0s.tar.gz'
    # # process, result = runcmd(cmd, MyPath.component())
    # process, result = runcmd(cmd)

    work_path = MyPath.component() + '/openssl-1.0.0s'

    testfile = work_path + '/CHANGES'
    SysUtils.chmod(testfile, "777")

    # save_make_files('18e2f698-487a-47d4-9bf0-3c33d7a78320', work_path)
    # return

    # cmd = MyPath.component() + '/openssl-1.0.0s/' + 'CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # runcmd(cmd, work_path)
    # cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccCXX=arm-linux-gnueabihf-g++AR=arm-linux-gnueabihf-arRANLIB=arm-linux-gnueabihf-ranlib ./Configure no-asm shared --prefix=/usr/local/arm/openssl linux-armv4'
    # runcmd(cmd, work_path)

    # cmd = 'CC=arm-linux-gnueabihf-gcc RANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    cmd = './Configure --prefix=/usr/local/arm/openssl linux-armv4'

    runcmd(cmd, work_path, "{'CC':'arm-linux-gnueabihf-gcc', 'RANLIB':'arm-linux-gnueabihf-ranlib'}")

    cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    runcmd(cmd, work_path)

    tmp = tempfile.TemporaryFile()

    rval = subprocess.call(shlex.split(cmd), stdout=tmp, stderr=tmp)

    cmd = 'make'
    runcmd(cmd, work_path)

    # print(process)
    # print(result)


#    result = output[1].decode('utf-8')
#    print(result)
    return sys_app_ok_p({})


# 获取组件编译工作目录
def getmakepath(file_name):
    # root, ext = os.path.splitext(file_name)
    dir = file_name.split('.tar.gz')[0]
    return os.path.join(MyPath.component(), dir)


# 组件编译X86
def compile_x86(file_name, task_id):
    make_path = getmakepath(file_name)

    # cmd = './config && make'
    # cmd = './config'

    # clear make_component
    build_path = os.path.join(make_path, 'make_component')
    SysUtils.rm_filepath(build_path)

    # 指定生成的目录，方便将新生成文件进行入库操作
    cmd = './config --prefix=' + build_path
    process, result = runcmd(cmd, make_path)
    cmd = 'make'
    process, result = runcmd(cmd, make_path)

    cmd = 'make install'
    process, result = runcmd(cmd, make_path)

    total_percentage = 90.0
    MyTask.save_exec_info(task_id, total_percentage, {'process': process})
    MyTask.save_exec_info(task_id, total_percentage, {'result': result})

    return build_path


# 组件编译ARM
def compile_arm(file_name, task_id):
    make_path = getmakepath(file_name)

    # clear make_component
    build_path = os.path.join(make_path, 'make_component')
    SysUtils.rm_filepath(build_path)

    cmd = '/bin/sh -c CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    runcmd(cmd, make_path)

    cmd = 'CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=/usr/local/arm/openssl linux-armv4'
    runcmd(cmd, make_path)







    cmd = 'CC=arm-linux-gnueabihf-gccRANLIB=arm-linux-gnueabihf-ranlib ./Configure --prefix=' + build_path + ' linux-armv4'
    runcmd(cmd, make_path)

    cmd = 'make'
    process, result = runcmd(cmd, make_path)

    cmd = 'make install'
    process, result = runcmd(cmd, make_path)

    return build_path


# 查询所有组件生成文件信息
def list_make(request):
    print('list_make')
    pack_id = ReqParams.one(request, 'pack_id')

    # 读取所有可执行文件
    exec_list = MakeCOMFileDO.search_files_of_pack(pack_id, FileType.MAKE_FILE)

    # if tree_type is None or len(tree_type) == 0 or tree_type == 'normal':
    #     # file_path_insert_into_tree 树，初始化为字典
    #     tree_type = 'normal'
    #     exec_tree = {}
    # elif tree_type == 'antd':
    #     # file_path_insert_into_antd_tree 树，初始化为数组
    #     exec_tree = []
    # else:
    #     tree_type = 'normal'
    #     exec_tree = {}

    tree_type = 'normal'
    exec_tree = {}

    # 对每个文件做树的各级节点定位和创建
    for exec_file in exec_list:
        # 获取文件路径
        file_path = exec_file['file_path']
        file_id = exec_file['file_id']
        if file_path is None or len(file_path) == 0:
            continue

        if tree_type == 'normal':
            MyTree.file_path_insert_into_tree(exec_tree, file_path, file_id)
        elif tree_type == 'antd':
            MyTree.file_path_insert_into_antd_tree(exec_tree, file_path, file_id)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='读取固件包文件结构',
                    desc='获取指定固件包（ID=%s）的文件结构（模式为：%s）' % (pack_id, tree_type))

    return sys_app_ok_p(exec_tree)


# 查询所有组件源码包信息
def list(request):
    # 所有包的基本信息
    com_list = PackCOMFileDO.all_packs()
    # info_list = []
    # for pack in com_list:
    #     # 各个包的所含文件信息
    #     # 各个包的提取任务和分析任务状态
    #     pack_id = pack['pack_id']
    #     pack_service = PackInfoService(pack_id, pack)
    #     pack = pack_service.pack_summary()
    #
    #     info_list.append(pack)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='查询所有组件源码包信息',
                    desc='查询所有组件源码包的信息，统计其文件数量，查询任务信息')

    return sys_app_ok_p(com_list)


# 组件编译
def compile(request):
    # 获取编译参数
    arch, pack_id = ReqParams.many(request, ['arch', 'pack_id'])

    # 启动编译任务
    extra_info = {'task_type': TaskType.REMOTE_DOWNLOAD,
                  'task_name': '组件编译',
                  'task_desc': '组件编译及入库操作'}
    task = MyTask(_proc_compile_tasks, (arch, pack_id), extra_info=extra_info)
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id}, category='compile', action='组件编译',
                    desc='组件编译及入库操作')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


# 从存储桶导出源码文件
def export_files(pack_id):
    # DB中导出源码文件／目录
    files_list = SourceCodeFileDO.get_files_of_pack(pack_id)

    for file in files_list:
        print(file['file_path'])
        path, name = os.path.split(file['file_path'])
        SourceCodeFilesStorage.export(file['file_id'], name, path)

    fileinfo = PackCOMFileDO.fetch_pack(pack_id)
    path, name = os.path.split(fileinfo['file_path'])
    return path, name


# 遍历文件夹
def walkFile(file):

    itotal_files=0
    for root, dirs, files in os.walk(file):

        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        for f in files:
            itotal_files+=1
            print(os.path.join(root, f))

        # 遍历所有的文件夹
        for d in dirs:
            print(os.path.join(root, d))

    print(itotal_files)
    for root, dirs, files in os.walk(file):

        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        for f in files:
            print(os.path.join(root, f))

        # 遍历所有的文件夹
        for d in dirs:
            print(os.path.join(root, d))


# 保存MAKE生成目录文件
def save_make_files(pack_com_id, buildpath):
    print(buildpath)

    # 遍历生成目录
    # 遍历目录 读取文件内容保存到DB
    itotal_files = 0
    for root, dirs, files in os.walk(buildpath):

        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        for f in files:
            itotal_files += 1
            print(os.path.join(root, f))
            path_file_name = os.path.join(root, f)
            file_type = FileType.MAKE_FILE
            file_name = os.path.basename(path_file_name)

            # 新建或保存文件记录
            # 新的 pack ID
            # pack_com_id = StrUtils.uuid_str()
            # 新的 pack 文件 UUID
            file_com_id = StrUtils.uuid_str()
            # 读取包文件内容
            contents = MyFile.read(path_file_name)
            # 保存文件记录
            MakeCOMFileDO.save_file_item(pack_com_id, file_com_id, file_name, file_type, path_file_name, None)
            # 保存文件内容
            MakeCOMFilesStorage.save(file_com_id, file_name, path_file_name, file_type, contents)

        # print(root)
        # print(dir)
        print(files)

    print(itotal_files)


# 启动编译任务
def _proc_compile_tasks(arch, pack_id, task_id):


    #1 DB中导出源码文件／目录
    path, file_name = export_files(pack_id)
    print(path)
    if path is None:
        print("export_files error")
        MyTask.save_exec_info(task_id, 0, {'compile': "组件源码编译失败，导出组件库源码失败"})
        return

    MyTask.save_exec_info_name(task_id, file_name)

    # cmd = 'tar -xzvf ' + file_name
    # runcmd(cmd)

    # 2 make
    if arch == 'x86':
        build_path = compile_x86(file_name, task_id)
    elif arch == 'arm':
        build_path = compile_arm(file_name, task_id)

    # 3 save make file to db
    save_make_files(pack_id, build_path)


    total_percentage = 100.0
    MyTask.save_exec_info(task_id, total_percentage, {'compile': "组件源码编译操作完成"})


# test
def test(request):
    # com_download_url = ReqParams.one(request, 'url', protocol='GET')
    # # 启动下载任务
    # extra_info = {'task_type': TaskType.REMOTE_DOWNLOAD,
    #               'task_name': '组件源码下载',
    #               'task_desc': '下载组件源码入库存储桶'}
    # task = MyTask(_proc_component_tasks, (com_download_url, MyPath.component()), extra_info=extra_info)
    # task_id = task.get_task_id()
    #
    # # 保存操作日志
    # LogRecords.save({'task_id': task_id}, category='download', action='组件源码下载',
    #                 desc='下载组件源码入库存储桶')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p({})


# def _proc_component_tasks(com_download_url, g_fw_save_path, task_id):
#     print("download task_id", task_id)
#     # 检查本地保存路径 没有则创建
#     SysUtils.check_filepath(g_fw_save_path)
#
#     # 1 时间消耗总占比30  执行下载操作
#     total_percentage = 30.0
#     ret_download_info = com_filename = ""
#     file_list = []
#
#     ret_download_info, com_filename, file_list = Mydownload.http_download(com_download_url, g_fw_save_path, task_id, total_percentage)
#
#     print(ret_download_info, com_filename)
#     MyTask.save_exec_info_name(task_id, com_filename)
#
#     total_percentage = 100.0
#     MyTask.save_exec_info(task_id, total_percentage, {'download': "组件下载、提取、入库操作完成"})
#
#     # 7 clear temp files
#     return 'ERROR_OK'


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

