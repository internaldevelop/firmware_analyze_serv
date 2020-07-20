import os

import utils.sys.config
from django.conf import settings

from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.db.mongodb.source_code_file import SourceCodeFileDO
from utils.db.mongodb.source_code_file_storage import SourceCodeFilesStorage
from utils.db.mongodb.pack_com_file import PackCOMFileDO
from utils.db.mongodb.pack_com_file_storage import PackCOMFilesStorage
from utils.db.mongodb.cnvd_share import CnvdshareDO

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
from utils.mybinwalk.mybinwalk import MyBinwalk

# firmware 信息集合
from utils.task.task_type import TaskType

firmware_info_coll = utils.sys.config.g_firmware_info_col
# 任务集合
task_info_coll = utils.sys.config.g_task_info_col

# firmware 存储桶
method_fs = utils.sys.config.g_firmware_method_fs


# 组件源码下载
def async_com_download(request):
    com_download_url = ReqParams.one(request, 'url', protocol='POST')
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


# 组件源码下载后关联漏洞库 判断识别文件名中的版本号进查询
def associated_vulner_db(file_name):
    name, ver = file_name.split('-')
    version = ver.split('.tar.gz')[0]
    print(name)
    print(version)
    cnvd_list = CnvdshareDO.search_info_of_component_name(name)

    # 枚举每个文件，读出其文件数据，校验
    total_count = len(cnvd_list)
    for index, file_item in enumerate(cnvd_list):
        title = file_item['title']
        cnvd_id = file_item['edb_id']
        versions = file_item['products'][0]['version']
        print(versions)
        if version in versions:
            return cnvd_id, title

    return None, None


# 下载组件源码入库存储桶
def _proc_component_tasks(com_download_url, components_save_path, task_id):
    print("download task_id", task_id)
    # 检查本地保存路径 没有则创建
    SysUtils.check_filepath(components_save_path)

    # 1 时间消耗总占比30  执行下载操作
    total_percentage = 30.0
    ret_download_info = com_filename = ""
    file_list = []

    ret_download_info, com_filename, file_list = Mydownload.http_download(com_download_url, components_save_path, task_id, total_percentage)

    print(ret_download_info, com_filename)
    MyTask.save_exec_info_name(task_id, com_filename)

    # 5 组件源码下载后关联漏洞库
    edb_id, title = associated_vulner_db(com_filename)
    total_percentage = 50.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "组件源码下载后关联漏洞库"})

    # 2 时间消耗总占比0 保存到 pack_com_file to mongodb
    pack_com_id, pack_com_file_id = _save_pack_com_db(os.path.join(components_save_path, com_filename), ret_download_info, edb_id, title, task_id)

    # 3 时间消耗总占比0 解压缩源码包，提取文件到mongo
    output_dir, file_name = os.path.split(os.path.join(components_save_path, com_filename))
    file_list = _proc_com_uncompress(os.path.join(components_save_path, com_filename), output_dir, task_id)

    total_percentage = 70.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "下载组件解压缩源码包操作完成"})
    # 4 时间消耗总占比0 保存源码文件 to mongodb
    file_id = _save_source_code_file_db(os.path.join(output_dir, file_name.split('.tar.gz')[0]), pack_com_id, task_id)

    total_percentage = 100.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "下载组件源码入库操作完成"})

    # 7 clear temp files
    return 'ERROR_OK'


# 固件下载
def async_fwdownload(request):
    # 获取下载URL
    fw_download_url, ftp_user, ftp_password = ReqParams.many(request, ['url', 'user', 'password'], protocol='POST')

    # 启动下载任务
    extra_info = {'task_type': TaskType.REMOTE_DOWNLOAD,
                  'task_name': '固件下载',
                  'task_desc': '下载固件入库存储桶并进行文件抽取操作'}
    task = MyTask(_proc_tasks, (fw_download_url, settings.FW_PATH, ftp_user, ftp_password), extra_info=extra_info)
    task_id = task.get_task_id()

    # 保存操作日志
    LogRecords.save({'task_id': task_id}, category='download', action='固件下载',
                    desc='下载固件入库存储桶并进行文件抽取操作')

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


def _proc_tasks(fw_download_url, g_fw_save_path, ftp_user, ftp_password, task_id):
    print("download task_id", task_id)
    # 检查本地保存路径 没有则创建
    SysUtils.check_filepath(g_fw_save_path)

    # 1 时间消耗总占比30  执行下载操作
    total_percentage = 30.0
    ret_download_info = fw_filename = ""
    file_list = []

    if 'ftp://' in fw_download_url:
        ret_download_info, fw_filename, file_list = Mydownload.ftp_download(fw_download_url, g_fw_save_path, ftp_user,
                                                                            ftp_password, task_id, total_percentage)
    else:
        ret_download_info, fw_filename, file_list = Mydownload.http_download(fw_download_url, g_fw_save_path, task_id,
                                                                             total_percentage)

    print(ret_download_info, fw_filename)
    MyTask.save_exec_info_name(task_id, fw_filename)

    # 2 时间消耗总占比0 保存到 pack_file to mongodb
    pack_id, pack_file_id = _save_pack_db(fw_download_url, os.path.join(g_fw_save_path, fw_filename), ret_download_info,
                                          task_id)

    # 3 时间消耗总占比0 解压缩固件包->系统镜像文件，提取文件到mongo
    img_filename = _proc_uncompress(os.path.join(g_fw_save_path, fw_filename), g_fw_save_path, task_id)
    if len(img_filename) == 0:
        print("package uncompress error")
        img_filename = fw_filename  # bin文件做为包名（文件名）
        # return "package uncompress error"

    # 4 时间消耗总占比0 保存系统镜像文件 to mongodb
    file_id = _save_file_db(os.path.join(g_fw_save_path, img_filename), pack_id)

    # 5 时间消耗总占比40 BIN提取子文件
    total_percentage = 70.0
    extract_bin_files = MyBinwalk.binwalk_file_extract(os.path.join(g_fw_save_path, img_filename))
    MyTask.save_exec_info(task_id, total_percentage, {'binwalk_file_extract': extract_bin_files})

    for file in extract_bin_files:
        # binwalk解包返回的文件名带全路径
        # 对变量类型进行判断 list 值带[] 如： ['C:\\GIT\\firmware_analyze_serv\\files\\firmware\\_CF-EW71-V2.6.0.bin-2.extracted\\40']
        if isinstance(file, list):
            file_id = _save_file_db(file[0], pack_id)
        else:
            file_id = _save_file_db(file, pack_id)

    # 6 时间消耗总占比30 提取文件系统
    FsImage.start_fs_image_extract_task(pack_id)

    total_percentage = 100.0
    MyTask.save_exec_info(task_id, total_percentage, {'download': "固件下载、提取、入库操作完成"})

    # 7 clear temp files
    return 'ERROR_OK'


# 获取文件类型
def check_file_type(path_file_name):
    contents = MyFile.read(path_file_name)
    if contents is None:  # linux 系统下 BINWALK会提取出空目录，读目录文件为None
        return None, contents

    if contents[0:4] == b'\x45\x3d\xcd\x28' or contents[0:4] == b'\x28\xcd\x3d\x45':
        print(contents[0:4], "cramfs")
        return FileType.FS_IMAGE, contents
    elif contents[0:2] == b'\x85\x19' or contents[0:2] == b'\x19\x85':
        print(contents[0:4], "jffs2")
        return FileType.FS_IMAGE, contents
    elif contents[0:8] == b'-rom1fs-':
        print("romfs")
        return FileType.FS_IMAGE, contents
    elif contents[0:4] == b'UBI#':
        print("ubifs")
        return FileType.FS_IMAGE, contents
    elif contents[0:10] == b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff' or \
            contents[0:10] == b'\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff' or \
            contents[0:10] == b'\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff' or \
            contents[0:10] == b'\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff':
        print("yaffs2")
        return FileType.FS_IMAGE, contents
    elif contents[0:4] == b'\x8a\x32\xfc\x66':
        print("romfs")
        return FileType.FS_IMAGE, contents
    elif contents[0:4] == b'sqsh' or contents[0:4] == b'hsqs' or \
            contents[0:4] == b'shsq' or contents[0:4] == b'qshs' or \
            contents[0:4] == b'tqsh' or contents[0:4] == b'hsqt' or \
            contents[0:4] == b'sqlz':
        print(contents[0:4], "squashfs")
        return FileType.FS_IMAGE, contents
    elif contents[0:4] == b'\x50\x4b\x03\04':
        print("zip")
        return FileType.PACK, contents
    # elif '.bin' in file_name:
    #     return FileType.FW_BIN
    elif contents[0:5] == b'7z\xbc\xaf\x27\x1c':
        print("7z")
        return FileType.ZIP_FILE, contents
    elif '.bin' in path_file_name:
        return FileType.FW_BIN, contents
    else:
        return FileType.OTHER_FILE, contents


# 获取文件列表中的某类型文件名
def getfilebytype(file_list, type):
    filename = ""
    for file in file_list:
        if type in file:
            return file

    return filename


# 保存文件到数据库
def _save_file_db(path_file_name, pack_id):
    # 获取 文件的路径和文件类型
    # file_path = _get_fw_file_path(virtual_id)
    # if file_path is None:
    #     return None
    #
    print(path_file_name)
    file_path, file_name = os.path.split(path_file_name)
    # 新的文件 UUID
    file_id = StrUtils.uuid_str()
    # 获取文件类型 内容
    file_type, contents = check_file_type(path_file_name)
    # file_type = _get_file_type(file_name)
    if contents is None:  # linux 系统下 BINWALK会提取出空目录，读目录文件为None
        return None
    # 保存文件记录
    FwFileDO.save_file_item(pack_id, file_id, file_name, file_type, file_path)
    # 保存文件内容
    FwFilesStorage.save(file_id, file_name, file_path, file_type, contents)

    # 返回文件ID
    return file_id


# 保存源码组件文件tar.gz 到数据库
def _save_pack_com_db(path_file_name, download_info, edb_id, title, task_id):
    # todo file_type
    #file_type, contents = check_file_type(path_file_name)
    file_type = FileType.PACK
    file_name = os.path.basename(path_file_name)

    name, ver = file_name.split('-')
    version = ver.split('.tar.gz')[0]


    # 新建或保存文件记录
    # 新的 pack ID
    pack_com_id = StrUtils.uuid_str()
    # 新的 pack 文件 UUID
    file_com_id = StrUtils.uuid_str()
    # 读取包文件内容
    contents = MyFile.read(path_file_name)
    # 保存文件记录
    PackCOMFileDO.save(pack_com_id, file_com_id, edb_id, title, version, path_file_name, name=file_name, file_type=file_type)
    # 保存文件内容
    PackCOMFilesStorage.save(file_com_id, file_name, FileType.PACK, contents)

    # 返回固件包ID,文件ID
    return pack_com_id, file_com_id


# 保存解压缩源码组件文件到数据库
def _save_source_code_file_db(path_file_name, pack_com_id, task_id):
    # 遍历目录 读取文件内容保存到DB
    itotal_files=0
    for root, dirs, files in os.walk(path_file_name):

        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        for f in files:
            itotal_files+=1
            print(os.path.join(root, f))
            path_file_name = os.path.join(root, f)
            #contents = MyFile.read(path_file_name)

            # todo file_type
            # file_type, contents = check_file_type(path_file_name)
            file_type = FileType.OTHER_FILE
            file_name = os.path.basename(path_file_name)

            # 新建或保存文件记录
            # 新的 pack ID
            # pack_com_id = StrUtils.uuid_str()
            # 新的 pack 文件 UUID
            file_com_id = StrUtils.uuid_str()
            # 读取包文件内容
            contents = MyFile.read(path_file_name)
            # 保存文件记录
            SourceCodeFileDO.save_file_item(pack_com_id, file_com_id, file_name, file_type, path_file_name, None)
            # 保存文件内容
            SourceCodeFilesStorage.save(file_com_id, file_name, path_file_name, file_type, contents)


        # 遍历所有的文件夹
        for d in dirs:
            print(os.path.join(root, d))



# 保存包文件到数据库
def _save_pack_db(fw_download_url, path_file_name, download_info, task_id):
    # todo file_type
    file_type, contents = check_file_type(path_file_name)
    file_type = FileType.PACK
    file_name = os.path.basename(path_file_name)

    # 新建或保存文件记录
    # 新的 pack ID
    pack_id = StrUtils.uuid_str()
    # 新的 pack 文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取包文件内容
    contents = MyFile.read(path_file_name)
    # 保存文件记录
    PackFileDO.save(pack_id, file_id, name=file_name, file_type=file_type)
    # 保存文件内容
    PackFilesStorage.save(file_id, file_name, FileType.PACK, contents)

    # 返回固件包ID,文件ID
    return pack_id, file_id


# 1.2 查询固件列表
def fwlist(reuqest):
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
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


def _proc_fetch(firmware_id, path, task_id):
    fw_pocs = MongoPocs(method_fs, path)

    # 存储桶读取固件 保存到本地
    filename = fw_pocs.fetch(firmware_id)

    # .zip .trx 解压缩 提取系统文件目录
    fw_filename = _proc_uncompress(filename, path, task_id)

    # 将解压缩后的固件文件信息存入mongodb firmware_info
    fw_coll = MongoDB(firmware_info_coll)
    # item = {'fw_info': {'filepath': path, 'filename': filename, 'length': length}}
    item = {'fw_info': {'filepath': path, 'filename': fw_filename}}
    fw_coll.update(firmware_id, item)
    return 'ERROR_OK'


def _proc_com_uncompress(path_file_name, uncompress_path, task_id):
    return SysUtils.uncompress(path_file_name, uncompress_path)


def _proc_uncompress(path_file_name, uncompress_path, task_id):
    # uncompress zip  .zip .trx 解压缩 提取系统文件目录
    list = SysUtils.uncompress(path_file_name, uncompress_path)
    # sub_path = file_name.split('.')[0]
    # 提取.BIN文件
    bin_file = getfilebytype(list, ".bin")
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.trx')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.img')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.w')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.chk')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.bix')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.Image')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.BootImage')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.jffs2')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.yaffs2')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.ubifs')
    if len(bin_file) == 0:
        bin_file = getfilebytype(list, '.cramfs')

    return bin_file


# test
def test_check_file(reuqest):
    task = MyTask(_check_file, )
    task_id = task.get_task_id()
    return sys_app_ok_p('ok')


def enumfiles(path, dest):
    files = os.listdir(path)
    for f in files:
        subpath = path + '/' + f
        if (os.path.isfile(subpath)):
            dest.append(subpath)
        elif (os.path.isdir(subpath)):
            if (f[0] == '.'):
                pass
            else:
                enumfiles(subpath, dest)


def _check_file(task_id):
    # 枚举目录 获取文件
    # path = "C:\\GIT\\python\\firmware"
    path = "C:\\固件下载\\huawei"
    path = "C:\\固件下载\\ZS7035"
    # path = "C:\\TEMP"
    uncompress_path = "C:\\TEMP"

    dest = []
    enumfiles(path, dest)

    SysUtils.check_filepath(uncompress_path)
    os.chdir(uncompress_path)  # 将当前的目录设置为uncompress_path
    for file in dest:
        print(file)
        # 解压缩固件包->系统镜像文件，提取文件到mongo
        # file_path, file_name = os.path.split(file)
        if '.bin' in file:
            img_filename = file
        elif '.trx' in file:
            img_filename = file
        else:
            img_filename = _proc_uncompress(file, uncompress_path, task_id)
        if len(img_filename) == 0:
            continue
        # BINWALK 提取文件
        extract_bin_files = MyBinwalk._binwalk_file_extract(os.path.join(uncompress_path, img_filename),
                                                            uncompress_path)

        # binwalk解包返回的文件名带全路径 写文件
        with open('c:\\git\\file_tree_info0413.txt', 'a+') as fw:
            fw.write(file)
            fw.write('\r')
            for f in extract_bin_files:
                # print(b'Saving original ' + path.encode() + i.getPath().encode() + i.getName())
                if isinstance(f, list):
                    fw.write(os.path.basename(f[0]))
                else:
                    fw.write(os.path.basename(f))
                fw.write('\r')
            fw.close()

        del_file(uncompress_path)

    return


def del_file(filepath):
    # 删除某一目录下的所有文件或文件夹
    for root, dirs, files in os.walk(filepath, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
