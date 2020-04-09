import os

from fw_analyze.service.pack_process_service import PackProcessService
from utils.const.file_type import FileType
from utils.const.pack_type import PackType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.fs.fs_image import FsImage
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p, sys_app_err

virtual_file_list = {
    '1': {'file_name': 'CF-AC101-V2.6.1.zip', 'file_type': FileType.PACK, 'paths': ['CF-AC101-V2.6.1']},
    '11': {'file_name': 'CF-AC101-V2.6.1.bin', 'file_type': FileType.FW_BIN, 'paths': ['CF-AC101-V2.6.1']},
    '12': {'file_name': '12F304.squashfs', 'file_type': FileType.FS_IMAGE, 'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
    '13': {'file_name': '40.7z', 'file_type': FileType.ZIP_FILE, 'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
    '14': {'file_name': '40', 'file_type': FileType.SYS_IMAGE, 'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
    '2': {'file_name': 'R1CL_2.7.81.zip', 'file_type': FileType.PACK, 'paths': ['R1CL_2.7.81']},
    '21': {'file_name': 'miwifi_r1cl_firmware_82b5c_2.7.81.bin', 'file_type': FileType.FW_BIN, 'paths': ['R1CL_2.7.81']},
    '22': {'file_name': '1702A0.squashfs', 'file_type': FileType.FS_IMAGE, 'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
    '23': {'file_name': '2E0.7z', 'file_type': FileType.ZIP_FILE, 'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
    '24': {'file_name': '2E0', 'file_type': FileType.SYS_IMAGE, 'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
}


def _get_fw_file_path(virtual_id):
    # 不能识别的 ID，不做处理
    if virtual_id not in virtual_file_list:
        return None

    # 测试用固件文件的根目录
    root_path = MyPath.firmware()

    fw_path = root_path
    for path in virtual_file_list[virtual_id]['paths']:
        fw_path = os.path.join(fw_path, path)
    file_name = virtual_file_list[virtual_id]['file_name']

    return os.path.join(fw_path, file_name)


def _get_file_type(virtual_id):
    if virtual_id not in virtual_file_list:
        return FileType.OTHER_FILE
    else:
        return virtual_file_list[virtual_id]['file_type']


def _save_pack(virtual_id, pack_name):
    # 获取 pack 文件的路径
    file_path = _get_fw_file_path(virtual_id)
    if file_path is None:
        return None, None

    # 文件类型
    file_type = _get_file_type(virtual_id)

    # 新建或保存文件记录
    # 新的 pack ID
    pack_id = StrUtils.uuid_str()
    # 新的 pack 文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取包文件内容
    contents = MyFile.read(file_path)
    # 保存文件记录
    PackFileDO.save(pack_id, file_id, name=pack_name, file_type=file_type)
    # 保存文件内容
    PackFilesStorage.save(file_id, pack_name, file_type, contents)

    return pack_id, file_id


def test_save_pack(request):
    virtual_id, pack_name = ReqParams.many(request, ['virtual_id', 'pack_name'])

    pack_id, file_id = _save_pack(virtual_id, pack_name)
    if pack_id is None:
        return sys_app_err('UNKNOWN')

    return sys_app_ok_p({'pack_id': pack_id, 'file_id': file_id})


def _save_image(virtual_id, pack_id):
    # 获取 文件的路径和文件类型
    file_path = _get_fw_file_path(virtual_id)
    if file_path is None:
        return None

    # 文件类型
    file_type = _get_file_type(virtual_id)

    # 新的文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取文件内容
    contents = MyFile.read(file_path)
    # 保存文件记录
    FwFileDO.save_file_item(pack_id, file_id, os.path.basename(file_path), file_type)
    # 保存文件内容
    FwFilesStorage.save(file_id, os.path.basename(file_path), os.path.basename(file_path), file_type, contents)

    return file_id


def test_save_image(request):
    virtual_id, pack_id = ReqParams.many(request, ['virtual_id', 'pack_id'])

    file_id = _save_image(virtual_id, pack_id)
    if file_id is None:
        return sys_app_err('UNKNOWN')

    return sys_app_ok_p(file_id)


def test_pack_extract_bat(request):
    for v_pack_id in range(1, 100):

        vpd = str(v_pack_id)
        # 保存固件包
        pack_id, p_file_id = _save_pack(vpd, 'pack_' + vpd)
        # 保存失败时，则退出循环
        if pack_id is None:
            break

        for v_image_id in range(1, 100):
            vid = str(v_image_id)
            # 保存固件镜像文件
            i_file_id = _save_image(vpd + vid, pack_id)
            # 保存失败时，则已经完成所有的镜像文件保存，退出循环
            if i_file_id is None:
                break

        # 提取文件系统
        FsImage.start_fs_image_extract_task(pack_id)

    return sys_app_ok_p(pack_id)


def test_add_single_exec(request):
    file_name = ReqParams.one(request, 'file_name')

    # 如果没有给定文件名称，则使用默认文件列表
    if len(file_name) == 0:
        file_name_list = ['1.6.26-libjsound.so', 'ais3_crackme', 'bash', 'datadep_test', 'opkg',
                          'regedit.exe', 'true']
    else:
        file_name_list = [file_name]

    pack_infos = []
    for file_name in file_name_list:
        # 从 samples 文件中读取文件内容
        file_path = os.path.join(MyPath.samples(), file_name)
        file_data = MyFile.read(file_path)

        # 添加虚拟包和可执行文件记录及数据存储
        pack_id, exec_file_id = PackProcessService.add_single_exec(file_name, file_data)

        pack_infos.append({'file_name': file_name, 'pack_id': pack_id, 'exec_file_id': exec_file_id})

    return sys_app_ok_p(pack_infos)


def test_clear_virtual_packs(request):
    PackProcessService.remove_all_packs_by_type(PackType.VIRTUAL)
    return sys_app_ok_p({})


def test_clear_real_packs(request):
    PackProcessService.remove_all_packs_by_type(PackType.REAL)
    return sys_app_ok_p({})
