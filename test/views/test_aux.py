from utils.db.mongodb.fw_file import FwFile
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_file import PackFile
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.file.my_file import MyFile
from utils.fs.fs_image import FsImage
from utils.gadget.strutil import StrUtils
from utils.http.response import sys_app_ok_p
from utils.http.request import ReqParams
import os

from utils.const.file_type import FileType


def test_generate_uuid(request):
    return sys_app_ok_p(StrUtils.uuid_str())


virtual_file_list = {
    '1': {'file_name': 'CF-AC101-V2.6.1.zip', 'file_type': FileType.ZIP_FLE},
    '11': {'file_name': '12F304.squashfs', 'file_type': FileType.FS_IMAGE},
    '12': {'file_name': '40.7z', 'file_type': FileType.ZIP_FLE},
    '13': {'file_name': '40', 'file_type': FileType.SYS_IMAGE},
    '2': {'file_name': 'R1CL_2.7.81.zip', 'file_type': FileType.ZIP_FLE},
    '21': {'file_name': '1702A0.squashfs', 'file_type': FileType.FS_IMAGE},
    '22': {'file_name': '2E0.7z', 'file_type': FileType.ZIP_FLE},
    '23': {'file_name': '2E0', 'file_type': FileType.SYS_IMAGE},
}


def _get_file_path(virtual_id):
    # 临时用指定文件测试
    root_path = os.getcwd()
    samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')
    if virtual_id not in virtual_file_list:
        file_name = virtual_file_list['1']['file_name']
    else:
        file_name = virtual_file_list[virtual_id]['file_name']
    return os.path.join(samples_path, file_name)


def _get_file_type(virtual_id):
    if virtual_id not in virtual_file_list:
        return FileType.OTHER_FILE
    else:
        return virtual_file_list[virtual_id]['file_type']


def _save_pack(virtual_id, pack_name):
    # 获取 pack 文件的路径
    file_path = _get_file_path(virtual_id)
    file_type = _get_file_type(virtual_id)
    # file_type = FileType.ZIP_FLE if file_path[-4:-1] == '.zip' else FileType.OTHER_FILE

    # 新建或保存文件记录
    # 新的 pack ID
    pack_id = StrUtils.uuid_str()
    # 新的 pack 文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取包文件内容
    contents = MyFile.read(file_path)
    # 保存文件记录
    PackFile.save(pack_id, file_id, name=pack_name, file_type=file_type)
    # 保存文件内容
    PackFilesStorage.save(file_id, pack_name, file_type, contents)

    return pack_id, file_id


def test_save_pack(request):
    virtual_id, pack_name = ReqParams.many(request, ['virtual_id', 'pack_name'])

    pack_id, file_id = _save_pack(virtual_id, pack_name)

    return sys_app_ok_p({'pack_id': pack_id, 'file_id': file_id})


def _save_image(virtual_id, pack_id):
    # 获取 文件的路径和文件类型
    file_path = _get_file_path(virtual_id)
    file_type = _get_file_type(virtual_id)

    # 新的文件 UUID
    file_id = StrUtils.uuid_str()
    # 读取文件内容
    contents = MyFile.read(file_path)
    # 保存文件记录
    FwFile.save_file_item(pack_id, file_id, os.path.basename(file_path), file_type)
    # 保存文件内容
    FwFilesStorage.save(file_id, os.path.basename(file_path), '', file_type, contents)

    return file_id


def test_save_image(request):
    virtual_id, pack_id = ReqParams.many(request, ['virtual_id', 'pack_id'])

    file_id = _save_image(virtual_id, pack_id)

    return sys_app_ok_p(file_id)


def test_pack_extract_bat(request):
    virtual_id = pack_name = ReqParams.one(request, 'virtual_id')

    # 保存固件包
    pack_id, file_id = _save_pack(virtual_id, pack_name)

    # 保存固件镜像文件
    file_id = _save_image(virtual_id + '1', pack_id)
    file_id = _save_image(virtual_id + '2', pack_id)
    file_id = _save_image(virtual_id + '3', pack_id)

    # 提取文件系统
    fs_image = FsImage(pack_id)
    fs_image.extract()

    return sys_app_ok_p(pack_id)
