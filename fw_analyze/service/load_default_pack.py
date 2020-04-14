import os

from fw_analyze.service.pack_process_service import PackProcessService
from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.fs.fs_image import FsImage
from utils.fs.pack_files import PackFiles
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils


class LoadDefaultPack:
    default_file_list = {
        '1': {'file_name': 'CF-AC101-V2.6.1.zip', 'file_type': FileType.PACK, 'paths': ['CF-AC101-V2.6.1'], 'pack_name': 'CF-AC101-V2.6.1'},
        '11': {'file_name': 'CF-AC101-V2.6.1.bin', 'file_type': FileType.FW_BIN, 'paths': ['CF-AC101-V2.6.1']},
        '12': {'file_name': '12F304.squashfs', 'file_type': FileType.FS_IMAGE,
               'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
        '13': {'file_name': '40.7z', 'file_type': FileType.ZIP_FILE,
               'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
        '14': {'file_name': '40', 'file_type': FileType.SYS_IMAGE,
               'paths': ['CF-AC101-V2.6.1', '_CF-AC101-V2.6.1.bin.extracted']},
        '2': {'file_name': 'R1CL_2.7.81.zip', 'file_type': FileType.PACK, 'paths': ['R1CL_2.7.81'], 'pack_name': 'R1CL_2.7.81'},
        '21': {'file_name': 'miwifi_r1cl_firmware_82b5c_2.7.81.bin', 'file_type': FileType.FW_BIN,
               'paths': ['R1CL_2.7.81']},
        '22': {'file_name': '1702A0.squashfs', 'file_type': FileType.FS_IMAGE,
               'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
        '23': {'file_name': '2E0.7z', 'file_type': FileType.ZIP_FILE,
               'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
        '24': {'file_name': '2E0', 'file_type': FileType.SYS_IMAGE,
               'paths': ['R1CL_2.7.81', '_miwifi_r1cl_firmware_82b5c_2.7.81.bin.extracted']},
    }

    @staticmethod
    def _get_fw_file_path(index):
        # 不能识别的 ID，不做处理
        if index not in LoadDefaultPack.default_file_list:
            return None

        # 测试用固件文件的根目录
        root_path = MyPath.firmware()

        fw_path = root_path
        for path in LoadDefaultPack.default_file_list[index]['paths']:
            fw_path = os.path.join(fw_path, path)
        file_name = LoadDefaultPack.default_file_list[index]['file_name']

        return os.path.join(fw_path, file_name)

    @staticmethod
    def _get_file_type(index):
        if index not in LoadDefaultPack.default_file_list:
            return FileType.OTHER_FILE
        else:
            return LoadDefaultPack.default_file_list[index]['file_type']

    @staticmethod
    def _get_pack_name(index):
        if index not in LoadDefaultPack.default_file_list:
            return ''
        else:
            return LoadDefaultPack.default_file_list[index]['pack_name']

    @staticmethod
    def _save_pack(pack_index, pack_name):
        # 获取 pack 文件的路径
        file_path = LoadDefaultPack._get_fw_file_path(pack_index)
        if file_path is None:
            return None, None

        # 文件类型
        file_type = LoadDefaultPack._get_file_type(pack_index)

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

    @staticmethod
    def _save_image(file_index, pack_id):
        # 获取 文件的路径和文件类型
        file_path = LoadDefaultPack._get_fw_file_path(file_index)
        if file_path is None:
            return None

        # 文件类型
        file_type = LoadDefaultPack._get_file_type(file_index)

        # 新的文件 UUID
        file_id = StrUtils.uuid_str()
        # 读取文件内容
        contents = MyFile.read(file_path)
        # 保存文件记录
        FwFileDO.save_file_item(pack_id, file_id, os.path.basename(file_path), file_type)
        # 保存文件内容
        FwFilesStorage.save(file_id, os.path.basename(file_path), os.path.basename(file_path), file_type, contents)

        return file_id

    @staticmethod
    def load_default_virtual_packs(file_name=''):
        # 如果没有给定文件名称，则使用默认文件列表
        if len(file_name) == 0:
            file_name_list = ['msvc_cfg_0_debug.exe', 'CADET_00002', '1.6.26-libjsound.so', 'ais3_crackme', 'bash', 'datadep_test', 'opkg',
                              'regedit.exe', 'true']
        else:
            file_name_list = [file_name]

        pack_list = []
        for file_name in file_name_list:
            # 从 samples 文件中读取文件内容
            file_path = os.path.join(MyPath.samples(), file_name)
            file_data = MyFile.read(file_path)

            # 添加虚拟包和可执行文件记录及数据存储
            pack_id, exec_file_id = PackProcessService.add_single_exec(file_name, file_data)

            # 验证是否可执行文件，并分析 arch
            PackFiles.start_exec_bin_verify_task(pack_id)

            pack_list.append({'pack_id': pack_id, 'file_id': exec_file_id})

        return pack_list

    @staticmethod
    def load_default_real_packs(pack_index_list):
        pack_list = []

        for pack_index_int in pack_index_list:

            pack_index = str(pack_index_int)
            # 保存固件包
            pack_id, p_file_id = LoadDefaultPack._save_pack(pack_index, LoadDefaultPack._get_pack_name(pack_index))
            # 保存失败时，则退出循环
            if pack_id is None:
                break

            file_id_list = []
            for file_index_int in range(1, 100):
                file_index = str(file_index_int)
                # 保存固件镜像文件
                i_file_id = LoadDefaultPack._save_image(pack_index + file_index, pack_id)
                # 保存失败时，则已经完成所有的镜像文件保存，退出循环
                if i_file_id is None:
                    break
                file_id_list.append(i_file_id)

            # 提取文件系统
            FsImage.start_fs_image_extract_task(pack_id)
            pack_list.append({'pack_id': pack_id, 'file_id_list': file_id_list})

        return pack_list
