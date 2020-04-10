import os
import utils.sys.config

from utils.gadget.general import SysUtils

# 解包出来的文件 信息集合
fw_files_coll = utils.sys.config.g_fw_files_coll


class FwFileDO:

    @staticmethod
    def find(file_id):
        cursor = fw_files_coll.find({'file_id': file_id}, {'_id': 0})
        if cursor is not None:
            docs = list(cursor)
            if len(docs) != 0:
                return docs[0]
        return None

    @staticmethod
    def search_files_of_pack(pack_id, file_type):
        result_cursor = fw_files_coll.find({'pack_id': pack_id, 'file_type': file_type}, {'_id': 0})
        item_list = list(result_cursor)
        return item_list

    @staticmethod
    def get_files_of_pack(pack_id):
        result_cursor = fw_files_coll.find({'pack_id': pack_id}, {'_id': 0})
        item_list = list(result_cursor)
        return item_list

    @staticmethod
    def count_files(pack_id, file_type):
        return fw_files_coll.find({'pack_id': pack_id, 'file_type': file_type}, {}).count()

    @staticmethod
    def _db_get_file(file_id):
        fw_files_coll.find({'file_id': file_id}, {'_id': 0})

    @staticmethod
    def save_file_item(pack_id, file_id, file_name, file_type, file_path='', extra_props=None):
        # 如果文件路径未给定，则使用文件名称代替
        if len(file_path) == 0:
            file_path = file_name

        doc = {'pack_id': pack_id, 'file_id': file_id, 'file_name': file_name, 'file_path': file_path,
               'file_type': file_type, 'create_time': SysUtils.get_now_time()}
        if extra_props is not None:
            doc['extra_props'] = extra_props

        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        rv = fw_files_coll.update_one({'file_id': file_id, 'file_path': file_path}, {'$set': doc}, True)

    @staticmethod
    def update_file_type(file_id, file_type, extra_props=None):
        doc = FwFileDO.find(file_id)
        if doc is None:
            return
        doc['file_type'] = file_type
        if extra_props is not None:
            doc['extra_props'] = extra_props
        rv = fw_files_coll.update_one({'file_id': file_id}, {'$set': doc})

    @staticmethod
    def delete(file_id):
        result = fw_files_coll.delete_one({'file_id': file_id})
        return result.deleted_count == 1

    @staticmethod
    def delete_many_of_pack(pack_id):
        result = fw_files_coll.delete_many({'pack_id': pack_id})
        return result.deleted_count >= 1

    @staticmethod
    def _simulate_id_to_file(file_id):
        # 临时用指定文件测试
        root_path = os.getcwd()
        # root_path = os.get_exec_path()
        # root_path = os.path.dirname(os.path.realpath(__file__))
        # root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')
        file_list = {
            # 自动检测结果 arch 为 'AMD64'
            '1': {'file_name': 'ais3_crackme', 'file_arch': ''},
            # 自动检测结果 arch 为 'X86'
            '2': {'file_name': '1.6.26-libjsound.so', 'file_arch': ''},
            # 自动检测结果 arch 为 'AMD64'
            '4': {'file_name': 'samples.zip', 'file_arch': ''},
            '5': {'file_name': 'samples.7z', 'file_arch': ''},
            '11': {'file_name': '2E0', 'file_arch': 'MIPS32'},
            '12': {'file_name': 'libstdc++.so.6.0.16', 'file_arch': ''},
            '13': {'file_name': '2E0.7z', 'file_arch': 'MIPS32'},
            '14': {'file_name': 'libm-0.9.33.2.so', 'file_arch': ''},
            '15': {'file_name': '1702A0.squashfs', 'file_arch': ''},
            '21': {'file_name': 'opkg', 'file_arch': ''},
        }
        if file_id not in file_list:
            file_name = 'ais3_crackme'
            file_arch = ''
        else:
            file_name = file_list[file_id]['file_name']
            file_arch = file_list[file_id]['file_arch']
        return os.path.join(samples_path, file_name), file_arch
