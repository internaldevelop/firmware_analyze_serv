import os
import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult

from utils.gadget.general import SysUtils

# 固件文件记录集合
source_code_files_coll = utils.sys.config.g_firmware_db_full["source_code_files"]


class SourceCodeFileDO:

    @staticmethod
    def find(file_id):
        cursor = source_code_files_coll.find({'file_id': file_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def search_files_of_pack(pack_id, file_type):
        cursor = source_code_files_coll.find({'pack_id': pack_id, 'file_type': file_type}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def set_file_type_verified(file_id, verified=1):
        doc = {'file_type_verified': verified}
        # 更新记录
        rv = source_code_files_coll.update_one({'file_id': file_id}, {'$set': doc}, True)

    @staticmethod
    def get_files_of_pack(pack_id):
        cursor = source_code_files_coll.find({'pack_id': pack_id}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def count_files(pack_id):
        return source_code_files_coll.find({'pack_id': pack_id, }, {}).count()

    @staticmethod
    def _db_get_file(file_id):
        source_code_files_coll.find({'file_id': file_id}, {'_id': 0})

    @staticmethod
    def _db_get_all_file(file_type=None):
        cursor = []
        if file_type is None:
            cursor = source_code_files_coll.find({}, {'_id': 0})
        else:
            cursor = source_code_files_coll.find({'file_type':file_type}, {'_id': 0})
        item_list = list(cursor)
        return item_list

    @staticmethod
    def save_file_item(pack_id, file_id, file_name, file_type, mode, file_path='', extra_props=None):
        # 如果文件路径未给定，则使用文件名称代替
        if len(file_path) == 0:
            file_path = file_name

        doc = {'pack_id': pack_id, 'file_id': file_id, 'file_name': file_name, 'file_path': file_path,
               'file_type': file_type, 'mode': mode, 'create_time': SysUtils.get_now_time()}
        if extra_props is not None:
            doc['extra_props'] = extra_props

        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        rv = source_code_files_coll.update_one({'file_id': file_id, 'file_path': file_path}, {'$set': doc}, True)

    @staticmethod
    def update_verified_file_type(file_id, file_type, extra_props=None):
        doc = {'file_type_verified': 1, 'file_type': file_type, 'extra_props': extra_props}
        rv = source_code_files_coll.update_one({'file_id': file_id}, {'$set': doc})

    @staticmethod
    def delete(file_id):
        result = source_code_files_coll.delete_one({'file_id': file_id})
        return result.deleted_count == 1

    @staticmethod
    def delete_many_of_pack(pack_id):
        result = source_code_files_coll.delete_many({'pack_id': pack_id})
        return result.deleted_count >= 1

    @staticmethod
    def _save_file_props(file_id, props):
        # 更新记录
        rv = source_code_files_coll.update_one({'file_id': file_id}, {'$set': props}, True)
        return rv

    # @staticmethod
    # def set_cfg_analyzed(file_id, cfg_analyzed=1):
    #     SourceCodeFileDO._save_file_props(file_id, {'cfg_analyze': cfg_analyzed})



