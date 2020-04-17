import utils.sys.config

from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils

# 基于文件的分析结果的缓存
file_cache_coll = utils.sys.config.g_firmware_db_full["file_cache"]


class FileCacheDAO:
    @staticmethod
    def _build_common_keys(file_id, key_name, data_dict):
        return {'file_id': file_id, key_name: data_dict, 'update_time': SysUtils.get_now_time()}

    @staticmethod
    def find(file_id):
        cursor = file_cache_coll.find({'file_id': file_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def fetch_record(file_id, key_name):
        cursor = file_cache_coll.find({'file_id': file_id}, {'_id': 0})
        doc = CursorResult.one(cursor)
        if doc is not None and doc.get(key_name) is not None:
            return doc.get(key_name)
        else:
            return None

    @staticmethod
    def save_state_info(file_id, state_dict):
        state_doc = FileCacheDAO._build_common_keys(file_id, 'state_info', state_dict)
        result = file_cache_coll.update_one({'file_id': file_id},
                                            {'$set': state_doc}, True)

    @staticmethod
    def fetch_state_info(file_id):
        return FileCacheDAO.fetch_record(file_id, 'state_info')

    @staticmethod
    def save_functions(file_id, funcs_dict):
        funcs_doc = FileCacheDAO._build_common_keys(file_id, 'functions', funcs_dict)
        result = file_cache_coll.update_one({'file_id': file_id},
                                            {'$set': funcs_doc}, True)

    @staticmethod
    def fetch_functions(file_id):
        return FileCacheDAO.fetch_record(file_id, 'functions')

