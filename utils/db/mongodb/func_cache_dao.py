import utils.sys.config

from utils.db.mongodb.cursor_result import CursorResult

# 任务集合
from utils.gadget.general import SysUtils

func_cache_coll = utils.sys.config.g_func_cache_coll


class FuncCacheDAO:
    @staticmethod
    def _build_common_keys(file_id, func_addr, key_name, data_dict):
        func_addr_hex = hex(func_addr)
        return {'file_id': file_id, 'func_addr': func_addr, 'func_addr_hex': func_addr_hex,
                key_name: data_dict, 'update_time': SysUtils.get_now_time()}

    @staticmethod
    def find(file_id, func_addr):
        cursor = func_cache_coll.find({'file_id': file_id, 'func_addr': func_addr}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def fetch_record(file_id, func_addr, key_name):
        cursor = func_cache_coll.find({'file_id': file_id, 'func_addr': func_addr}, {'_id': 0})
        doc = CursorResult.one(cursor)
        if doc is not None and doc.get(key_name) is not None:
            return doc.get(key_name)
        else:
            return None

    @staticmethod
    def save_vars(file_id, func_addr, vars_dict):
        vars_doc = FuncCacheDAO._build_common_keys(file_id, func_addr, 'vars', vars_dict)
        result = func_cache_coll.update_one({'file_id': file_id, 'func_addr': func_addr},
                                            {'$set': vars_doc}, True)

    @staticmethod
    def fetch_vars(file_id, func_addr):
        return FuncCacheDAO.fetch_record(file_id, func_addr, 'vars')

    @staticmethod
    def save_props(file_id, func_addr, props_dict):
        props_doc = FuncCacheDAO._build_common_keys(file_id, func_addr, 'props', props_dict)
        result = func_cache_coll.update_one({'file_id': file_id, 'func_addr': func_addr},
                                            {'$set': props_doc}, True)

    @staticmethod
    def fetch_props(file_id, func_addr):
        return FuncCacheDAO.fetch_record(file_id, func_addr, 'props')

    @staticmethod
    def save_codes(file_id, func_addr, props_dict):
        props_doc = FuncCacheDAO._build_common_keys(file_id, func_addr, 'codes', props_dict)
        result = func_cache_coll.update_one({'file_id': file_id, 'func_addr': func_addr},
                                            {'$set': props_doc}, True)

    @staticmethod
    def fetch_codes(file_id, func_addr):
        return FuncCacheDAO.fetch_record(file_id, func_addr, 'codes')

