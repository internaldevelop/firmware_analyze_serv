import utils.sys.config

from utils.db.mongodb.cursor_result import CursorResult

# 任务集合
from utils.gadget.general import SysUtils

func_cache_coll = utils.sys.config.g_func_cache_coll


class FuncCacheDAO:
    @staticmethod
    def save_vars(file_id, func_addr, vars_doc):
        func_addr = hex(func_addr)
        vars_doc['file_id'] = file_id
        vars_doc['func_addr'] = func_addr
        vars_doc['update_time'] = SysUtils.get_now_time()
        func_cache_coll.update_one({'file_id': file_id, 'func_addr': func_addr}, {'$set': vars_doc}, True)

    @staticmethod
    def fetch_vars(file_id, func_addr):
        func_addr = hex(func_addr)
        cursor = func_cache_coll.find({'file_id': file_id, 'func_addr': func_addr}, {'_id': 0})
        return CursorResult.one(cursor)
