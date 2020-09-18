import os
import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult

from utils.gadget.general import SysUtils

# 记录集合
func_taint_col = utils.sys.config.g_firmware_db_full["function_taint_dict"]


class TaintdictDO:

    @staticmethod
    def list():
        cursor = func_taint_col.find({}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def find(fun_id):
        cursor = func_taint_col.find({'fun_id': fun_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def search_func_name(func_name):
        cursor = func_taint_col.find({'func_name': func_name}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def delete(func_name):
        result = func_taint_col.delete_one({'func_name': func_name})
        return result.deleted_count == 1

    # @staticmethod
    # def delete_many(fun_id_list):
    #     for fun_id in fun_id_list:
    #         func_taint_col.delete(fun_id)

    @staticmethod
    def save(fun_id, func_name, hazard, solution):
        doc = {'func_name': func_name, 'hazard_desc': hazard, 'solution': solution}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        func_taint_col.update_one({'fun_id': fun_id}, {'$set': doc}, True)

    @staticmethod
    def update(func_name, hazard, solution):
        doc = {'func_name': func_name, 'hazard_desc': hazard, 'solution': solution}

        result = TaintdictDO.search_func_name(func_name)
        if result is None:
            return

        fun_id = result.get('fun_id')
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        func_taint_col.update_one({'fun_id': fun_id}, {'$set': doc}, True)


