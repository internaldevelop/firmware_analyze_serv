# mongo集合操作
# import utils.sys.config
import pymongo
# import re
# import requests
# import os


class MongoDB:
    def __init__(self, collection):
        # 数据库集合（表）
        self.collection = collection

    def get_field_max_value(self, field):
        # 字段按照数字顺序整理：collation({'locale': 'zh', 'numericOrdering': True})
        res_curosr = self.collection.find({}, {'_id': 0, field: 1}). \
            collation({'locale': 'zh', 'numericOrdering': True}).sort(field, -1)
        if res_curosr.count() > 0:
            item = list(res_curosr)[0]
            return item[field]
        else:
            return 0

    def get_field_max_value_int(self, field):
        return int(self.get_field_max_value(field))

    # 检查传入的firmware_id，返回建议ID，检查项包括取值范围和是否冲突（firmware_id需要唯一）
    def get_suggest_firmware_id(self, firmware_id):
        max_id = self.get_field_max_value_int('firmware_id')
        if max_id < 1:
            suggest_id = 1
        else:
            suggest_id = max_id + 1
        if firmware_id is None or int(firmware_id) < 1 or self.exist_firmware_id(firmware_id):
            return str(suggest_id)
        else:
            return firmware_id

    def add(self, item):
        result = self.collection.insert_one(item)
        return result

    def update(self, _id, item):
        result = self.collection.update_one({'id': _id}, {'$set': item}, True)
        return result

    def info_count(self):
        return self.collection.count()

    def query(self, offset, count):
        result_cursor = self.collection.find({}, {'_id': 0}).sort([("_id", pymongo.DESCENDING)])
        item_list = list(result_cursor[offset: offset + count])
        return item_list