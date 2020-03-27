import common.config

from fw_fetch.firmware_pocs import FirmwarePocs
import pymongo
import re
import requests
import os
# firmware 信息集合
firmware_info_col = common.config.g_firmware_info_col
task_info_col = common.config.g_task_info_col
firmware_pocs = FirmwarePocs()

# 自定义固件信息的 ID号的起始值为900,000
custom_firmware_id_base = 900000


class FirmwareDB:

    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36'}
        # self.base_url = 'http://www.luyoudashi.com'
        self.base_url = 'http://www.luyoudashi.com/roms/vendor-13350-' #1.html'
        self.base_path = os.path.dirname(__file__)

    def info_count(self):
        return firmware_info_col.count()


    def makedir(self, name):
        path = os.path.join(self.base_path, name)
        isExist = os.path.exists(path)
        if not isExist:
            os.makedirs(path)
            print("File has been created.")
        else:
            print('OK!The file is existed. You do not need create a new one.')
        os.chdir(path)

    def request(self, url):
        r = requests.get(url, headers=self.headers)
        return r

    def max_firmware_id(self):
        return self.get_field_max_value(firmware_info_col, 'firmware_id')

    def info_count(self):
        total_count = firmware_info_col.count()
        return total_count

    def get_field_max_value(self, coll, field):
        # 字段按照数字顺序整理：collation({'locale': 'zh', 'numericOrdering': True})
        res_curosr = coll.find({}, {'_id': 0, field: 1}). \
            collation({'locale': 'zh', 'numericOrdering': True}).sort(field, -1)
        # if list(res_curosr).__len__() > 0:
        if res_curosr.count() > 0:
            item = list(res_curosr)[0]
            return item[field]
        else:
            return 0

    def get_field_max_value_int(self, coll, field):
        return int(self.get_field_max_value(coll, field))

    # 检查传入的firmware_id，返回建议ID，检查项包括取值范围和是否冲突（firmware_id需要唯一）
    def get_suggest_firmware_id(self, firmware_id):
        max_id = self.get_field_max_value_int(firmware_info_col, 'firmware_id')
        if max_id < custom_firmware_id_base:
            suggest_id = custom_firmware_id_base
        else:
            suggest_id = max_id + 1
        if firmware_id is None or int(firmware_id) < custom_firmware_id_base or self.exist_firmware_id(firmware_id):
            return str(suggest_id)
        else:
            return firmware_id

    def get_custom_id_base_int(self):
        return custom_firmware_id_base

    def get_custom_id_base(self):
        return str(custom_firmware_id_base)

    def query(self, offset, count):
        result_cursor = firmware_info_col.find({}, {'_id': 0}).sort([("_id", pymongo.DESCENDING)])
        item_list = list(result_cursor[offset: offset + count])
        return item_list

    def query_all(self):
        count = self.info_count()
        return self.query(0, count)

    def fetch(self, firmware_id):
        doc = firmware_info_col.find_one({'firmware_id': firmware_id}, {'_id': 0})
        return doc

    def filter(self, field, value):
        if field in ['os', 'service', 'db', 'PLC']:
            key = 'description'
            # 针对厂商名称做英文转换
            if value == '西门子':
                value = 'siemens'
            elif value == '施耐德':
                value = 'schneider'
            elif value == '菲尼克斯':
                value = 'phoenix'
            elif value == '通用电气' or value == '通用电气软件组态':
                value = 'GE'
        else:
            return None

        # 正则表达式匹配整个单词：re.compile(r'\b%s\b' % word, re.IGNORECASE)
        # \b表示单词的开始和结束
        result_cursor = firmware_info_col.find({key: re.compile(r'\b%s\b' % value, re.IGNORECASE)}, {'_id': 0})
        return result_cursor

    def search(self, value):
        key = 'description'
        # 正则表达式匹配特定字符串：re.compile(r'%s' % word, re.IGNORECASE)
        result_cursor = firmware_info_col.find({key: re.compile(r'%s' % value, re.IGNORECASE)}, {'_id': 0}).sort(
            [("_id", pymongo.DESCENDING)])
        return result_cursor

    def get_index_coll(self, field):
        index_coll = None
        field_name = 'name'
        if field == 'author':
            index_coll = common.config.g_author_coll
        elif field == 'type':
            index_coll = common.config.g_type_coll
        elif field == 'platform':
            index_coll = common.config.g_platform_coll
            field_name = 'platform'
        return index_coll, field_name

    def fetch_field_id(self, field, value):
        # 不同的字段对应不同的字段索引集合
        index_coll, field_name = self.get_index_coll(field)
        if index_coll is None:
            return None
        # 在字段索引集合中查找指定值是否已存在
        item = index_coll.find_one({field_name: value})
        if item is not None:
            return item['id']

        # 新的域值的ID取值，在现有数据的最大ID的基础上增加1
        id = self.get_field_max_value_int(index_coll, 'id') + 1
        id_str = str(id)
        # 写入该条字段索引信息
        result = index_coll.insert_one({'id': id_str, field_name: value})
        return id_str

    def exist_firmware_id(self, firmware_id):
        item = firmware_info_col.find_one({'firmware_id': firmware_id})
        return item is not None

    def custom_firmware_id(self, firmware_id):
        return int(firmware_id) >= custom_firmware_id_base

    def add(self, item):
        result = firmware_info_col.insert_one(item)
        return result

    def update(self, firmware_id, item):
        result = firmware_info_col.update_one({'firmware_id': firmware_id}, {'$set': item})
        return result

    def delete(self, firmware_id):
        result = firmware_info_col.delete_one({'firmware_id': firmware_id})
        return result

    def query_type(self):
        result_cursor = common.config.g_type_coll.find({}, {'_id': 0})
        return list(result_cursor)

    def query_platform(self):
        result_cursor = common.config.g_platform_coll.find({}, {'_id': 0})
        return list(result_cursor)

    def fetch_some(self, id_list):
        docs = []
        for firmware_id in id_list:
            firmware_id = firmware_id.strip()
            doc = self.fetch(firmware_id)
            if doc is not None:
                docs.append(doc)
        return docs

    def fetch_range(self, id_from, id_to):
        where_from = 'NumberInt(obj.firmware_id) >= {}'.format(id_from)
        where_to = 'NumberInt(obj.firmware_id) <= {}'.format(id_to)
        result_cursor = firmware_info_col.find({'$and': [{'$where': where_from}, {'$where': where_to}]}, {'_id': 0})
        docs = list(result_cursor)
        return docs

# task_info
    def task_add(self, item):
        result = task_info_col.insert_one(item)
        return result

    def task_update(self, task_id, item):
        result = task_info_col.update_one({'task_id': task_id}, {'$set': item})
        return result

    def task_delete(self, task_id):
        result = task_info_col.delete_one({'task_id': task_id})
        return result

    def task_query(self, offset, count):
        result_cursor = task_info_col.find({}, {'_id': 0}).sort([("_id", pymongo.DESCENDING)])
        item_list = list(result_cursor[offset: offset + count])
        return item_list

    def exist_task_id(self, task_id):
        item = task_info_col.find_one({'task_id': task_id})
        return item is not None

    def task_fetch(self, task_id):
        doc = task_info_col.find_one({'task_id': task_id}, {'_id': 0})
        return doc

    def task_search(self, value):
        key = 'description'
        # 正则表达式匹配特定字符串：re.compile(r'%s' % word, re.IGNORECASE)
        result_cursor = task_info_col.find({key: re.compile(r'%s' % value, re.IGNORECASE)}, {'_id': 0}).sort(
            [("_id", pymongo.DESCENDING)])
        return result_cursor

    def task_fetch_field_id(self, field, value):
        # 不同的字段对应不同的字段索引集合
        index_coll, field_name = self.get_index_coll(field)
        if index_coll is None:
            return None
        # 在字段索引集合中查找指定值是否已存在
        item = index_coll.find_one({field_name: value})
        if item is not None:
            return item['id']

        # 新的域值的ID取值，在现有数据的最大ID的基础上增加1
        id = self.get_field_max_value_int(index_coll, 'id') + 1
        id_str = str(id)
        # 写入该条字段索引信息
        result = index_coll.insert_one({'id': id_str, field_name: value})
        return id_str

    def task_get_field_max_value_int(self, coll, field):
        return int(self.get_field_max_value(coll, field))

    def get_suggest_task_id(self, task_id):
        max_id = self.get_field_max_value_int(task_info_col, 'task_id')
        if max_id < 1:
            suggest_id = 1
        else:
            suggest_id = max_id + 1
        if task_id is None or int(task_id) < 0 or self.exist_task_id(task_id):
            return str(suggest_id)
        else:
            return task_id

    def task_info_count(self):
        total_count = task_info_col.count()
        return total_count

    def task_get_field_max_value(self, coll, field):
        # 字段按照数字顺序整理：collation({'locale': 'zh', 'numericOrdering': True})
        res_curosr = coll.find({}, {'_id': 0, field: 1}). \
            collation({'locale': 'zh', 'numericOrdering': True}).sort(field, -1)
        # if list(res_curosr).__len__() > 0:
        if res_curosr.count() > 0:
            item = list(res_curosr)[0]
            return item[field]
        else:
            return 0
