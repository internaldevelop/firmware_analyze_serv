from common.response import app_ok_p, app_err_p, app_ok, app_err
from common.error_code import Error
from common.utils.http_request import req_get_param_int, req_get_param, req_post_param, req_post_param_int, \
    req_post_param_dict
import common.config
from common.utils.general import SysUtils
from django.conf import settings

import pymongo
import re
import os
import zipfile

# 固件文件方法存储桶
method_fs = common.config.g_firmware_method_fs


class FirmwarePocs:
    def count(self):
        count = method_fs.find().count()
        return count

    def query(self, offset, count):
        result_cursor = method_fs.find().sort([("_id", pymongo.DESCENDING)])
        item_list = list(result_cursor[offset: offset + count])
        items = []
        for item in item_list:
            items.append(SysUtils.grid_out_to_dict(item))
        # item_list = list(result_cursor[offset: offset + count])
        return items

    def fetch(self, firmware_id):
        grid_out = method_fs.find_one({'filename': firmware_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        if item is None:
            return None

        data = grid_out.read()
        print(item['aliases'])

        # save path file
        filename = settings.FW_PATH + item['aliases'] #os.getcwd() + "\\firmware\\" + item['aliases']
        outf = open(filename, 'wb')  # 创建文件
        outf.write(data)
        outf.close()

        # uncompress zip
        filepath, list = SysUtils.un_py7zr(filename)

        # item['firmware_id'] = firmware_id
        item['firmware_path'] = filepath
        item['filelist'] = list
        return item

    def fetch_no_content(self, firmware_id):
        grid_out = method_fs.find_one({'filename': firmware_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        if item is None:
            return None
        return item

    def add(self, firmware_id, alias, content):
        type = SysUtils.parse_file_type(alias)
        # 更新POC到 GridFS 存储桶中
        # method_fs.put(content.encode(encoding="utf-8"), content_type=type, filename=firmware_id, aliases=[alias])
        method_fs.put(content, content_type=type, filename=firmware_id, aliases=[alias])
        return True

    def delete(self, firmware_id):
        file_item = method_fs.find_one({'filename': firmware_id})
        if file_item is None:
            return False
        method_fs.delete(file_item._id)
        return True

    def update(self, firmware_id, alias, content):
        # 删除旧的POC
        self.delete(firmware_id)

        type = SysUtils.parse_file_type(alias)
        # 更新POC到 GridFS 存储桶中
        method_fs.put(content.encode(encoding="utf-8"), content_type=type, filename=firmware_id, aliases=[alias])
        return True

    def search(self, name):
        # 正则表达式匹配整个单词：re.compile(r'\b%s\b' % word, re.IGNORECASE)
        result_cursor = method_fs.find({'aliases': re.compile(r'\b%s\b' % name, re.IGNORECASE)}, {'_id': 0}).sort(
            [("_id", pymongo.DESCENDING)])

        return result_cursor
